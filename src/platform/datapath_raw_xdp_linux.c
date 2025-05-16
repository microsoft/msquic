/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.

Abstract:

    QUIC XDP Datapath Implementation (User Mode)

--*/

#define _CRT_SECURE_NO_WARNINGS 1 // TODO - Remove

#include "bpf.h"
#include "datapath_raw_linux.h"
#include "datapath_raw_xdp.h"
#include "libbpf.h"
#include "libxdp.h"
#include "xsk.h"
#include <dirent.h>
#include <libgen.h>
#include <linux/ethtool.h>
#include <linux/sockios.h>
#include <netpacket/packet.h>

#ifdef QUIC_CLOG
#include "datapath_raw_xdp_linux.c.clog.h"
#endif

#define NUM_FRAMES         8192 * 2
#define CONS_NUM_DESCS     NUM_FRAMES / 2
#define PROD_NUM_DESCS     NUM_FRAMES / 2
#define FRAME_SIZE         XSK_UMEM__DEFAULT_FRAME_SIZE // TODO: 2K mode
#define INVALID_UMEM_FRAME UINT64_MAX

struct XskSocketInfo {
    struct xsk_ring_cons Rx;
    struct xsk_ring_prod Tx;
    struct XskUmemInfo *UmemInfo;
    struct xsk_socket *Xsk;

    CXPLAT_LOCK UmemLock;
    uint64_t UmemFrameAddr[NUM_FRAMES];
    uint32_t UmemFrameFree;
};

struct XskUmemInfo {
    struct xsk_ring_prod Fq;
    struct xsk_ring_cons Cq;
    struct xsk_umem *Umem;
    void *Buffer;
    uint32_t RxHeadRoom;
    uint32_t TxHeadRoom;
};

// TODO: remove this exception when finalizing members
typedef struct XDP_DATAPATH { // NOLINT(clang-analyzer-optin.performance.Padding)
    CXPLAT_DATAPATH_RAW;
    __attribute__((aligned(64)))
    //
    // Currently, all XDP interfaces share the same config.
    //
    CXPLAT_REF_COUNT RefCount;
    uint32_t PartitionCount;
    uint32_t BufferCount;

    uint32_t PollingIdleTimeoutUs;
    BOOLEAN TxAlwaysPoke;
    BOOLEAN SkipXsum;
    BOOLEAN Running;        // Signal to stop workers.

    CXPLAT_RUNDOWN_REF Rundown;
    XDP_PARTITION Partitions[0];
} XDP_DATAPATH;

typedef struct XDP_INTERFACE {
    XDP_INTERFACE_COMMON;
    struct xsk_socket_config *XskCfg;
    struct bpf_object *BpfObj;
    struct xdp_program *XdpProg;
    enum xdp_attach_mode AttachMode;
    struct in_addr Ipv4Address;
    struct in6_addr Ipv6Address;
    char IfName[IFNAMSIZ];
} XDP_INTERFACE;

typedef struct CXPLAT_QUEUE {
    XDP_QUEUE_COMMON;
    CXPLAT_SQE RxIoSqe;
    CXPLAT_SQE FlushTxSqe;

    CXPLAT_LIST_ENTRY PartitionTxQueue;
    CXPLAT_SLIST_ENTRY PartitionRxPool;

    // Move contended buffer pools to their own cache lines.
    // TODO: Use better (more scalable) buffer algorithms.
    // DECLSPEC_CACHEALIGN SLIST_HEADER RxPool;
    CXPLAT_LIST_ENTRY TxPool;

    // Move TX queue to its own cache line.
    CXPLAT_LIST_ENTRY TxQueue;

    // NOTE: experimental
    CXPLAT_LOCK TxLock;
    CXPLAT_LOCK RxLock;
    CXPLAT_LOCK FqLock;
    CXPLAT_LOCK CqLock;

    struct XskSocketInfo* XskInfo;
} CXPLAT_QUEUE;

typedef struct __attribute__((aligned(64))) XDP_RX_PACKET {
    CXPLAT_QUEUE* Queue;
    CXPLAT_ROUTE RouteStorage;
    uint64_t Addr;
    CXPLAT_RECV_DATA RecvData;
    // Followed by:
    // uint8_t ClientContext[...];
    // uint8_t FrameBuffer[MAX_ETH_FRAME_SIZE];
} XDP_RX_PACKET;

typedef struct __attribute__((aligned(64))) XDP_TX_PACKET {
    CXPLAT_SEND_DATA;
    uint64_t UmemRelativeAddr;
    CXPLAT_QUEUE* Queue;
    CXPLAT_LIST_ENTRY Link;
    uint8_t FrameBuffer[MAX_ETH_FRAME_SIZE];
} XDP_TX_PACKET;

CXPLAT_EVENT_COMPLETION CxPlatPartitionShutdownEventComplete;
CXPLAT_EVENT_COMPLETION CxPlatQueueRxIoEventComplete;
CXPLAT_EVENT_COMPLETION CxPlatQueueTxIoEventComplete;

void
XdpSocketContextSetEvents(
    _In_ CXPLAT_QUEUE* Queue,
    _In_ int Operation,
    _In_ uint32_t Events
    )
{
    struct epoll_event SockFdEpEvt = {
        .events = Events, .data = { .ptr = &Queue->RxIoSqe, } };

    int Ret =
        epoll_ctl(
            *Queue->Partition->EventQ,
            Operation,
            xsk_socket__fd(Queue->XskInfo->Xsk),
            &SockFdEpEvt);
    if (Ret != 0) {
        QuicTraceEvent(
            XdpEpollErrorStatus,
            "[ xdp]ERROR, %u, %s.",
            errno,
            "epoll_ctl failed");
    }
}

_IRQL_requires_max_(PASSIVE_LEVEL)
BOOLEAN
CxPlatXdpExecute(
    _Inout_ void* Context,
    _Inout_ CXPLAT_EXECUTION_STATE* State
    );

QUIC_STATUS
CxPlatGetInterfaceRssQueueCount(
    _In_ uint32_t InterfaceIndex,
    _Out_ uint16_t* Count
    )
{
    char IfName[IF_NAMESIZE];
    if_indextoname(InterfaceIndex, IfName);

    char Path[256];
    snprintf(Path, sizeof(Path), "/sys/class/net/%s/queues/", IfName);

    DIR* Dir = opendir(Path);
    if (Dir == NULL) {
        QuicTraceLogVerbose(
            XdpFailGettingRssQueueCount,
            "[ xdp] Failed to get RSS queue count for %s",
            IfName);
        return QUIC_STATUS_INTERNAL_ERROR;
    }

    struct dirent* Entry;
    while ((Entry = readdir(Dir)) != NULL) {
        if (strncmp(Entry->d_name, "rx-", 3) == 0) {
            (*Count)++;
        }
    }

    closedir(Dir);
    return QUIC_STATUS_SUCCESS;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
void
CxPlatXdpReadConfig(
    _Inout_ XDP_DATAPATH* Xdp
    )
{
    //
    // Default config.
    //
    Xdp->TxAlwaysPoke = FALSE;
}

void UninitializeUmem(struct XskUmemInfo* UmemInfo)
{
    if (xsk_umem__delete(UmemInfo->Umem) != 0) {
        QuicTraceLogVerbose(
            XdpUmemDeleteFails,
            "[ xdp] Failed to delete Umem");
    }
    free(UmemInfo->Buffer);
    free(UmemInfo);
}

// Detach XDP program from interface
void DetachXdpProgram(XDP_INTERFACE *Interface, BOOLEAN Initial)
{
    // NOTE: Experimental. this might remove none related programs as well.
    struct xdp_multiprog *mp = xdp_multiprog__get_from_ifindex(Interface->IfIndex);
    int err = xdp_multiprog__detach(mp);
    if (!Initial && err) {
        QuicTraceLogVerbose(
            XdpDetachFails,
            "[ xdp] Failed to detach XDP program from %s. error:%s",
            Interface->IfName,
            strerror(-err));
    }
	xdp_multiprog__close(mp);
}

_IRQL_requires_max_(PASSIVE_LEVEL)
void
CxPlatDpRawInterfaceUninitialize(
    _Inout_ XDP_INTERFACE* Interface
    )
{
    QuicTraceLogVerbose(
        InterfaceFree,
        "[ xdp][%p] Freeing Interface",
        Interface);
    for (uint32_t i = 0; Interface->Queues != NULL && i < Interface->QueueCount; i++) {
        CXPLAT_QUEUE *Queue = &Interface->Queues[i];

        QuicTraceLogVerbose(
            QueueFree,
            "[ xdp][%p] Freeing Queue on Interface:%p",
            Queue,
            Interface);

        if(Queue->XskInfo) {
            if (Queue->XskInfo->Xsk) {
                if (Queue->Partition && Queue->Partition->EventQ) {
                    epoll_ctl(*Queue->Partition->EventQ, EPOLL_CTL_DEL, xsk_socket__fd(Queue->XskInfo->Xsk), NULL);
                    CxPlatSqeCleanup(Queue->Partition->EventQ, &Queue->RxIoSqe);
                    CxPlatSqeCleanup(Queue->Partition->EventQ, &Queue->FlushTxSqe);
                    if (i == 0) {
                        CxPlatSqeCleanup(Queue->Partition->EventQ, &Queue->Partition->ShutdownSqe);
                    }
                }
                xsk_socket__delete(Queue->XskInfo->Xsk);
            }
            if (Queue->XskInfo->UmemInfo) {
                UninitializeUmem(Queue->XskInfo->UmemInfo);
            }
            CxPlatLockUninitialize(&Queue->XskInfo->UmemLock);
            free(Queue->XskInfo);
        }

        CxPlatLockUninitialize(&Queue->TxLock);
        CxPlatLockUninitialize(&Queue->RxLock);
        CxPlatLockUninitialize(&Queue->CqLock);
        CxPlatLockUninitialize(&Queue->FqLock);
    }

    if (Interface->Queues != NULL) {
        CxPlatFree(Interface->Queues, QUEUE_TAG);
    }

    DetachXdpProgram(Interface, false);

    if (Interface->XdpProg) {
        xdp_program__close(Interface->XdpProg);
    }

    if (Interface->XskCfg) {
        free(Interface->XskCfg);
    }
}

static QUIC_STATUS InitializeUmem(uint32_t FrameSize, uint32_t NumFrames, uint32_t RxHeadRoom, uint32_t TxHeadRoom, struct XskUmemInfo* UmemInfo)
{
    void *Buffer = NULL;
    if (posix_memalign(&Buffer, getpagesize(), (size_t)(FrameSize) * NumFrames)) {
        QuicTraceLogVerbose(
            XdpAllocUmem,
            "[ xdp] Failed to allocate umem");
        return QUIC_STATUS_OUT_OF_MEMORY;
    }

    struct xsk_umem_config UmemConfig = {
        .fill_size = PROD_NUM_DESCS,
        .comp_size = CONS_NUM_DESCS,
        .frame_size = FrameSize, // frame_size is really sensitive to become EINVAL
        .frame_headroom = RxHeadRoom,
        .flags = 0
    };

    int Ret = xsk_umem__create(&UmemInfo->Umem, Buffer, (uint64_t)(FrameSize) * NumFrames, &UmemInfo->Fq, &UmemInfo->Cq, &UmemConfig);
    if (Ret) {
        errno = -Ret;
        free(Buffer);
        return QUIC_STATUS_INTERNAL_ERROR;
    }

    UmemInfo->Buffer = Buffer;
    UmemInfo->RxHeadRoom = RxHeadRoom;
    UmemInfo->TxHeadRoom = TxHeadRoom;
    return QUIC_STATUS_SUCCESS;
}

static uint64_t XskUmemFreeFrames(struct XskSocketInfo *Xsk)
{
    return Xsk->UmemFrameFree;
}

static uint64_t XskUmemFrameAlloc(struct XskSocketInfo *Xsk)
{
    uint64_t Frame;
    if (Xsk->UmemFrameFree == 0) {
        QuicTraceLogVerbose(
            XdpUmemAllocFails,
            "[ xdp][umem] Out of UMEM frame, OOM");
        return INVALID_UMEM_FRAME;
    }
    Frame = Xsk->UmemFrameAddr[--Xsk->UmemFrameFree];
    Xsk->UmemFrameAddr[Xsk->UmemFrameFree] = INVALID_UMEM_FRAME;
    return Frame;
}

static void XskUmemFrameFree(struct XskSocketInfo *Xsk, uint64_t Frame)
{
    assert(Xsk->UmemFrameFree < NUM_FRAMES);
    Xsk->UmemFrameAddr[Xsk->UmemFrameFree++] = Frame;
}

QUIC_STATUS
AttachXdpProgram(struct xdp_program *Prog, XDP_INTERFACE *Interface, struct xsk_socket_config *XskCfg)
{
    char errmsg[1024];
    int err;

    // WARN: Attaching HW mode (error) affects doing
    //       with DRV/SKB mode. Need report to libxdp team
    // NOTE: eth0 on azure VM doesn't work with XDP_FLAGS_DRV_MODE
    static const struct AttachTypePair {
        enum xdp_attach_mode mode;
        unsigned int xdp_flag;
    } AttachTypePairs[]  = {
        // { XDP_MODE_HW, XDP_FLAGS_HW_MODE },
        // { XDP_MODE_NATIVE, XDP_FLAGS_DRV_MODE },
        { XDP_MODE_SKB, XDP_FLAGS_SKB_MODE },
    };
    for (uint32_t i = 0; i < ARRAYSIZE(AttachTypePairs); i++) {
        err = xdp_program__attach(Prog, Interface->IfIndex, AttachTypePairs[i].mode, 0);
        if (!err) {
            Interface->AttachMode = AttachTypePairs[i].mode;
            XskCfg->xdp_flags = AttachTypePairs[i].xdp_flag;
            break;
        }
    }

    if (err) {
        libxdp_strerror(err, errmsg, sizeof(errmsg));
        QuicTraceLogVerbose(
            XdpAttachFails,
            "[ xdp] Failed to attach XDP program to %s. error:%s", Interface->IfName, errmsg);
        return QUIC_STATUS_INTERNAL_ERROR;
    }
    QuicTraceLogVerbose(
        XdpAttachSucceeds,
        "[ xdp] Successfully attach XDP program to %s by mode:%d", Interface->IfName, Interface->AttachMode);
    return QUIC_STATUS_SUCCESS;
}

QUIC_STATUS
OpenXdpProgram(struct xdp_program **Prog)
{
    char errmsg[1024];
    int err = 0;
    char ExePath[256];
    ssize_t len = readlink("/proc/self/exe", ExePath, sizeof(ExePath)-1);
    char *ExeDir = NULL;
    if (len != -1) {
        ExePath[len] = '\0'; // Ensure null-terminated
        ExeDir = dirname(ExePath); // Get directory name
    }

    const char* Filename = "datapath_raw_xdp_kern.o";
    char* EnvPath = getenv("MSQUIC_XDP_OBJECT_PATH");
    char* Paths[] = {
        EnvPath,
        "/usr/lib/TBD", // TODO: decide where to install
        ExeDir,         // Same directory as executable
        ".",            // For development
        };
    char FilePath[256];
    int readRetry = 5;

    for (uint32_t i = 0; i < ARRAYSIZE(Paths); i++) {
        if (Paths[i] != NULL) {
            snprintf(FilePath, sizeof(FilePath), "%s/%s", Paths[i], Filename);
            if (access(FilePath, F_OK) == 0) {
                do {
                    *Prog = xdp_program__open_file(FilePath, "xdp_prog", NULL);
                    err = libxdp_get_error(*Prog);
                    if (err) {
                        // TODO: Need investigation.
                        //       Sometimes fail to load same object
                        CxPlatSleep(50);
                    }
                } while (err && readRetry-- > 0);
                break;
            }
        }
    }
    if (err) {
        libxdp_strerror(err, errmsg, sizeof(errmsg));
        QuicTraceLogVerbose(
            XdpOpenFileError,
            "[ xdp] Failed to open xdp program %s. error:%s(%d)",
            FilePath,
            errmsg,
            err);
        return QUIC_STATUS_INTERNAL_ERROR;
    }
    QuicTraceLogVerbose(
    XdpLoadObject,
    "[ xdp] Successfully loaded xdp object of %s",
    FilePath);
    return QUIC_STATUS_SUCCESS;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
QUIC_STATUS
CxPlatDpRawInterfaceInitialize(
    _In_ XDP_DATAPATH* Xdp,
    _Inout_ XDP_INTERFACE* Interface,
    _In_ uint32_t ClientRecvContextLength
    )
{
    libxdp_set_print(NULL);
    libbpf_set_print(NULL);

    const uint32_t RxHeadroom = ALIGN_UP(sizeof(XDP_RX_PACKET) + ClientRecvContextLength, 32);
    const uint32_t TxHeadroom = ALIGN_UP(FIELD_OFFSET(XDP_TX_PACKET, FrameBuffer), 32);
    // WARN: variable frame size cause unexpected behavior
    // TODO: 2K mode
    const uint32_t FrameSize = FRAME_SIZE;
    QUIC_STATUS Status = QUIC_STATUS_SUCCESS;
    int SocketCreated = 0;

    // TODO: setup offload features

    Interface->Xdp = Xdp;
    struct xsk_socket_config *XskCfg = (struct xsk_socket_config*)calloc(1, sizeof(struct xsk_socket_config));
    if (!XskCfg) {
        Status = QUIC_STATUS_OUT_OF_MEMORY;
        goto Error;
    }
    XskCfg->rx_size = CONS_NUM_DESCS;
    XskCfg->tx_size = PROD_NUM_DESCS;
    XskCfg->libbpf_flags = XSK_LIBBPF_FLAGS__INHIBIT_PROG_LOAD;
    // TODO: check ZEROCOPY feature, change Tx/Rx behavior based on feature
    //       refer xdp-tools/xdp-loader/xdp-loader features <ifname>
    XskCfg->bind_flags &= ~XDP_ZEROCOPY;
    XskCfg->bind_flags |= XDP_COPY;
    XskCfg->bind_flags |= XDP_USE_NEED_WAKEUP;
    Interface->XskCfg = XskCfg;

    DetachXdpProgram(Interface, true);

    Status = OpenXdpProgram(&Interface->XdpProg);
    if (QUIC_FAILED(Status)) {
        goto Error;
    }

    Status = AttachXdpProgram(Interface->XdpProg, Interface, XskCfg);
    if (QUIC_FAILED(Status)) {
        goto Error;
    }

    int XskBypassMapFd = bpf_map__fd(bpf_object__find_map_by_name(xdp_program__bpf_obj(Interface->XdpProg), "xsks_map"));
    if (XskBypassMapFd < 0) {
        QuicTraceLogVerbose(
            XdpNoXsksMap,
            "[ xdp] No xsks map found");
        Status = QUIC_STATUS_INTERNAL_ERROR;
        goto Error;
    }

    Status = CxPlatGetInterfaceRssQueueCount(Interface->IfIndex, &Interface->QueueCount);
    if (QUIC_FAILED(Status) || Interface->QueueCount == 0) {
        Status = QUIC_STATUS_INVALID_STATE;
        QuicTraceEvent(
            LibraryErrorStatus,
            "[ lib] ERROR, %u, %s.",
            Status,
            "CxPlatGetInterfaceRssQueueCount");
        goto Error;
    }

    Interface->Queues = CxPlatAlloc(Interface->QueueCount * sizeof(*Interface->Queues), QUEUE_TAG);
    if (Interface->Queues == NULL) {
        QuicTraceEvent(
            AllocFailure,
            "Allocation of '%s' failed. (%llu bytes)",
            "XDP Queues",
            Interface->QueueCount * sizeof(*Interface->Queues));
        Status = QUIC_STATUS_OUT_OF_MEMORY;
        goto Error;
    }

    CxPlatZeroMemory(Interface->Queues, Interface->QueueCount * sizeof(*Interface->Queues));

    for (uint16_t i = 0; i < Interface->QueueCount; i++) {
        CXPLAT_QUEUE* Queue = &Interface->Queues[i];

        Queue->Interface = Interface;
        CxPlatListInitializeHead(&Queue->TxPool);

        CxPlatLockInitialize(&Queue->TxLock);
        CxPlatLockInitialize(&Queue->RxLock);
        CxPlatLockInitialize(&Queue->FqLock);
        CxPlatLockInitialize(&Queue->CqLock);

        // Initialize shared packet_buffer for umem usage
        struct XskUmemInfo *UmemInfo = calloc(1, sizeof(struct XskUmemInfo));
        if (!UmemInfo) {
            Status = QUIC_STATUS_OUT_OF_MEMORY;
            goto Error;
        }

        Status = InitializeUmem(FRAME_SIZE, NUM_FRAMES, RxHeadroom, TxHeadroom, UmemInfo);
        if (QUIC_FAILED(Status)) {
            QuicTraceLogVerbose(
                XdpConfigureUmem,
                "[ xdp] Failed to configure Umem");
            free(UmemInfo);
            goto Error;
        }

        //
        // Create AF_XDP socket.
        //
        struct XskSocketInfo *XskInfo = calloc(1, sizeof(*XskInfo));
        if (!XskInfo) {
            Status = QUIC_STATUS_OUT_OF_MEMORY;
            free(UmemInfo->Buffer);
            free(UmemInfo);
            goto Error;
        }
        CxPlatLockInitialize(&XskInfo->UmemLock);
        Queue->XskInfo = XskInfo;
        XskInfo->UmemInfo = UmemInfo;

        int RetryCount = 10;
        int Ret = 0;
        do {
            Ret = xsk_socket__create(&XskInfo->Xsk, Interface->IfName,
                        i, UmemInfo->Umem, &XskInfo->Rx,
                        &XskInfo->Tx, XskCfg);
            if (Ret == -EBUSY) {
                CxPlatSleep(100);
            }
        } while (Ret == -EBUSY && RetryCount-- > 0);
        if (Ret < 0) {
            QuicTraceLogVerbose(
                FailXskSocketCreate,
                "[ xdp] Failed to create XDP socket for %s. error:%s", Interface->IfName, strerror(-Ret));
            Status = QUIC_STATUS_INTERNAL_ERROR;
            goto Error;
        }
        CxPlatRundownAcquire(&Xdp->Rundown);
        SocketCreated++;

        if(xsk_socket__update_xskmap(XskInfo->Xsk, XskBypassMapFd)) {
            Status = QUIC_STATUS_INTERNAL_ERROR;
            goto Error;
        }

        for (int i = 0; i < NUM_FRAMES; i++) {
            XskInfo->UmemFrameAddr[i] = i * FrameSize;
        }
        XskInfo->UmemFrameFree = NUM_FRAMES;

        // Setup fill queue for Rx
        uint32_t FqIdx = 0;
        Ret = xsk_ring_prod__reserve(&XskInfo->UmemInfo->Fq, PROD_NUM_DESCS, &FqIdx);
        if (Ret != PROD_NUM_DESCS) {
            return QUIC_STATUS_OUT_OF_MEMORY;
        }
        for (uint32_t i = 0; i < PROD_NUM_DESCS; i ++) {
            uint64_t Addr = XskUmemFrameAlloc(XskInfo);
            if (Addr == INVALID_UMEM_FRAME) {
                QuicTraceLogVerbose(
                    FailRxAlloc,
                    "[ xdp][rx  ] OOM for Rx");
                break;
            }
            *xsk_ring_prod__fill_addr(&XskInfo->UmemInfo->Fq, FqIdx++) = Addr;
        }

        xsk_ring_prod__submit(&XskInfo->UmemInfo->Fq, PROD_NUM_DESCS);
    }

    //
    // Add each queue to a worker (round robin).
    //
    for (uint16_t i = 0; i < Interface->QueueCount; i++) {
        XdpWorkerAddQueue(&Xdp->Partitions[i % Xdp->PartitionCount], &Interface->Queues[i]);
    }

Error:
    if (QUIC_FAILED(Status)) {
        while (SocketCreated--) {CxPlatRundownRelease(&Xdp->Rundown);}
        CxPlatDpRawInterfaceUninitialize(Interface);
    }
    return Status;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
void
CxPlatDpRawInterfaceUpdateRules(
    _In_ XDP_INTERFACE* Interface
    )
{
    UNREFERENCED_PARAMETER(Interface);
}

_IRQL_requires_max_(PASSIVE_LEVEL)
size_t
CxPlatDpRawGetDatapathSize(
    _In_ CXPLAT_WORKER_POOL* WorkerPool
    )
{
    const uint32_t PartitionCount = CxPlatWorkerPoolGetCount(WorkerPool);
    return sizeof(XDP_DATAPATH) + (PartitionCount * sizeof(XDP_PARTITION));
}

void ProcessInterfaceAddress(int family, struct ifaddrs *ifa, XDP_INTERFACE *Interface) {
    if (family == AF_INET) {
        struct sockaddr_in *addr_in = (struct sockaddr_in *)ifa->ifa_addr;
        Interface->Ipv4Address = addr_in->sin_addr;
    } else if (family == AF_INET6) {
        struct sockaddr_in6 *addr_in6 = (struct sockaddr_in6 *)ifa->ifa_addr;
        if (addr_in6->sin6_scope_id == if_nametoindex(ifa->ifa_name)) {
            return;
        }
        memcpy(&Interface->Ipv6Address, &addr_in6->sin6_addr, sizeof(struct in6_addr));
    } else if (family == AF_PACKET) {
        struct sockaddr_ll *sall = (struct sockaddr_ll*)ifa->ifa_addr;
        memcpy(Interface->PhysicalAddress, sall->sll_addr, sizeof(Interface->PhysicalAddress));
    }
}

_IRQL_requires_max_(PASSIVE_LEVEL)
QUIC_STATUS
CxPlatDpRawInitialize(
    _Inout_ CXPLAT_DATAPATH_RAW* Datapath,
    _In_ uint32_t ClientRecvContextLength,
    _In_ CXPLAT_WORKER_POOL* WorkerPool
    )
{
    XDP_DATAPATH* Xdp = (XDP_DATAPATH*)Datapath;

    CxPlatListInitializeHead(&Xdp->Interfaces);
    Xdp->PollingIdleTimeoutUs = 0;
    Xdp->PartitionCount = CxPlatWorkerPoolGetCount(WorkerPool);
    for (uint32_t i = 0; i < Xdp->PartitionCount; i++) {
        Xdp->Partitions[i].Processor = (uint16_t)
            CxPlatWorkerPoolGetIdealProcessor(WorkerPool, i);
    }

    //CxPlatXdpReadConfig(Xdp); // TODO - Make this more secure

    QuicTraceLogVerbose(
        XdpInitialize,
        "[ xdp][%p] XDP initialized, %u procs",
        Xdp,
        Xdp->PartitionCount);

    struct ifaddrs *ifaddr, *ifa;
    int family;

    QUIC_STATUS Status = QUIC_STATUS_SUCCESS;
    if (getifaddrs(&ifaddr) == -1) {
        return QUIC_STATUS_INTERNAL_ERROR;
    }

    CxPlatRundownInitialize(&Xdp->Rundown);
    CxPlatRundownAcquire(&Xdp->Rundown);
    for (ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next) {
        if (ifa->ifa_addr == NULL) {
            continue;
        }

        if ((ifa->ifa_flags & IFF_UP) &&
            // !(ifa->ifa_flags & IFF_LOOPBACK) &&
            // TODO: if there are MASTER-SLAVE interfaces, slave need to be
            //         loaded first to load all interfaces
            !(ifa->ifa_flags & IFF_SLAVE)) {
            // Create and initialize the interface data structure here
            family = ifa->ifa_addr->sa_family;
            XDP_INTERFACE* Interface = NULL;
            CXPLAT_LIST_ENTRY* Entry = Xdp->Interfaces.Flink;
            bool Initialized = false;
            for (; Entry != &Xdp->Interfaces; Entry = Entry->Flink) {
                Interface = (XDP_INTERFACE*)CXPLAT_CONTAINING_RECORD(Entry, CXPLAT_INTERFACE, Link);

                if (strcmp(Interface->IfName, ifa->ifa_name) == 0) {
                    Initialized = true;
                    ProcessInterfaceAddress(family, ifa, Interface);
                    break;
                }
            }
            if (!Initialized) {
                Interface = CxPlatAlloc(sizeof(XDP_INTERFACE), IF_TAG);
                if (Interface == NULL) {
                    QuicTraceEvent(
                        AllocFailure,
                        "Allocation of '%s' failed. (%llu bytes)",
                        "XDP interface",
                        sizeof(*Interface));
                    Status = QUIC_STATUS_OUT_OF_MEMORY;
                    goto Error;
                }
                CxPlatZeroMemory(Interface, sizeof(*Interface));
                memcpy(Interface->IfName, ifa->ifa_name, sizeof(Interface->IfName));
                Interface->IfIndex = if_nametoindex(ifa->ifa_name);
                ProcessInterfaceAddress(family, ifa, Interface);

                if (QUIC_FAILED(CxPlatDpRawInterfaceInitialize(
                        Xdp, Interface, ClientRecvContextLength))) {
                    QuicTraceEvent(
                        LibraryErrorStatus,
                        "[ lib] ERROR, %u, %s.",
                        Status,
                        "CxPlatDpRawInterfaceInitialize");
                    CxPlatFree(Interface, IF_TAG);
                    continue;
                }
                CxPlatListInsertTail(&Xdp->Interfaces, &Interface->Link);
            }
        }
    }
    freeifaddrs(ifaddr);

    if (CxPlatListIsEmpty(&Xdp->Interfaces)) {
        QuicTraceEvent(
            LibraryError,
            "[ lib] ERROR, %s.",
            "no XDP capable interface");
        Status = QUIC_STATUS_NOT_FOUND;
        goto Error;
    }

    Xdp->Running = TRUE;
    CxPlatRefInitialize(&Xdp->RefCount);
    for (uint32_t i = 0; i < Xdp->PartitionCount; i++) {
        XDP_PARTITION* Partition = &Xdp->Partitions[i];
        if (Partition->Queues == NULL) {
            //
            // Because queues are assigned in a round-robin manner, subsequent
            // workers will not have a queue assigned. Stop the loop and update
            // worker count.
            //
            Xdp->PartitionCount = i;
            break;
        }

        Partition->Xdp = Xdp;
        Partition->PartitionIndex = (uint16_t)i;
        Partition->Ec.Ready = TRUE;
        Partition->Ec.NextTimeUs = UINT64_MAX;
        Partition->Ec.Callback = CxPlatXdpExecute;
        Partition->Ec.Context = &Xdp->Partitions[i];
        CxPlatRefIncrement(&Xdp->RefCount);
        CxPlatRundownAcquire(&Xdp->Rundown);
        Partition->EventQ = CxPlatWorkerPoolGetEventQ(WorkerPool, (uint16_t)i);

        if (!CxPlatSqeInitialize(
                Partition->EventQ,
                CxPlatPartitionShutdownEventComplete,
                &Partition->ShutdownSqe)) {
            Status = QUIC_STATUS_INTERNAL_ERROR;
            goto Error;
        }

        uint32_t QueueCount = 0;
        CXPLAT_QUEUE* Queue = Partition->Queues;
        while (Queue) {
            if (!CxPlatSqeInitialize(
                    Partition->EventQ,
                    CxPlatQueueRxIoEventComplete,
                    &Queue->RxIoSqe)) {
                Status = QUIC_STATUS_INTERNAL_ERROR;
                goto Error;
            }
            XdpSocketContextSetEvents(Queue, EPOLL_CTL_ADD, EPOLLIN);

            if (!CxPlatSqeInitialize(
                    Partition->EventQ,
                    CxPlatQueueTxIoEventComplete,
                    &Queue->FlushTxSqe)) {
                Status = QUIC_STATUS_INTERNAL_ERROR;
                goto Error;
            }

            ++QueueCount;
            Queue = Queue->Next;
        }

        QuicTraceLogVerbose(
            XdpWorkerStart,
            "[ xdp][%p] XDP partition start, %u queues",
            Partition,
            QueueCount);

        CxPlatWorkerPoolAddExecutionContext(
            WorkerPool, &Partition->Ec, Partition->PartitionIndex);
    }

Error:
    if (QUIC_FAILED(Status)) {
        while (!CxPlatListIsEmpty(&Xdp->Interfaces)) {
            XDP_INTERFACE* Interface =
                CXPLAT_CONTAINING_RECORD(CxPlatListRemoveHead(&Xdp->Interfaces), XDP_INTERFACE, Link);
            CxPlatDpRawInterfaceUninitialize(Interface);
            CxPlatFree(Interface, IF_TAG);
        }
    }

    return Status;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
void
CxPlatDpRawRelease(
    _In_ XDP_DATAPATH* Xdp
    )
{
    QuicTraceLogVerbose(
        XdpRelease,
        "[ xdp][%p] XDP release",
        Xdp);
    if (CxPlatRefDecrement(&Xdp->RefCount)) {
        QuicTraceLogVerbose(
            XdpUninitializeComplete,
            "[ xdp][%p] XDP uninitialize complete",
            Xdp);
        while (!CxPlatListIsEmpty(&Xdp->Interfaces)) {
            XDP_INTERFACE* Interface =
                CXPLAT_CONTAINING_RECORD(CxPlatListRemoveHead(&Xdp->Interfaces), XDP_INTERFACE, Link);
            CxPlatDpRawInterfaceUninitialize(Interface);
            for (int i = 0; i < Interface->QueueCount; i++) {
                CxPlatRundownRelease(&Xdp->Rundown);
            }
            CxPlatFree(Interface, IF_TAG);
        }
        CxPlatDataPathUninitializeComplete((CXPLAT_DATAPATH_RAW*)Xdp);
    }
    CxPlatRundownRelease(&Xdp->Rundown);
}

_IRQL_requires_max_(PASSIVE_LEVEL)
void
CxPlatDpRawUninitialize(
    _In_ CXPLAT_DATAPATH_RAW* Datapath
    )
{
    XDP_DATAPATH* Xdp = (XDP_DATAPATH*)Datapath;
    QuicTraceLogVerbose(
        XdpUninitialize,
        "[ xdp][%p] XDP uninitialize",
        Xdp);
    Xdp->Running = FALSE; // call CxPlatDpRawRelease from each partition
    for (uint32_t i = 0; i < Xdp->PartitionCount; i++) {
        Xdp->Partitions[i].Ec.Ready = TRUE;
        CxPlatWakeExecutionContext(&Xdp->Partitions[i].Ec);
    }
    CxPlatDpRawRelease(Xdp);
    CxPlatRundownReleaseAndWait(&Xdp->Rundown);
}

_IRQL_requires_max_(PASSIVE_LEVEL)
void
CxPlatDpRawUpdatePollingIdleTimeout(
    _In_ CXPLAT_DATAPATH_RAW* Datapath,
    _In_ uint32_t PollingIdleTimeoutUs
    )
{
    XDP_DATAPATH* Xdp = (XDP_DATAPATH*)Datapath;
    Xdp->PollingIdleTimeoutUs = PollingIdleTimeoutUs;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
QUIC_STATUS
RawSocketUpdateQeo(
    _In_ CXPLAT_SOCKET_RAW* Socket,
    _In_reads_(OffloadCount)
        const CXPLAT_QEO_CONNECTION* Offloads,
    _In_ uint32_t OffloadCount
    )
{
    UNREFERENCED_PARAMETER(Socket);
    UNREFERENCED_PARAMETER(Offloads);
    UNREFERENCED_PARAMETER(OffloadCount);
    return QUIC_STATUS_NOT_SUPPORTED;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
void
CxPlatDpRawPlumbRulesOnSocket(
    _In_ CXPLAT_SOCKET_RAW* Socket,
    _In_ BOOLEAN IsCreated
    )
{
    CXPLAT_LIST_ENTRY* Entry = Socket->RawDatapath->Interfaces.Flink;
    for (; Entry != &Socket->RawDatapath->Interfaces; Entry = Entry->Flink) {
        XDP_INTERFACE* Interface = (XDP_INTERFACE*)CXPLAT_CONTAINING_RECORD(Entry, CXPLAT_INTERFACE, Link);
        struct bpf_map *port_map = bpf_object__find_map_by_name(xdp_program__bpf_obj(Interface->XdpProg), "port_map");
        if (port_map) {
            int port = Socket->LocalAddress.Ipv4.sin_port;
            if (IsCreated) {
                BOOLEAN exist = true;
                if (bpf_map_update_elem(bpf_map__fd(port_map), &port, &exist, BPF_ANY)) {
                    QuicTraceLogVerbose(
                        XdpSetPortFails,
                        "[ xdp] Failed to set port %d on %s", port, Interface->IfName);
                }
            } else {
                if (bpf_map_delete_elem(bpf_map__fd(port_map), &port)) {
                    QuicTraceLogVerbose(
                        XdpDeletePortFails,
                        "[ xdp] Failed to delete port %d on %s", port, Interface->IfName);
                }
            }
        }

        struct bpf_map *ip_map = bpf_object__find_map_by_name(xdp_program__bpf_obj(Interface->XdpProg), "ip_map");
        static const int IPv4Key = 0;
        static const int IPv6Key = 1;
        if (ip_map) {
            __u8 ipv_data[16] = {0};
            if (IsCreated) {
                memcpy(ipv_data, &Interface->Ipv4Address.s_addr, 4);
                if (bpf_map_update_elem(bpf_map__fd(ip_map), &IPv4Key, ipv_data, BPF_ANY)) {
                    QuicTraceLogVerbose(
                        XdpSetIpFails,
                        "[ xdp] Failed to set ipv4 %s on %s",
                        inet_ntoa(Interface->Ipv4Address),
                        Interface->IfName);
                }
                memcpy(ipv_data, &Interface->Ipv6Address.s6_addr, sizeof(ipv_data));
                if (bpf_map_update_elem(bpf_map__fd(ip_map), &IPv6Key, ipv_data, BPF_ANY)) {
                    char str_ipv6[INET6_ADDRSTRLEN];
                    inet_ntop(AF_INET6, &Interface->Ipv6Address, str_ipv6, sizeof(str_ipv6));
                    QuicTraceLogVerbose(
                        XdpSetIpFails,
                        "[ xdp] Failed to set ipv6 %s on %s",
                        str_ipv6,
                        Interface->IfName);
                }
            } else {
                bpf_map_update_elem(bpf_map__fd(ip_map), &IPv4Key, ipv_data, BPF_ANY);
                bpf_map_update_elem(bpf_map__fd(ip_map), &IPv6Key, ipv_data, BPF_ANY);
            }
        }


        // Debug info
        // TODO: set flag to enable dump in xdp program
        struct bpf_map *ifname_map = bpf_object__find_map_by_name(xdp_program__bpf_obj(Interface->XdpProg), "ifname_map");
        if (ifname_map) {
            int key = 0;
            if (IsCreated) {
                if (bpf_map_update_elem(bpf_map__fd(ifname_map), &key, Interface->IfName, BPF_ANY)) {
                    QuicTraceLogVerbose(
                        XdpSetIfnameFails,
                        "[ xdp] Failed to set ifname %s on %s", Interface->IfName, Interface->IfName);
                }
            } // BPF_MAP_TYPE_ARRAY doesn't support delete
        }
    }
}

_IRQL_requires_max_(DISPATCH_LEVEL)
BOOLEAN
CxPlatDpRawIsL3TxXsumOffloadedOnQueue(
    _In_ const CXPLAT_QUEUE* Queue
    )
{
    return CxPlatDpRawGetInterfaceFromQueue(Queue)->OffloadStatus.Transmit.NetworkLayerXsum;
}


_IRQL_requires_max_(DISPATCH_LEVEL)
BOOLEAN
CxPlatDpRawIsL4TxXsumOffloadedOnQueue(
    _In_ const CXPLAT_QUEUE* Queue
    )
{
    return CxPlatDpRawGetInterfaceFromQueue(Queue)->OffloadStatus.Transmit.TransportLayerXsum;
}

_IRQL_requires_max_(DISPATCH_LEVEL)
void
CxPlatDpRawRxFree(
    _In_opt_ const CXPLAT_RECV_DATA* PacketChain
    )
{
    uint32_t Count = 0;
    struct XskSocketInfo *XskInfo = NULL;
    if (PacketChain) {
        const XDP_RX_PACKET* Packet =
            CXPLAT_CONTAINING_RECORD(PacketChain, XDP_RX_PACKET, RecvData);
        XskInfo = Packet->Queue->XskInfo;

        CxPlatLockAcquire(&XskInfo->UmemLock);
        while (PacketChain) {
            Packet =
                CXPLAT_CONTAINING_RECORD(PacketChain, XDP_RX_PACKET, RecvData);
            PacketChain = PacketChain->Next;
            XskUmemFrameFree(Packet->Queue->XskInfo, Packet->Addr);
            Count++;
        }
    }

    if (Count > 0) {
        CxPlatLockRelease(&XskInfo->UmemLock);
    }
}

_IRQL_requires_max_(DISPATCH_LEVEL)
CXPLAT_SEND_DATA*
CxPlatDpRawTxAlloc(
    _Inout_ CXPLAT_SEND_CONFIG* Config
    )
{
    CXPLAT_DBG_ASSERT(Config->MaxPacketSize <= MAX_UDP_PAYLOAD_LENGTH);
    XDP_TX_PACKET* Packet = NULL;
    CXPLAT_QUEUE* Queue = Config->Route->Queue;
    struct XskSocketInfo* XskInfo = Queue->XskInfo;
    CxPlatLockAcquire(&XskInfo->UmemLock);
    uint64_t BaseAddr = XskUmemFrameAlloc(XskInfo);
    CxPlatLockRelease(&XskInfo->UmemLock);
    if (BaseAddr == INVALID_UMEM_FRAME) {
        QuicTraceLogVerbose(
            FailTxAlloc,
            "[ xdp][tx  ] OOM for Tx");
        goto Error;
    }

    Packet = (XDP_TX_PACKET*)xsk_umem__get_data(XskInfo->UmemInfo->Buffer, BaseAddr);
    if (Packet) {
        HEADER_BACKFILL HeaderBackfill = CxPlatDpRawCalculateHeaderBackFill(Config->Route); // TODO - Cache in Route?
        CXPLAT_DBG_ASSERT(Config->MaxPacketSize <= sizeof(Packet->FrameBuffer) - HeaderBackfill.AllLayer);
        Packet->Queue = Queue;
        Packet->Buffer.Length = Config->MaxPacketSize;
        Packet->Buffer.Buffer = &Packet->FrameBuffer[HeaderBackfill.AllLayer];
        Packet->ECN = Config->ECN;
        Packet->DSCP = Config->DSCP;
        Packet->UmemRelativeAddr = BaseAddr;
        Packet->DatapathType = Config->Route->DatapathType = CXPLAT_DATAPATH_TYPE_RAW;
    }

Error:
    return (CXPLAT_SEND_DATA*)Packet;
}

_IRQL_requires_max_(DISPATCH_LEVEL)
void
CxPlatDpRawTxFree(
    _In_ CXPLAT_SEND_DATA* SendData
    )
{
    UNREFERENCED_PARAMETER(SendData);
}

void
KickTx(
    _In_ CXPLAT_QUEUE* Queue,
    _In_ BOOLEAN SendAlreadyPending
    )
{
    struct XskSocketInfo* XskInfo = Queue->XskInfo;
    if (sendto(xsk_socket__fd(XskInfo->Xsk), NULL, 0, MSG_DONTWAIT, NULL, 0) < 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            if (!SendAlreadyPending) {
                XdpSocketContextSetEvents(Queue, EPOLL_CTL_MOD, EPOLLIN | EPOLLOUT);
            }
            return;
        }
    }
    QuicTraceLogVerbose(
        DoneSendTo,
        "[ xdp][TX  ] Done sendto.");

    if (SendAlreadyPending) {
        XdpSocketContextSetEvents(Queue, EPOLL_CTL_MOD, EPOLLIN);
    }

    uint32_t Completed;
    uint32_t CqIdx;
    CxPlatLockAcquire(&Queue->CqLock);
    Completed = xsk_ring_cons__peek(&XskInfo->UmemInfo->Cq, CONS_NUM_DESCS, &CqIdx);
    if (Completed > 0) {
        CxPlatLockAcquire(&XskInfo->UmemLock);
        for (uint32_t i = 0; i < Completed; i++) {
            uint64_t addr = *xsk_ring_cons__comp_addr(&XskInfo->UmemInfo->Cq, CqIdx++) - XskInfo->UmemInfo->TxHeadRoom;
            XskUmemFrameFree(XskInfo, addr);
        }
        CxPlatLockRelease(&XskInfo->UmemLock);

        xsk_ring_cons__release(&XskInfo->UmemInfo->Cq, Completed);
        QuicTraceLogVerbose(
            ReleaseCons,
            "[ xdp][cq  ] Release %d from completion queue", Completed);
    }
    CxPlatLockRelease(&Queue->CqLock);
}

_IRQL_requires_max_(DISPATCH_LEVEL)
void
CxPlatDpRawTxEnqueue(
    _In_ CXPLAT_SEND_DATA* SendData
    )
{
    XDP_TX_PACKET* Packet = (XDP_TX_PACKET*)SendData;
    CXPLAT_QUEUE* Queue = Packet->Queue;
    XDP_PARTITION* Partition = Queue->Partition;
    struct XskSocketInfo* XskInfo = Queue->XskInfo;

    uint32_t TxIdx = 0;
    CxPlatLockAcquire(&Queue->TxLock);
    if (xsk_ring_prod__reserve(&XskInfo->Tx, 1, &TxIdx) != 1) {
        CxPlatLockAcquire(&XskInfo->UmemLock);
        XskUmemFrameFree(XskInfo, Packet->UmemRelativeAddr);
        CxPlatLockRelease(&XskInfo->UmemLock);
        QuicTraceLogVerbose(
            FailTxReserve,
            "[ xdp][tx  ] Failed to reserve");
        return;
    }

    struct xdp_desc *tx_desc = xsk_ring_prod__tx_desc(&XskInfo->Tx, TxIdx);
    CXPLAT_FRE_ASSERT(tx_desc != NULL);
    tx_desc->addr = Packet->UmemRelativeAddr + XskInfo->UmemInfo->TxHeadRoom;
    tx_desc->len = SendData->Buffer.Length;
    xsk_ring_prod__submit(&XskInfo->Tx, 1);
    CxPlatLockRelease(&Queue->TxLock);

    KickTx(Packet->Queue, FALSE);

    Partition->Ec.Ready = TRUE;
    CxPlatWakeExecutionContext(&Partition->Ec);
}

_IRQL_requires_max_(DISPATCH_LEVEL)
void
CxPlatDpRawTxSetL3ChecksumOffload(
    _In_ CXPLAT_SEND_DATA* SendData
    )
{
    UNREFERENCED_PARAMETER(SendData);
}

_IRQL_requires_max_(DISPATCH_LEVEL)
void
CxPlatDpRawTxSetL4ChecksumOffload(
    _In_ CXPLAT_SEND_DATA* SendData,
    _In_ BOOLEAN IsIpv6,
    _In_ BOOLEAN IsTcp,
    _In_ uint8_t L4HeaderLength
    )
{
    UNREFERENCED_PARAMETER(SendData);
    UNREFERENCED_PARAMETER(IsIpv6);
    UNREFERENCED_PARAMETER(IsTcp);
    UNREFERENCED_PARAMETER(L4HeaderLength);
}

static
BOOLEAN // Did work?
CxPlatXdpTx(
    _In_ const XDP_DATAPATH* Xdp,
    _In_ CXPLAT_QUEUE* Queue
    )
{
    UNREFERENCED_PARAMETER(Xdp);
    UNREFERENCED_PARAMETER(Queue);
    return FALSE;
}

static
BOOLEAN // Did work?
CxPlatXdpRx(
    _In_ const XDP_DATAPATH* Xdp,
    _In_ CXPLAT_QUEUE* Queue,
    _In_ uint16_t PartitionIndex
    );

_IRQL_requires_max_(PASSIVE_LEVEL)
BOOLEAN
CxPlatXdpExecute(
    _Inout_ void* Context,
    _Inout_ CXPLAT_EXECUTION_STATE* State
    )
{
    XDP_PARTITION* Partition = (XDP_PARTITION*)Context;
    const XDP_DATAPATH* Xdp = Partition->Xdp;

    if (!Xdp->Running) {
        QuicTraceLogVerbose(
            XdpPartitionShutdown,
            "[ xdp][%p] XDP partition shutdown",
            Partition);
        CxPlatEventQEnqueue(Partition->EventQ, &Partition->ShutdownSqe);
        return FALSE;
    }

     const BOOLEAN PollingExpired =
        CxPlatTimeDiff64(State->LastWorkTime, State->TimeNow) >= Xdp->PollingIdleTimeoutUs;

    BOOLEAN DidWork = FALSE;
    CXPLAT_QUEUE* Queue = Partition->Queues;
    while (Queue) {
        DidWork |= CxPlatXdpRx(Xdp, Queue, Partition->PartitionIndex);
        DidWork |= CxPlatXdpTx(Xdp, Queue);
        Queue = Queue->Next;
    }

    if (DidWork) {
        Partition->Ec.Ready = TRUE;
        State->NoWorkCount = 0;
    } else if (!PollingExpired) {
        Partition->Ec.Ready = TRUE;
    } else {
        Queue = Partition->Queues;
        while (Queue) {
            Queue = Queue->Next;
        }
    }

    return TRUE;
}

static
BOOLEAN // Did work?
CxPlatXdpRx(
    _In_ const XDP_DATAPATH* Xdp,
    _In_ CXPLAT_QUEUE* Queue,
    _In_ uint16_t PartitionIndex
    )
{
    struct XskSocketInfo *XskInfo = Queue->XskInfo;
    uint32_t Rcvd, i;
    uint32_t Available;
    uint32_t RxIdx = 0, FqIdx = 0;
    unsigned int ret;

    CxPlatLockAcquire(&Queue->RxLock);
    Rcvd = xsk_ring_cons__peek(&XskInfo->Rx, RX_BATCH_SIZE, &RxIdx);

    // Process received packets
    CXPLAT_RECV_DATA* Buffers[RX_BATCH_SIZE] = {};
    uint32_t PacketCount = 0;
    for (i = 0; i < Rcvd; i++) {
        uint64_t Addr = xsk_ring_cons__rx_desc(&XskInfo->Rx, RxIdx)->addr;
        uint32_t Len = xsk_ring_cons__rx_desc(&XskInfo->Rx, RxIdx++)->len;
        uint8_t *FrameBuffer = xsk_umem__get_data(XskInfo->UmemInfo->Buffer, Addr);
        XDP_RX_PACKET* Packet = (XDP_RX_PACKET*)(FrameBuffer - XskInfo->UmemInfo->RxHeadRoom);
        CxPlatZeroMemory(Packet, XskInfo->UmemInfo->RxHeadRoom);

        Packet->Queue = Queue;
        Packet->RouteStorage.Queue = Queue;
        Packet->RecvData.Route = &Packet->RouteStorage;
        Packet->RecvData.Route->DatapathType = Packet->RecvData.DatapathType = CXPLAT_DATAPATH_TYPE_RAW;
        Packet->RecvData.PartitionIndex = PartitionIndex;

        CxPlatDpRawParseEthernet(
            (CXPLAT_DATAPATH*)Xdp,
            &Packet->RecvData,
            FrameBuffer,
            (uint16_t)Len);
        QuicTraceEvent(
            RxConstructPacket,
            "[ xdp][rx  ] Constructing Packet from Rx, local=%!ADDR!, remote=%!ADDR!",
            CASTED_CLOG_BYTEARRAY(sizeof(Packet->RouteStorage.LocalAddress), &Packet->RouteStorage.LocalAddress),
            CASTED_CLOG_BYTEARRAY(sizeof(Packet->RouteStorage.RemoteAddress), &Packet->RouteStorage.RemoteAddress));

        //
        // The route has been filled in with the packet's src/dst IP and ETH addresses, so
        // mark it resolved. This allows stateless sends to be issued without performing
        // a route lookup.
        //
        Packet->RecvData.Route->State = RouteResolved;
        CXPLAT_DBG_ASSERT(Packet->RecvData.Route->Queue != NULL);

        if (Packet->RecvData.Buffer) {
            Packet->Addr = Addr - (XDP_PACKET_HEADROOM + XskInfo->UmemInfo->RxHeadRoom);
            Packet->RecvData.Allocated = TRUE;
            Buffers[PacketCount++] = &Packet->RecvData;
        } else {
            XskUmemFrameFree(XskInfo, Addr - (XDP_PACKET_HEADROOM + XskInfo->UmemInfo->RxHeadRoom));
        }
    }

    if (Rcvd) {
        xsk_ring_cons__release(&XskInfo->Rx, Rcvd);
    }
    CxPlatLockRelease(&Queue->RxLock);

    CxPlatLockAcquire(&XskInfo->UmemLock);
    CxPlatLockAcquire(&Queue->FqLock);
    // Stuff the ring with as much frames as possible
    Available = xsk_prod_nb_free(&XskInfo->UmemInfo->Fq, XskUmemFreeFrames(XskInfo));
    if (Available > 0) {
        ret = xsk_ring_prod__reserve(&XskInfo->UmemInfo->Fq, Available, &FqIdx);

        // This should not happen, but just in case
        while (ret != Available) {
            ret = xsk_ring_prod__reserve(&XskInfo->UmemInfo->Fq, Rcvd, &FqIdx);
        }
        for (i = 0; i < Available; i++) {
            uint64_t addr = XskUmemFrameAlloc(XskInfo);
            if (addr == INVALID_UMEM_FRAME) {
                QuicTraceLogVerbose(
                    FailRxAlloc,
                    "[ xdp][rx  ] OOM for Rx");
                break;
            }
            *xsk_ring_prod__fill_addr(&XskInfo->UmemInfo->Fq, FqIdx++) = addr;
        }
        if (i > 0) {
            xsk_ring_prod__submit(&XskInfo->UmemInfo->Fq, i);
        }
    }
    CxPlatLockRelease(&Queue->FqLock);
    CxPlatLockRelease(&XskInfo->UmemLock);

    if (PacketCount) {
        CxPlatDpRawRxEthernet(
            (CXPLAT_DATAPATH_RAW*)Queue->Partition->Xdp,
            Buffers,
            (uint16_t)PacketCount);
    }
    return PacketCount > 0 || i > 0;
}

void
CxPlatPartitionShutdownEventComplete(
    _In_ CXPLAT_CQE* Cqe
    )
{
    XDP_PARTITION* Partition =
        CXPLAT_CONTAINING_RECORD(CxPlatCqeGetSqe(Cqe), XDP_PARTITION, ShutdownSqe);
    QuicTraceLogVerbose(
        XdpPartitionShutdownComplete,
        "[ xdp][%p] XDP partition shutdown complete",
        Partition);
    CxPlatDpRawRelease((XDP_DATAPATH*)Partition->Xdp);
}

void
CxPlatQueueRxIoEventComplete(
    _In_ CXPLAT_CQE* Cqe
    )
{
    // TODO: use CQE to distinguish Tx/RX
    CXPLAT_QUEUE* Queue =
        CXPLAT_CONTAINING_RECORD(CxPlatCqeGetSqe(Cqe), CXPLAT_QUEUE, RxIoSqe);
    QuicTraceLogVerbose(
        XdpQueueAsyncIoRxComplete,
        "[ xdp][%p] XDP async IO complete (RX)",
        Queue);
    if (EPOLLOUT & Cqe->events) {
        KickTx(Queue, TRUE);
    } else {
        Queue->RxQueued = FALSE;
        Queue->Partition->Ec.Ready = TRUE;
    }
}

void
CxPlatQueueTxIoEventComplete(
    _In_ CXPLAT_CQE* Cqe
    )
{
    UNREFERENCED_PARAMETER(Cqe); // TODO - Use this?
}

_IRQL_requires_max_(PASSIVE_LEVEL)
QUIC_STATUS
CxPlatDataPathRssConfigGet(
    _In_ uint32_t InterfaceIndex,
    _Outptr_ _At_(*RssConfig, __drv_allocatesMem(Mem))
        CXPLAT_RSS_CONFIG** RssConfig
    )
{
    UNREFERENCED_PARAMETER(InterfaceIndex);
    UNREFERENCED_PARAMETER(RssConfig);
    return QUIC_STATUS_NOT_SUPPORTED;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
void
CxPlatDataPathRssConfigFree(
    _In_ CXPLAT_RSS_CONFIG* RssConfig
    )
{
    UNREFERENCED_PARAMETER(RssConfig);
    CXPLAT_FRE_ASSERTMSG(FALSE, "CxPlatDataPathRssConfigFree not supported");
}
