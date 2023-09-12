/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.

Abstract:

    QUIC XDP Datapath Implementation (User Mode)

--*/

#define _CRT_SECURE_NO_WARNINGS 1 // TODO - Remove

#include "datapath_raw_linux.h"
#include "datapath_raw_xdp_linux.h"
// #include "datapath_raw_xdp.h"

#ifdef QUIC_CLOG
#include "datapath_raw_xdp_linux.c.clog.h"
#endif

void
CxPlatSocketContextSetEvents(
    _In_ XDP_QUEUE* Queue,
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
            xsk_socket__fd(Queue->xsk_info->xsk),
            &SockFdEpEvt);
    if (Ret != 0) {
        QuicTraceEvent(
            XdpEpollErrorStatus,
            "[ xdp]ERROR, %u, %s.",
            errno,
            "epoll_ctl failed");
    }
}

void XdpWorkerAddQueue(_In_ XDP_PARTITION* Partition, _In_ XDP_QUEUE* Queue) {
    XDP_QUEUE** Tail = &Partition->Queues;
    while (*Tail != NULL) {
        Tail = &(*Tail)->Next;
    }
    *Tail = Queue;
    Queue->Next = NULL;
    Queue->Partition = Partition;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
BOOLEAN
CxPlatXdpExecute(
    _Inout_ void* Context,
    _Inout_ CXPLAT_EXECUTION_STATE* State
    );

// CXPLAT_RECV_DATA*
// CxPlatDataPathRecvPacketToRecvData(
//     _In_ const CXPLAT_RECV_PACKET* const Context
//     )
// {
//     return (CXPLAT_RECV_DATA*)(((uint8_t*)Context) - sizeof(XDP_RX_PACKET));
// }

// CXPLAT_RECV_PACKET*
// CxPlatDataPathRecvDataToRecvPacket(
//     _In_ const CXPLAT_RECV_DATA* const Datagram
//     )
// {
//     return (CXPLAT_RECV_PACKET*)(((uint8_t*)Datagram) + sizeof(XDP_RX_PACKET));
// }

QUIC_STATUS
CxPlatGetInterfaceRssQueueCount(
    _In_ uint32_t InterfaceIndex,
    _Out_ uint16_t* Count
    )
{
    // TODO: check ethtool implementation
    FILE *fp;
    *Count = UINT16_MAX;

    char IfName[IF_NAMESIZE];
    if_indextoname(InterfaceIndex, IfName);
    char cmd[128];
    snprintf(cmd, sizeof(cmd), "ethtool -x %s", IfName);
    fp = popen(cmd, "r");
    if (fp == NULL) {
        goto Error;
    }

    char buf[256];
    // Read and scan each line of the output for the number of rings
    while (fgets(buf, sizeof(buf), fp) != NULL) {
        if (strstr(buf, "RX flow hash indirection table for") != NULL) {
            sscanf(buf, "RX flow hash indirection table for %*s with %hd", Count);
            break;
        }
    }
    pclose(fp);

Error:
    if (*Count == UINT16_MAX) {
        *Count = 1;
    }
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
    Xdp->RxBufferCount = 8192;
    Xdp->RxRingSize = 256;
    Xdp->TxBufferCount = 8192;
    Xdp->TxRingSize = 256;
    Xdp->TxAlwaysPoke = FALSE;

    // TODO
}

void UninitializeUmem(struct xsk_umem_info* Umem)
{
    // TODO: error check
    xsk_umem__delete(Umem->umem);
    free(Umem->buffer);
    free(Umem);
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
        XDP_QUEUE *Queue = &Interface->Queues[i];

        QuicTraceLogVerbose(
            QueueFree,
            "[ xdp][%p] Freeing Queue on Interface:%p",
            Queue,
            Interface);

        if(Queue->xsk_info) {
            if (Queue->xsk_info->xsk) {
                if (Queue->Partition && Queue->Partition->EventQ) {
                    epoll_ctl(*Queue->Partition->EventQ, EPOLL_CTL_DEL, xsk_socket__fd(Queue->xsk_info->xsk), NULL);
                }
                xsk_socket__delete(Queue->xsk_info->xsk);
            }
            if (Queue->xsk_info->umem) {
                UninitializeUmem(Queue->xsk_info->umem);
            }
            CxPlatLockUninitialize(&Queue->xsk_info->UmemLock);
            free(Queue->xsk_info);
        }

        CxPlatLockUninitialize(&Queue->TxLock);
    }

    if (Interface->Queues != NULL) {
        CxPlatFree(Interface->Queues, QUEUE_TAG);
    }

    struct xdp_multiprog *mp = xdp_multiprog__get_from_ifindex(Interface->IfIndex);
    int err = xdp_multiprog__detach(mp);
    if (err) {
        fprintf(stderr, "Unable to detach XDP program: %s\n",
            strerror(-err));
    }
	xdp_multiprog__close(mp);

    if (Interface->XdpProg) {
        xdp_program__close(Interface->XdpProg);
    }

    if (Interface->XskCfg) {
        free(Interface->XskCfg);
    }
}

static QUIC_STATUS InitializeUmem(uint32_t frameSize, uint32_t numFrames, uint32_t RxHeadRoom, uint32_t TxHeadRoom, struct xsk_umem_info* Umem)
{
    void *buffer;
    if (posix_memalign(&buffer, getpagesize(), frameSize * numFrames)) {
        QuicTraceLogVerbose(
            XdpAllocUmem,
            "[ xdp] Failed to allocate umem");
        return QUIC_STATUS_OUT_OF_MEMORY;
    }

    struct xsk_umem_config UmemConfig = {
        .fill_size = PROD_NUM_DESCS,
        .comp_size = CONS_NUM_DESCS,
        .frame_size = frameSize, // frame_size is really sensitive to become EINVAL
        // .frame_headroom = TxHeadRoom,
        .frame_headroom = 0,
        .flags = 0
    };

    int Ret = xsk_umem__create(&Umem->umem, buffer, frameSize * numFrames, &Umem->fq, &Umem->cq, &UmemConfig);
    if (Ret) {
        errno = -Ret;
        return QUIC_STATUS_INTERNAL_ERROR;
    }

    Umem->buffer = buffer;
    Umem->RxHeadRoom = RxHeadRoom;
    Umem->TxHeadRoom = TxHeadRoom;
    return QUIC_STATUS_SUCCESS;
}

static uint64_t xsk_alloc_umem_frame(struct xsk_socket_info *xsk)
{
    uint64_t frame;
    if (xsk->umem_frame_free == 0) {
        // fprintf(stderr, "[%p] XSK UMEM alloc:\tOOM\n", xsk);
        QuicTraceLogVerbose(
            XdpUmemAllocFails,
            "[ xdp][umem] Out of UMEM frame, OOM");        
        return INVALID_UMEM_FRAME;
    }

    frame = xsk->umem_frame_addr[--xsk->umem_frame_free];
    xsk->umem_frame_addr[xsk->umem_frame_free] = INVALID_UMEM_FRAME;
    // fprintf(stderr, "[%p] XSK UMEM alloc:\t%d:%ld\n", xsk, xsk->umem_frame_free, frame);
    return frame;
}

// not used yet as bpf map control with already attached bpf object doesn't work
uint8_t
IsXdpAttached(const char* prog_name, XDP_INTERFACE *Interface, enum xdp_attach_mode attach_mode)
{
    struct xdp_multiprog* mp = xdp_multiprog__get_from_ifindex(Interface->IfIndex);
    if (!mp) {
        return 0; // should not happen
    }
    enum xdp_attach_mode mode = xdp_multiprog__attach_mode(mp);
    struct xdp_program *p = NULL;

    while ((p = xdp_multiprog__next_prog(p, mp))) {
        if (strcmp(xdp_program__name(p), prog_name) == 0) {
            if (mode == attach_mode) {
                QuicTraceLogVerbose(
                    XdpAttached,
                    "[ xdp] XDP program already attached to %s", Interface->IfName);
                fprintf(stderr, "XDP program %s already attached to %s\n",
                    prog_name, Interface->IfName);
                return 2; // attached same
            }
            return 1; // attached, but different mode
        }
    }
    // not attached anything, or attaching different program
    return 0;
}

QUIC_STATUS
AttachXdpProgram(struct xdp_program *prog, XDP_INTERFACE *Interface, struct xsk_socket_config *xskcfg)
{
    char errmsg[1024];
    int err;
    enum xdp_attach_mode attach_mode = XDP_MODE_NATIVE;

    // TODO: iterate from HW -> DRV -> SKB
    static const struct AttachTypePair {
        enum xdp_attach_mode mode;
        unsigned int xdp_flag;
    } AttachTypePairs[]  = {
        { XDP_MODE_HW, XDP_FLAGS_HW_MODE },
        { XDP_MODE_NATIVE, XDP_FLAGS_DRV_MODE },
        { XDP_MODE_SKB, XDP_FLAGS_SKB_MODE },
    };
    UNREFERENCED_PARAMETER(AttachTypePairs);

    switch (xskcfg->xdp_flags) {
    case XDP_FLAGS_DRV_MODE:
        attach_mode = XDP_MODE_NATIVE;
        break;
    case XDP_FLAGS_SKB_MODE:
        attach_mode = XDP_MODE_SKB;
        break;
    case XDP_FLAGS_HW_MODE:
        attach_mode = XDP_MODE_HW;
        break;
    default:
        CXPLAT_DBG_ASSERT(FALSE);
    }

    err = xdp_program__attach(prog, Interface->IfIndex, attach_mode, 0);
    if (err) {
        libxdp_strerror(err, errmsg, sizeof(errmsg));
        QuicTraceLogVerbose(
            XdpAttachFails,
            "[ xdp] Failed to attach XDP program to %s. error:%s", Interface->IfName, errmsg);
        return QUIC_STATUS_INTERNAL_ERROR;
    }
    QuicTraceLogVerbose(
        XdpAttachSucceeds,
        "[ xdp] Successfully attach XDP program to %s", Interface->IfName);
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
    const uint32_t RxHeadroom = sizeof(XDP_RX_PACKET) + ALIGN_UP(ClientRecvContextLength, uint32_t);
    const uint32_t TxHeadroom = FIELD_OFFSET(XDP_TX_PACKET, FrameBuffer);
    // WARN: variable frame size cause unexpected behavior
    // TODO: 2K mode
    const uint32_t FrameSize = FRAME_SIZE;
    // const uint64_t UmemSize = NUM_FRAMES * FrameSize;
    QUIC_STATUS Status = QUIC_STATUS_SUCCESS;

    // Interface->OffloadStatus.Receive.NetworkLayerXsum = Xdp->SkipXsum;
    // Interface->OffloadStatus.Receive.TransportLayerXsum = Xdp->SkipXsum;
    // Interface->OffloadStatus.Transmit.NetworkLayerXsum = Xdp->SkipXsum;
    // Interface->OffloadStatus.Transmit.NetworkLayerXsum = Xdp->SkipXsum;
    Interface->Xdp = Xdp;
    struct xsk_socket_config *XskCfg = (struct xsk_socket_config*)calloc(1, sizeof(struct xsk_socket_config));
    if (!XskCfg) {
        Status = QUIC_STATUS_OUT_OF_MEMORY;
        goto Error;
    }
    XskCfg->rx_size = CONS_NUM_DESCS;
    XskCfg->tx_size = PROD_NUM_DESCS;
    XskCfg->libbpf_flags = XSK_LIBBPF_FLAGS__INHIBIT_PROG_LOAD;
    XskCfg->xdp_flags = XDP_FLAGS_DRV_MODE;
    // TODO: check ZEROCOPY feature, change Tx/Rx behavior based on feature
    //       refer xdp-tools/xdp-loader/xdp-loader features <ifname>
    XskCfg->bind_flags &= ~XDP_ZEROCOPY;
    XskCfg->bind_flags |= XDP_COPY;
    XskCfg->bind_flags |= XDP_USE_NEED_WAKEUP;
    Interface->XskCfg = XskCfg;

    struct xdp_program *prog;

    prog = xdp_program__open_file("./datapath_raw_xdp_kern.o", "xdp_prog", NULL);

    // uint8_t Attached = IsXdpAttached(xdp_program__name(prog), Interface, XDP_MODE_SKB);
    // FIXME: eth0 on azure VM doesn't work with XDP_FLAGS_DRV_MODE
    XskCfg->xdp_flags = XDP_FLAGS_SKB_MODE;
    if (QUIC_FAILED(AttachXdpProgram(prog, Interface, XskCfg))) {
        goto Error;
    }
    Interface->XdpProg = prog;

    int XskBypassMapFd = bpf_map__fd(bpf_object__find_map_by_name(xdp_program__bpf_obj(prog), "xsks_map"));
    if (XskBypassMapFd < 0) {
        fprintf(stderr, "ERROR: no xsks map found: %s\n",
            strerror(XskBypassMapFd));
        exit(EXIT_FAILURE);
    }

    // Debug info for bpf
    struct bpf_map *ifname_map = bpf_object__find_map_by_name(xdp_program__bpf_obj(prog), "ifname_map");
    if (ifname_map) {
        int key = 0;
        if (bpf_map_update_elem(bpf_map__fd(ifname_map), &key, Interface->IfName, BPF_ANY)) {
            fprintf(stderr, "Failed to update BPF map\n");
        }
    } else {
        fprintf(stderr, "Failed to find BPF ifacename_map\n");
    }

    Status = CxPlatGetInterfaceRssQueueCount(Interface->IfIndex, &Interface->QueueCount);
    if (QUIC_FAILED(Status)) {
        goto Error;
    }

    if (Interface->QueueCount == 0) {
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

    for (uint8_t i = 0; i < Interface->QueueCount; i++) {
        XDP_QUEUE* Queue = &Interface->Queues[i];

        Queue->Interface = Interface;
        CxPlatListInitializeHead(&Queue->TxPool);

        CxPlatLockInitialize(&Queue->TxLock);
        CxPlatLockInitialize(&Queue->RxLock);
        CxPlatLockInitialize(&Queue->FqLock);
        CxPlatLockInitialize(&Queue->CqLock);

        // Initialize shared packet_buffer for umem usage
        struct xsk_umem_info *Umem = calloc(1, sizeof(struct xsk_umem_info));
        if (!Umem) {
            Status = QUIC_STATUS_OUT_OF_MEMORY;
            goto Error;
        }

        Status = InitializeUmem(FRAME_SIZE, NUM_FRAMES, RxHeadroom, TxHeadroom, Umem);
        if (QUIC_FAILED(Status)) {
            QuicTraceLogVerbose(
                XdpConfigureUmem,
                "[ xdp] Failed to configure Umem");
            goto Error;
        }

        //
        // Create AF_XDP socket.
        //
        struct xsk_socket_info *xsk_info = calloc(1, sizeof(*xsk_info));
        if (!xsk_info) {
            Status = QUIC_STATUS_OUT_OF_MEMORY;
            goto Error;
        }
        CxPlatLockInitialize(&xsk_info->UmemLock);
        Queue->xsk_info = xsk_info;
        xsk_info->umem = Umem;
        int ret = xsk_socket__create(&xsk_info->xsk, Interface->IfName,
                    i, Umem->umem, &xsk_info->rx,
                    &xsk_info->tx, XskCfg);
        if (ret) {
            QuicTraceLogVerbose(
                XdpSocketCreate,
                "[ xdp] Failed to create AF_XDP socket. ret:%d errno:%d", ret, errno);
            Status = QUIC_STATUS_INTERNAL_ERROR;
            goto Error;
        }

        if(xsk_socket__update_xskmap(xsk_info->xsk, XskBypassMapFd)) {
            Status = QUIC_STATUS_INTERNAL_ERROR;
            goto Error;
        }

        for (int i = 0; i < NUM_FRAMES; i++) {
            xsk_info->umem_frame_addr[i] = i * FrameSize;
        }
        xsk_info->umem_frame_free = NUM_FRAMES;

        // Setup fill queue for Rx
        uint32_t FqIdx = 0;
        ret = xsk_ring_prod__reserve(&xsk_info->umem->fq, PROD_NUM_DESCS, &FqIdx);
        if (ret != PROD_NUM_DESCS) {
            return QUIC_STATUS_OUT_OF_MEMORY;
        }
        for (uint32_t i = 0; i < PROD_NUM_DESCS; i ++) {
            *xsk_ring_prod__fill_addr(&xsk_info->umem->fq, FqIdx++) =
                xsk_alloc_umem_frame(xsk_info) + RxHeadroom;
        }

        xsk_ring_prod__submit(&xsk_info->umem->fq, PROD_NUM_DESCS);
    }

    //
    // Add each queue to a worker (round robin).
    //
    for (uint8_t i = 0; i < Interface->QueueCount; i++) {
        XdpWorkerAddQueue(&Xdp->Partitions[i % Xdp->PartitionCount], &Interface->Queues[i]);
    }

Error:
    if (QUIC_FAILED(Status)) {
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
    _In_opt_ const QUIC_EXECUTION_CONFIG* Config
    )
{
    const uint32_t PartitionCount =
        (Config && Config->ProcessorCount) ? Config->ProcessorCount : CxPlatProcMaxCount();
    return sizeof(XDP_DATAPATH) + (PartitionCount * sizeof(XDP_PARTITION));
}

_IRQL_requires_max_(PASSIVE_LEVEL)
QUIC_STATUS
CxPlatDpRawInitialize(
    _Inout_ CXPLAT_DATAPATH* Datapath,
    _In_ uint32_t ClientRecvContextLength,
    _In_opt_ const QUIC_EXECUTION_CONFIG* Config
    )
{
    XDP_DATAPATH* Xdp = (XDP_DATAPATH*)Datapath;
    QUIC_STATUS Status = QUIC_STATUS_SUCCESS;

    CxPlatXdpReadConfig(Xdp);
    CxPlatListInitializeHead(&Xdp->Interfaces);
    Xdp->PollingIdleTimeoutUs = Config ? Config->PollingIdleTimeoutUs : 0;

    if (Config && Config->ProcessorCount) {
        Xdp->PartitionCount = Config->ProcessorCount;
    } else {
        Xdp->PartitionCount = CxPlatProcMaxCount();
    }

    QuicTraceLogVerbose(
        XdpInitialize,
        "[ xdp][%p] XDP initialized, %u procs",
        Xdp,
        Xdp->PartitionCount);

    struct ifaddrs *ifaddr, *ifa;
    int family;

    if (getifaddrs(&ifaddr) == -1) {
        return QUIC_STATUS_INTERNAL_ERROR;
    }

    for (ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next) {
        if (ifa->ifa_addr == NULL) {
            continue;
        }
        family = ifa->ifa_addr->sa_family;

        if ((ifa->ifa_flags & IFF_UP) &&
            // !(ifa->ifa_flags & IFF_LOOPBACK) &&
            // FIXME: if there are MASTER-SLAVE interfaces, slave need to be
            //         loaded first to load all interfaces
            !(ifa->ifa_flags & IFF_SLAVE) &&
            family == AF_PACKET) {
            // Create and initialize the interface data structure here
            XDP_INTERFACE* Interface = (XDP_INTERFACE*) malloc(sizeof(XDP_INTERFACE));
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
            struct sockaddr_ll *sall = (struct sockaddr_ll*)ifa->ifa_addr;
            memcpy(Interface->PhysicalAddress, sall->sll_addr, sizeof(Interface->PhysicalAddress));

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
        Partition->ShutdownSqe.CqeType = CXPLAT_CQE_TYPE_SOCKET_SHUTDOWN;
        CxPlatRefIncrement(&Xdp->RefCount);
        Partition->EventQ = CxPlatWorkerGetEventQ((uint16_t)i);

        // if (!CxPlatSqeInitialize(
        //         Partition->EventQ,
        //         &Partition->ShutdownSqe.Sqe,
        //         &Partition->ShutdownSqe)) {
        //     Status = QUIC_STATUS_INTERNAL_ERROR;
        //     goto Error;
        // }

        uint32_t QueueCount = 0;
        XDP_QUEUE* Queue = Partition->Queues;
        while (Queue) {
            if (!CxPlatSqeInitialize(
                    Partition->EventQ,
                    &Queue->RxIoSqe.Sqe,
                    &Queue->RxIoSqe)) {
                Status = QUIC_STATUS_INTERNAL_ERROR;
                goto Error;
            }
            Queue->RxIoSqe.CqeType = CXPLAT_CQE_TYPE_SOCKET_IO;
            CxPlatSocketContextSetEvents(Queue, EPOLL_CTL_ADD, EPOLLIN);

            // if (!CxPlatSqeInitialize(
            //     Partition->EventQ,
            //     &Queue->TxIoSqe.Sqe,
            //     &Queue->TxIoSqe)) {
            //     Status = QUIC_STATUS_INTERNAL_ERROR;
            //     goto Error;
            // }
            // Queue->TxIoSqe.CqeType = CXPLAT_CQE_TYPE_SOCKET_FLUSH_TX
            // CxPlatSocketContextSetEvents(Queue, EPOLL_CTL_ADD, EPOLLIN);
            // TODOL other queues
            ++QueueCount;
            Queue = Queue->Next;
        }

        QuicTraceLogVerbose(
            XdpWorkerStart,
            "[ xdp][%p] XDP partition start, %u queues",
            Partition,
            QueueCount);

        CxPlatAddExecutionContext(&Partition->Ec, Partition->PartitionIndex);
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
    // if (CxPlatRefDecrement(&Xdp->RefCount)) {
        QuicTraceLogVerbose(
            XdpUninitializeComplete,
            "[ xdp][%p] XDP uninitialize complete",
            Xdp);
        while (!CxPlatListIsEmpty(&Xdp->Interfaces)) {
            XDP_INTERFACE* Interface =
                CXPLAT_CONTAINING_RECORD(CxPlatListRemoveHead(&Xdp->Interfaces), XDP_INTERFACE, Link);
            CxPlatDpRawInterfaceUninitialize(Interface);
            CxPlatFree(Interface, IF_TAG);
        }
        CxPlatDataPathUninitializeComplete((CXPLAT_DATAPATH*)Xdp);
    // }
}

_IRQL_requires_max_(PASSIVE_LEVEL)
void
CxPlatDpRawUninitialize(
    _In_ CXPLAT_DATAPATH* Datapath
    )
{
    XDP_DATAPATH* Xdp = (XDP_DATAPATH*)Datapath;
    QuicTraceLogVerbose(
        XdpUninitialize,
        "[ xdp][%p] XDP uninitialize",
        Xdp);
    Xdp->Running = FALSE;
    // TODO: currently no worker created
    for (uint32_t i = 0; i < Xdp->PartitionCount; i++) {
        Xdp->Partitions[i].Ec.Ready = TRUE;
        CxPlatWakeExecutionContext(&Xdp->Partitions[i].Ec);
    }
    CxPlatDpRawRelease(Xdp);
}

_IRQL_requires_max_(PASSIVE_LEVEL)
void
CxPlatDpRawUpdateConfig(
    _In_ CXPLAT_DATAPATH* Datapath,
    _In_ QUIC_EXECUTION_CONFIG* Config
    )
{
    XDP_DATAPATH* Xdp = (XDP_DATAPATH*)Datapath;
    Xdp->PollingIdleTimeoutUs = Config->PollingIdleTimeoutUs;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
void
CxPlatDpRawPlumbRulesOnSocket(
    _In_ CXPLAT_SOCKET* Socket,
    _In_ BOOLEAN IsCreated
    )
{
    CXPLAT_LIST_ENTRY* Entry = Socket->Datapath->Interfaces.Flink;
    for (; Entry != &Socket->Datapath->Interfaces; Entry = Entry->Flink) {
        XDP_INTERFACE* Interface = (XDP_INTERFACE*)CXPLAT_CONTAINING_RECORD(Entry, CXPLAT_INTERFACE, Link);
        struct bpf_map *port_map = bpf_object__find_map_by_name(xdp_program__bpf_obj(Interface->XdpProg), "port_map");
        if (!port_map) {
            fprintf(stderr, "CxPlatDpRawPlumbRulesOnSocket: Failed to find BPF port_map\n");
        }

        int port = Socket->LocalAddress.Ipv4.sin_port;
        if (IsCreated) {
            BOOLEAN exist = true;
            if (bpf_map_update_elem(bpf_map__fd(port_map), &port, &exist, BPF_ANY)) {
                fprintf(stderr, "CxPlatDpRawPlumbRulesOnSocket: Failed to update BPF map on %s, port:%d\n", Interface->IfName, port);
            }
        } else {
            if (bpf_map_delete_elem(bpf_map__fd(port_map), &port)) {
                fprintf(stderr, "CxPlatDpRawPlumbRulesOnSocket: Failed to delete port %d from BPF map on %s\n", port, Interface->IfName);
            }
        }

        struct bpf_map *ifname_map = bpf_object__find_map_by_name(xdp_program__bpf_obj(Interface->XdpProg), "ifname_map");
        if (!ifname_map) {
            fprintf(stderr, "CxPlatDpRawPlumbRulesOnSocket: Failed to find BPF ifacename_map\n");
        }

        int key = 0;
        if (IsCreated) {
            if (bpf_map_update_elem(bpf_map__fd(ifname_map), &key, Interface->IfName, BPF_ANY)) {
                fprintf(stderr, "CxPlatDpRawPlumbRulesOnSocket: Failed to update BPF map\n");
            }
        } // BPF_MAP_TYPE_ARRAY doesn't support delete
    }
}

_IRQL_requires_max_(PASSIVE_LEVEL)
void
CxPlatDpRawAssignQueue(
    _In_ const CXPLAT_INTERFACE* _Interface,
    _Inout_ CXPLAT_ROUTE* Route
    )
{
    const XDP_INTERFACE* Interface = (const XDP_INTERFACE*)_Interface;
    Route->Queue = &Interface->Queues[0];
}

_IRQL_requires_max_(DISPATCH_LEVEL)
const CXPLAT_INTERFACE*
CxPlatDpRawGetInterfaceFromQueue(
    _In_ const void* Queue
    )
{
    return (const CXPLAT_INTERFACE*)((XDP_QUEUE*)Queue)->Interface;
}

static void xsk_free_umem_frame(struct xsk_socket_info *xsk, uint64_t frame)
{
    assert(xsk->umem_frame_free < NUM_FRAMES);
    xsk->umem_frame_addr[xsk->umem_frame_free++] = frame;
}

_IRQL_requires_max_(DISPATCH_LEVEL)
void
CxPlatDpRawRxFree(
    _In_opt_ const CXPLAT_RECV_DATA* PacketChain
    )
{
    uint32_t Count = 0;
    // struct xsk_socket_info *xsk_info = ((XDP_RX_PACKET*)PacketChain)->Queue->xsk_info;
    struct xsk_socket_info *xsk_info = NULL;
    if (PacketChain) {
        const XDP_RX_PACKET* Packet =
            CXPLAT_CONTAINING_RECORD(PacketChain, XDP_RX_PACKET, RecvData);
        xsk_info = Packet->Queue->xsk_info;

        CxPlatLockAcquire(&xsk_info->UmemLock);
        while (PacketChain) {
            Packet =
                CXPLAT_CONTAINING_RECORD(PacketChain, XDP_RX_PACKET, RecvData);
            PacketChain = PacketChain->Next;
            // NOTE: for some reason there is 8 bit gap
            xsk_free_umem_frame(Packet->Queue->xsk_info, Packet->addr - xsk_info->umem->RxHeadRoom - 8);
            Count++;
        }
    }

    CxPlatLockRelease(&xsk_info->UmemLock);
}

_IRQL_requires_max_(DISPATCH_LEVEL)
CXPLAT_SEND_DATA*
CxPlatDpRawTxAlloc(
    _In_ CXPLAT_SOCKET* Socket,
    _Inout_ CXPLAT_SEND_CONFIG* Config
    )
{
    CXPLAT_DBG_ASSERT(Socket != NULL);
    CXPLAT_DBG_ASSERT(Config->MaxPacketSize <= MAX_UDP_PAYLOAD_LENGTH);
    QUIC_ADDRESS_FAMILY Family = QuicAddrGetFamily(&Config->Route->RemoteAddress);
    XDP_TX_PACKET* Packet = NULL;
    XDP_QUEUE* Queue = Config->Route->Queue;
    struct xsk_socket_info* xsk_info = Queue->xsk_info;
    CxPlatLockAcquire(&xsk_info->UmemLock);
    uint64_t BaseAddr = xsk_alloc_umem_frame(xsk_info);
    CxPlatLockRelease(&xsk_info->UmemLock);
    if (BaseAddr == INVALID_UMEM_FRAME) {
        QuicTraceLogVerbose(
            FailTxAlloc,
            "[ xdp][tx  ] OOM for Tx");
        goto Error;
    }

    Packet = (XDP_TX_PACKET*)xsk_umem__get_data(xsk_info->umem->buffer, BaseAddr);
    if (Packet) {
        HEADER_BACKFILL HeaderBackfill = CxPlatDpRawCalculateHeaderBackFill(Family, Socket->UseTcp); // TODO - Cache in Route?
        CXPLAT_DBG_ASSERT(Config->MaxPacketSize <= sizeof(Packet->FrameBuffer) - HeaderBackfill.AllLayer);
        Packet->Queue = Queue;
        Packet->Buffer.Length = Config->MaxPacketSize;
        Packet->Buffer.Buffer = &Packet->FrameBuffer[HeaderBackfill.AllLayer];
        Packet->ECN = Config->ECN;
        Packet->UmemRelativeAddr = BaseAddr;
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

_IRQL_requires_max_(DISPATCH_LEVEL)
void
CxPlatDpRawTxEnqueue(
    _In_ CXPLAT_SEND_DATA* SendData
    )
{
    // TODO: use PartitionTxQueue to submit at once?
    XDP_TX_PACKET* Packet = (XDP_TX_PACKET*)SendData;
    struct xsk_socket_info* xsk_info = Packet->Queue->xsk_info;
    CxPlatLockAcquire(&xsk_info->UmemLock);

    uint32_t tx_idx = 0;
    if (xsk_ring_prod__reserve(&xsk_info->tx, 1, &tx_idx) != 1) {
        xsk_free_umem_frame(xsk_info, Packet->UmemRelativeAddr);
        QuicTraceLogVerbose(
            FailTxReserve,
            "[ xdp][tx  ] Failed to reserve");
        return;
    }

    struct xdp_desc *tx_desc = xsk_ring_prod__tx_desc(&xsk_info->tx, tx_idx);
    CXPLAT_FRE_ASSERT(tx_desc != NULL);
    tx_desc->addr = Packet->UmemRelativeAddr + xsk_info->umem->TxHeadRoom;
    tx_desc->len = SendData->Buffer.Length;

    xsk_ring_prod__submit(&xsk_info->tx, 1);
    if (sendto(xsk_socket__fd(xsk_info->xsk), NULL, 0, MSG_DONTWAIT, NULL, 0) < 0) {
        int er = errno;
        QuicTraceLogVerbose(
            FailSendTo,
            "[ xdp][tx  ] Faild sendto. errno:%d, Umem addr:%lld", er, tx_desc->addr);
    } else {
        QuicTraceLogVerbose(
            DoneSendTo,
            "[ xdp][TX  ] Done sendto. len:%d, Umem addr:%lld", SendData->Buffer.Length, tx_desc->addr);
    }

    uint32_t Completed;
    uint32_t CqIdx;
    Completed = xsk_ring_cons__peek(&xsk_info->umem->cq, CONS_NUM_DESCS, &CqIdx);
    if (Completed > 0) {
        for (uint32_t i = 0; i < Completed; i++) {
            xsk_free_umem_frame(xsk_info,
                                *xsk_ring_cons__comp_addr(&xsk_info->umem->cq,
                                                          CqIdx++) - xsk_info->umem->TxHeadRoom);
        }

        xsk_ring_cons__release(&xsk_info->umem->cq, Completed);
        QuicTraceLogVerbose(
            ReleaseCons,
            "[ xdp][cq  ] Release %d from completion queue", Completed);
    }
    CxPlatLockRelease(&xsk_info->UmemLock);

    // Partition->Ec.Ready = TRUE;
    // CxPlatWakeExecutionContext(&Partition->Ec);
}

_IRQL_requires_max_(PASSIVE_LEVEL)
BOOLEAN
CxPlatXdpExecute(
    _Inout_ void* Context,
    _Inout_ CXPLAT_EXECUTION_STATE* State
    )
{
    UNREFERENCED_PARAMETER(Context);
    UNREFERENCED_PARAMETER(State);
    return TRUE;
}

static uint64_t xsk_umem_free_frames(struct xsk_socket_info *xsk)
{
    return xsk->umem_frame_free;
}

void CxPlatXdpRx(
    _In_ XDP_QUEUE* Queue
    )
{
    struct xsk_socket_info *xsk = Queue->xsk_info;
    uint32_t Rcvd, i;
    uint32_t Available;
    uint32_t RxIdx = 0, FqIdx = 0;
    unsigned int ret;

    Rcvd = xsk_ring_cons__peek(&xsk->rx, RX_BATCH_SIZE, &RxIdx);
    if (!Rcvd) {
        QuicTraceLogVerbose(
            RxConsPeekFail,
            "[ xdp][rx  ] Failed to peek from Rx queue");
        return;
    } else {
        QuicTraceLogVerbose(
            RxConsPeekSucceed,
            "[ xdp][rx  ] Succeed peek %d from Rx queue", Rcvd);
    }

    CxPlatLockAcquire(&xsk->UmemLock);
    // Stuff the ring with as much frames as possible
    Available = xsk_prod_nb_free(&xsk->umem->fq,
                    xsk_umem_free_frames(xsk)); //TODO: remove lock and use  as big as possible?
    if (Available > 0) {
        ret = xsk_ring_prod__reserve(&xsk->umem->fq, Available, &FqIdx);

        // This should not happen, but just in case
        while (ret != Available) {
            ret = xsk_ring_prod__reserve(&xsk->umem->fq, Rcvd, &FqIdx);
        }
        for (i = 0; i < Available; i++) {
            *xsk_ring_prod__fill_addr(&xsk->umem->fq, FqIdx++) =
                xsk_alloc_umem_frame(xsk) + xsk->umem->RxHeadRoom;
        }
        xsk_ring_prod__submit(&xsk->umem->fq, Available);
    }
    CxPlatLockRelease(&xsk->UmemLock);

    // Process received packets
    CXPLAT_RECV_DATA* Buffers[RX_BATCH_SIZE];
    uint32_t PacketCount = 0;
    for (i = 0; i < Rcvd; i++) {
        uint64_t addr = xsk_ring_cons__rx_desc(&xsk->rx, RxIdx)->addr;
        uint32_t len = xsk_ring_cons__rx_desc(&xsk->rx, RxIdx++)->len;
        uint8_t *FrameBuffer = xsk_umem__get_data(xsk->umem->buffer, addr);
        XDP_RX_PACKET* Packet = (XDP_RX_PACKET*)(FrameBuffer - xsk->umem->RxHeadRoom);
        CxPlatZeroMemory(Packet, xsk->umem->RxHeadRoom);

        Packet->Queue = Queue;
        Packet->RouteStorage.Queue = Queue;
        Packet->RecvData.Route = &Packet->RouteStorage;
        Packet->RecvData.PartitionIndex = Queue->Partition->PartitionIndex;

        // TODO xsk_free_umem_frame if parse error?
        CxPlatDpRawParseEthernet(
            (CXPLAT_DATAPATH*)Queue->Partition->Xdp,
            &Packet->RecvData,
            FrameBuffer,
            (uint16_t)len);
        if (false) {
            // free if CxPlatDpRawParseEthernet failed
            xsk_free_umem_frame(xsk, addr - xsk->umem->RxHeadRoom);
        }
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

        Packet->addr = addr;
        Packet->RecvData.Allocated = TRUE;
        Buffers[PacketCount++] = &Packet->RecvData;
    }

    if (Rcvd) {
        xsk_ring_cons__release(&xsk->rx, Rcvd);

        CxPlatDpRawRxEthernet(
            (CXPLAT_DATAPATH*)Queue->Partition->Xdp,
            Buffers,
            (uint16_t)Rcvd);
    }
}

void
CxPlatDataPathProcessCqe(
    _In_ CXPLAT_CQE* Cqe
    )
{
    switch (CxPlatCqeType(Cqe)) {
    case CXPLAT_CQE_TYPE_SOCKET_SHUTDOWN: {
        // XDP_PARTITION* Partition =
        //     CXPLAT_CONTAINING_RECORD(CxPlatCqeUserData(Cqe), XDP_PARTITION, ShutdownSqe);

        // // CXPLAT_SOCKET_CONTEXT* SocketContext =
        // //     CXPLAT_CONTAINING_RECORD(CxPlatCqeUserData(Cqe), CXPLAT_SOCKET_CONTEXT, ShutdownSqe);
        // // CxPlatSocketContextUninitializeComplete(SocketContext);
        break;
    }
    case CXPLAT_CQE_TYPE_SOCKET_IO: {
        // TODO: use DATAPATH_IO_SQE to distinguish Tx/RX
        DATAPATH_SQE* Sqe = (DATAPATH_SQE*)CxPlatCqeUserData(Cqe);
        XDP_QUEUE* Queue;
        Queue = CXPLAT_CONTAINING_RECORD(Sqe, XDP_QUEUE, RxIoSqe);
        CxPlatXdpRx(Queue);
        QuicTraceLogVerbose(
            XdpQueueAsyncIoRxComplete,
            "[ xdp][%p] XDP async IO complete (RX)",
            Queue);
        Queue->RxQueued = FALSE;
        break;
    }
    case CXPLAT_CQE_TYPE_SOCKET_FLUSH_TX: {

    }
    }
}
