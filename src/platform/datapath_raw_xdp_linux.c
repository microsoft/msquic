/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.

Abstract:

    QUIC XDP Datapath Implementation (User Mode)

--*/

#define _CRT_SECURE_NO_WARNINGS 1 // TODO - Remove

#include "datapath_raw_linux.h"
#include "datapath_raw_xdp_linux.h"
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
            *Queue->Worker->EventQ,
            Operation,
            xsk_socket__fd(Queue->xsk_info->xsk),
            &SockFdEpEvt);
    if (Ret != 0) {

    }
}


void XdpWorkerAddQueue(_In_ XDP_WORKER* Worker, _In_ XDP_QUEUE* Queue) {
    XDP_QUEUE** Tail = &Worker->Queues;
    while (*Tail != NULL) {
        Tail = &(*Tail)->Next;
    }
    *Tail = Queue;
    Queue->Next = NULL;
    Queue->Worker = Worker;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
BOOLEAN
CxPlatXdpExecute(
    _Inout_ void* Context,
    _Inout_ CXPLAT_EXECUTION_STATE* State
    );

CXPLAT_RECV_DATA*
CxPlatDataPathRecvPacketToRecvData(
    _In_ const CXPLAT_RECV_PACKET* const Context
    )
{
    return (CXPLAT_RECV_DATA*)(((uint8_t*)Context) - sizeof(XDP_RX_PACKET));
}

CXPLAT_RECV_PACKET*
CxPlatDataPathRecvDataToRecvPacket(
    _In_ const CXPLAT_RECV_DATA* const Datagram
    )
{
    return (CXPLAT_RECV_PACKET*)(((uint8_t*)Datagram) + sizeof(XDP_RX_PACKET));
}

QUIC_STATUS
CxPlatGetInterfaceRssQueueCount(
    _In_ uint32_t InterfaceIndex,
    _Out_ uint16_t* Count
    )
{
    UNREFERENCED_PARAMETER(InterfaceIndex);
    UNREFERENCED_PARAMETER(Count);
    return QUIC_STATUS_NOT_SUPPORTED;
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

_IRQL_requires_max_(PASSIVE_LEVEL)
void
CxPlatDpRawInterfaceUninitialize(
    _Inout_ XDP_INTERFACE* Interface
    )
{
    UNREFERENCED_PARAMETER(Interface);
    for (uint32_t i = 0; Interface->Queues != NULL && i < Interface->QueueCount; i++) {
        XDP_QUEUE *Queue = &Interface->Queues[i];

        xsk_socket__delete(Queue->xsk_info->xsk);
        xsk_umem__delete(Queue->xsk_info->umem->umem);
        CxPlatSleep(20);

        // if (Queue->TxXsk != NULL) {
        //     CloseHandle(Queue->TxXsk);
        // }

        if (Queue->TxBuffers != NULL) {
            CxPlatFree(Queue->TxBuffers, TX_BUFFER_TAG);
        }

        // if (Queue->RxProgram != NULL) {
        //     CloseHandle(Queue->RxProgram);
        // }

        // if (Queue->RxXsk != NULL) {
        //     CloseHandle(Queue->RxXsk);
        // }

        if (Queue->RxBuffers != NULL) {
            CxPlatFree(Queue->RxBuffers, RX_BUFFER_TAG);
        }

        CxPlatLockUninitialize(&Queue->TxLock);
    }

    if (Interface->Queues != NULL) {
        CxPlatFree(Interface->Queues, QUEUE_TAG);
    }

    // if (Interface->Rules != NULL) {
    //     for (uint8_t i = 0; i < Interface->RuleCount; ++i) {
    //         if (Interface->Rules[i].Pattern.IpPortSet.PortSet.PortSet) {
    //             CxPlatFree(Interface->Rules[i].Pattern.IpPortSet.PortSet.PortSet, PORT_SET_TAG);
    //         }
    //     }
    //     CxPlatFree(Interface->Rules, RULE_TAG);
    // }

    // if (Interface->XdpHandle) {
    //     CloseHandle(Interface->XdpHandle);
    // }

    CxPlatLockUninitialize(&Interface->RuleLock);
}

static struct xsk_umem_info *configure_xsk_umem(void *buffer, uint64_t size, uint32_t TxHeadRoom)
{
    struct xsk_umem_info *umem;
    int ret;

    umem = calloc(1, sizeof(*umem)); // TODO: free
    if (!umem)
        return NULL;

    struct xsk_umem_config umem_config = {
        .fill_size = NUM_FRAMES,
        .comp_size = NUM_FRAMES,
        .frame_size = XSK_UMEM__DEFAULT_FRAME_SIZE, // frame_size is really sensitive to become EINVAL
        // .frame_size = sizeof(XDP_TX_PACKET),
        .frame_headroom = TxHeadRoom,
        .flags = 0
    };
    UNREFERENCED_PARAMETER(TxHeadRoom);

    ret = xsk_umem__create(&umem->umem, buffer, size, &umem->fq, &umem->cq, &umem_config);
    if (ret) {
        errno = -ret;
        return NULL;
    }

    umem->buffer = buffer;
    return umem;
}

QUIC_STATUS xdp_link_attach(int ifindex, __u32 xdp_flags, int prog_fd)
{
    QUIC_STATUS Status = QUIC_STATUS_SUCCESS;
    /* libbpf provide the XDP net_device link-level hook attach helper */
    int err = bpf_set_link_xdp_fd(ifindex, prog_fd, xdp_flags);
    if (err == -EEXIST && !(xdp_flags & XDP_FLAGS_UPDATE_IF_NOEXIST)) {
        /* Force mode didn't work, probably because a program of the
         * opposite type is loaded. Let's unload that and try loading
         * again.
         */

        __u32 old_flags = xdp_flags;

        xdp_flags &= ~XDP_FLAGS_MODES;
        xdp_flags |= (old_flags & XDP_FLAGS_SKB_MODE) ? XDP_FLAGS_DRV_MODE : XDP_FLAGS_SKB_MODE;
        err = bpf_set_link_xdp_fd(ifindex, -1, xdp_flags);
        if (!err)
            err = bpf_set_link_xdp_fd(ifindex, prog_fd, old_flags);
    }
    if (err < 0) {
        fprintf(stderr, "ERR: "
            "ifindex(%d) link set xdp fd failed (%d): %s\n",
            ifindex, -err, strerror(-err));

        switch (-err) {
        case EBUSY:
        case EEXIST:
            fprintf(stderr, "Hint: XDP already loaded on device"
                " use --force to swap/replace\n");
            Status = QUIC_STATUS_INVALID_STATE;
            break;
        case EOPNOTSUPP:
            fprintf(stderr, "Hint: Native-XDP not supported"
                " use --skb-mode or --auto-mode\n");
            Status = QUIC_STATUS_NOT_SUPPORTED;
            break;
        default:
            Status = QUIC_STATUS_INTERNAL_ERROR;
            break;
        }
    }
    return Status;
}

struct bpf_object *load_bpf_object_file(const char *filename, int ifindex)
{
    int first_prog_fd = -1;
    struct bpf_object *obj;
    int err;

    /* This struct allow us to set ifindex, this features is used for
     * hardware offloading XDP programs (note this sets libbpf
     * bpf_program->prog_ifindex and foreach bpf_map->map_ifindex).
     */
    struct bpf_prog_load_attr prog_load_attr = {
        .prog_type = BPF_PROG_TYPE_XDP,
        .ifindex   = ifindex,
    };
    prog_load_attr.file = filename;

    /* Use libbpf for extracting BPF byte-code from BPF-ELF object, and
     * loading this into the kernel via bpf-syscall
     */
    err = bpf_prog_load_xattr(&prog_load_attr, &obj, &first_prog_fd);
    if (err) {
        fprintf(stderr, "ERR: loading BPF-OBJ file(%s) (%d): %s\n",
            filename, err, strerror(-err));
        return NULL;
    }

    /* Notice how a pointer to a libbpf bpf_object is returned */
    return obj;
}

QUIC_STATUS load_bpf_and_xdp_attach(const char* filename, char* progsec, int ifindex, struct bpf_object **bpf_obj)
{
    // TODO: NULL out bpf_obj if any error happen?
    struct bpf_program *bpf_prog;
    int offload_ifindex = 0; // ?
    int prog_fd = -1;

    *bpf_obj = load_bpf_object_file(filename, offload_ifindex);
    if (!*bpf_obj) {
        fprintf(stderr, "ERR: loading file: %s\n", filename);
        return QUIC_STATUS_INVALID_PARAMETER;
    }
    /* At this point: All XDP/BPF programs from the cfg->filename have been
     * loaded into the kernel, and evaluated by the verifier. Only one of
     * these gets attached to XDP hook, the others will get freed once this
     * process exit.
     */
    bpf_prog = bpf_object__find_program_by_title(*bpf_obj, progsec);
    if (!bpf_prog) {
        fprintf(stderr, "ERR: couldn't find a program in ELF section '%s'\n", progsec);
        return QUIC_STATUS_INVALID_PARAMETER;
    }

    //strncpy(progsec, bpf_program__section_name(bpf_prog), 32);

    prog_fd = bpf_program__fd(bpf_prog);
    if (prog_fd <= 0) {
        fprintf(stderr, "ERR: bpf_program__fd failed\n");
        return QUIC_STATUS_INTERNAL_ERROR;
    }

    /* At this point: BPF-progs are (only) loaded by the kernel, and prog_fd
     * is our select file-descriptor handle. Next step is attaching this FD
     * to a kernel hook point, in this case XDP net_device link-level hook.
     */
    int xdp_flags = 0; // TODO: flag?
    return xdp_link_attach(ifindex, xdp_flags, prog_fd);
}

static uint64_t xsk_alloc_umem_frame(struct xsk_socket_info *xsk)
{
    uint64_t frame;
    if (xsk->umem_frame_free == 0)
        return INVALID_UMEM_FRAME;

    frame = xsk->umem_frame_addr[--xsk->umem_frame_free];
    // fprintf(stderr, "frame:%p, ", (void*)frame);
    xsk->umem_frame_addr[xsk->umem_frame_free] = INVALID_UMEM_FRAME;
    return frame;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
QUIC_STATUS
CxPlatDpRawInterfaceInitialize(
    _In_ XDP_DATAPATH* Xdp,
    _Inout_ XDP_INTERFACE* Interface,
    _In_ uint32_t ClientRecvContextLength
    )
{
    // TODO: cache RxHeadroom to somewhere
    const uint32_t RxHeadroom = sizeof(XDP_RX_PACKET) + ALIGN_UP(ClientRecvContextLength, uint32_t);
    const uint32_t RxPacketSize = ALIGN_UP(RxHeadroom + MAX_ETH_FRAME_SIZE, XDP_RX_PACKET); // TODO: aligh up with both tx/rx
    QUIC_STATUS Status = QUIC_STATUS_NOT_SUPPORTED;

    CxPlatLockInitialize(&Interface->RuleLock);
    // Interface->OffloadStatus.Receive.NetworkLayerXsum = Xdp->SkipXsum;
    // Interface->OffloadStatus.Receive.TransportLayerXsum = Xdp->SkipXsum;
    // Interface->OffloadStatus.Transmit.NetworkLayerXsum = Xdp->SkipXsum;
    // Interface->OffloadStatus.Transmit.NetworkLayerXsum = Xdp->SkipXsum;
    Interface->Xdp = Xdp;
     // TODO: free, or use stack in XDP_DATAPATH?
    struct xsk_socket_config *xsk_cfg = (struct xsk_socket_config*)calloc(1, sizeof(struct xsk_socket_config));
    xsk_cfg->rx_size = XSK_RING_CONS__DEFAULT_NUM_DESCS;
    xsk_cfg->tx_size = XSK_RING_PROD__DEFAULT_NUM_DESCS;
    // TODO: auto detect?
    xsk_cfg->libbpf_flags = XSK_LIBBPF_FLAGS__INHIBIT_PROG_LOAD;
    xsk_cfg->xdp_flags = 0;
    xsk_cfg->bind_flags = 0;

    struct bpf_object *bpf_obj;
    Status = load_bpf_and_xdp_attach("./datapath_raw_xdp_kern.o", "xdp_prog", Interface->IfIndex, &bpf_obj);
    struct bpf_map *map = bpf_object__find_map_by_name(bpf_obj, "xsks_map");
    int xsks_map_fd = bpf_map__fd(map);
    if (xsks_map_fd < 0) {
        fprintf(stderr, "ERROR: no xsks map found: %s\n",
            strerror(xsks_map_fd));
        exit(EXIT_FAILURE);
    }

    // TODO: implement
    // Status = CxPlatGetInterfaceRssQueueCount(Interface->IfIndex, &Interface->QueueCount);
    Interface->QueueCount = 1; // temporally

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

    for (uint8_t queue_id = 0; queue_id < Interface->QueueCount; queue_id++) {
        XDP_QUEUE* Queue = &Interface->Queues[queue_id];

        Queue->Interface = Interface;
        // InitializeSListHead(&Queue->RxPool);
        // InitializeSListHead(&Queue->TxPool);
        // CxPlatLockInitialize(&Queue->TxLock);
        // CxPlatListInitializeHead(&Queue->TxQueue);
        // CxPlatListInitializeHead(&Queue->WorkerTxQueue);
        // CxPlatDatapathSqeInitialize(&Queue->RxIoSqe.DatapathSqe, CXPLAT_CQE_TYPE_SOCKET_IO); // TODO: for epoll based
        // Queue->RxIoSqe.IoType = DATAPATH_IO_RECV;
        // CxPlatDatapathSqeInitialize(&Queue->TxIoSqe.DatapathSqe, CXPLAT_CQE_TYPE_SOCKET_IO);
        // Queue->TxIoSqe.IoType = DATAPATH_IO_SEND;


        void *packet_buffer; // TODO: free?
        uint64_t packet_buffer_size = NUM_FRAMES * RxPacketSize;
        // Allocate memory for NUM_FRAMES of the default XDP frame size
        if (posix_memalign(&packet_buffer,
                getpagesize(), /* PAGE_SIZE aligned */
                packet_buffer_size)) {
            fprintf(stderr, "ERROR: Can't allocate buffer memory \"%s\"\n",
                strerror(errno));
            exit(EXIT_FAILURE);
        }

        // Initialize shared packet_buffer for umem usage
        struct xsk_umem_info *umem;
        umem = configure_xsk_umem(packet_buffer, packet_buffer_size, FIELD_OFFSET(XDP_TX_PACKET, FrameBuffer));
        if (umem == NULL) {
            fprintf(stderr, "ERROR: Can't create umem \"%s\"\n",
                strerror(errno));
            exit(EXIT_FAILURE);
        }

        //
        // Create datagram socket.
        //
        struct xsk_socket_info *xsk_info = calloc(1, sizeof(*xsk_info)); // TODO: free
        if (!xsk_info) {
            return QUIC_STATUS_OUT_OF_MEMORY;
        }
        Queue->xsk_info = xsk_info;

        // TODO: share port from Binding->LocalAddress to BPF map
        xsk_info->umem = umem;
        char ifname[128] = {0}; // TODO: cache in Interface
        if_indextoname(Interface->IfIndex, ifname);
        int ret = xsk_socket__create(&xsk_info->xsk, ifname,
                    queue_id, umem->umem, &xsk_info->rx,
                    &xsk_info->tx, xsk_cfg);
        fprintf(stderr, "xsk_socket__create:%d\n", ret);
        if (ret) {
            return QUIC_STATUS_INTERNAL_ERROR;
        }
        CxPlatSleep(20); // Should be needed?

        for (int i = 0; i < NUM_FRAMES; i++) {
            xsk_info->umem_frame_addr[i] = i * RxPacketSize;
        }

        xsk_info->umem_frame_free = NUM_FRAMES;
        uint32_t prog_id = 0;
        ret = bpf_get_link_xdp_id(Interface->IfIndex, &prog_id, xsk_cfg->xdp_flags); // ?
        if (ret) {
            return QUIC_STATUS_INTERNAL_ERROR;
        }

        /* Stuff the receive path with buffers, we assume we have enough */
        uint32_t firstIdx = 0;
        ret = xsk_ring_prod__reserve(&xsk_info->umem->fq,
                        XSK_RING_PROD__DEFAULT_NUM_DESCS,
                        &firstIdx);
        if (ret != XSK_RING_PROD__DEFAULT_NUM_DESCS) {
            return QUIC_STATUS_OUT_OF_MEMORY;
        }

        for (int i = 0; i < XSK_RING_PROD__DEFAULT_NUM_DESCS; i ++) {
            *xsk_ring_prod__fill_addr(&xsk_info->umem->fq, firstIdx++) =
                xsk_alloc_umem_frame(xsk_info) + FIELD_OFFSET(XDP_TX_PACKET, FrameBuffer);
        }

        xsk_ring_prod__submit(&xsk_info->umem->fq,
                    XSK_RING_PROD__DEFAULT_NUM_DESCS);

    }

    //
    // Add each queue to a worker (round robin).
    //
    for (uint8_t i = 0; i < Interface->QueueCount; i++) {
        XdpWorkerAddQueue(&Xdp->Workers[i % Xdp->WorkerCount], &Interface->Queues[i]);
    }

    // Status = CxPlatGetInterfaceRssQueueCount(Interface->IfIndex, &Interface->QueueCount);
    // if (QUIC_FAILED(Status)) {
    //     goto Error;
    // }
    UNREFERENCED_PARAMETER(Xdp);
    UNREFERENCED_PARAMETER(Interface);
    UNREFERENCED_PARAMETER(ClientRecvContextLength);

Error:

    return Status;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
//_Requires_lock_held_(Interface->RuleLock)
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
    const uint32_t WorkerCount =
        (Config && Config->ProcessorCount) ? Config->ProcessorCount : CxPlatProcMaxCount();
    return sizeof(XDP_DATAPATH) + (WorkerCount * sizeof(XDP_WORKER));
}

#include <netpacket/packet.h>

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

    const uint16_t* ProcessorList;
    UNREFERENCED_PARAMETER(Status);
    UNREFERENCED_PARAMETER(ProcessorList);

    CxPlatXdpReadConfig(Xdp);
    CxPlatListInitializeHead(&Xdp->Interfaces);
    Xdp->PollingIdleTimeoutUs = Config ? Config->PollingIdleTimeoutUs : 0;

    if (Config && Config->ProcessorCount) {
        Xdp->WorkerCount = Config->ProcessorCount;
        ProcessorList = Config->ProcessorList;
    } else {
        Xdp->WorkerCount = CxPlatProcMaxCount();
        ProcessorList = NULL;
    }

    QuicTraceLogVerbose(
        XdpInitialize,
        "[ xdp][%p] XDP initialized, %u procs",
        Xdp,
        Xdp->WorkerCount);

    struct ifaddrs *ifaddr, *ifa;
    int family;//, s;

    // TODO: loop 3 times?
    if (getifaddrs(&ifaddr) == -1) {
        perror("getifaddrs");
        exit(EXIT_FAILURE);
    }

    for (ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next) {
        if (ifa->ifa_addr == NULL) {
            continue;
        }
        family = ifa->ifa_addr->sa_family;

        if ((ifa->ifa_flags & IFF_UP) &&
            !(ifa->ifa_flags & IFF_LOOPBACK) &&
            family == AF_PACKET) {
            // Create and initialize the interface data structure here
            XDP_INTERFACE* Interface = (XDP_INTERFACE*) malloc(sizeof(XDP_INTERFACE));
            if (Interface == NULL) {
                Status = QUIC_STATUS_OUT_OF_MEMORY;
                goto Error;
            }
            CxPlatZeroMemory(Interface, sizeof(*Interface));
            // TODO: remove
            //       setup duo nic only for simplisity
            if (memcmp(ifa->ifa_name, "duo", 3) != 0) {
                continue;
            }

            Interface->IfIndex = if_nametoindex(ifa->ifa_name);
            struct sockaddr_ll *sall = (struct sockaddr_ll*)ifa->ifa_addr;
            memcpy(Interface->PhysicalAddress, sall->sll_addr, sizeof(Interface->PhysicalAddress));
            for (int i = 0; i < 6; i++) {
                fprintf(stderr, "%02x:", Interface->PhysicalAddress[i]);
            }
            fprintf(stderr, "\n");

            Status =
                CxPlatDpRawInterfaceInitialize(
                    Xdp, Interface, ClientRecvContextLength);
            if (QUIC_FAILED(Status)) {
                QuicTraceEvent(
                    LibraryErrorStatus,
                    "[ lib] ERROR, %u, %s.",
                    Status,
                    "CxPlatDpRawInterfaceInitialize");
                CxPlatFree(Interface, IF_TAG);
                continue;
            }
            fprintf(stderr, "CxPlatListInsertTail\n");
            CxPlatListInsertTail(&Xdp->Interfaces, &Interface->Link);
        }
    }
    freeifaddrs(ifaddr);

    if (CxPlatListIsEmpty(&Xdp->Interfaces)) {
        fprintf(stderr, "Interfaces is empty!!!\n");
        QuicTraceEvent(
            LibraryError,
            "[ lib] ERROR, %s.",
            "no XDP capable interface");
        Status = QUIC_STATUS_NOT_FOUND;
        goto Error;
    } else {
        fprintf(stderr, "Interfaces is NOT empty!!!\n");
    }

    Xdp->Running = TRUE;
    CxPlatRefInitialize(&Xdp->RefCount);
    for (uint32_t i = 0; i < Xdp->WorkerCount; i++) {
        XDP_WORKER* Worker = &Xdp->Workers[i];
        if (Worker->Queues == NULL) {
            //
            // Because queues are assigned in a round-robin manner, subsequent
            // workers will not have a queue assigned. Stop the loop and update
            // worker count.
            //
            Xdp->WorkerCount = i;
            break;
        }

        Worker->Xdp = Xdp;
        Worker->ProcIndex = ProcessorList ? ProcessorList[i] : (uint16_t)i;
        Worker->Ec.Ready = TRUE;
        Worker->Ec.NextTimeUs = UINT64_MAX;
        Worker->Ec.Callback = CxPlatXdpExecute;
        Worker->Ec.Context = &Xdp->Workers[i];
        Worker->ShutdownSqe.CqeType = CXPLAT_CQE_TYPE_SOCKET_SHUTDOWN;
        CxPlatRefIncrement(&Xdp->RefCount);
        Worker->EventQ = CxPlatWorkerGetEventQ(Worker->ProcIndex);

        uint32_t QueueCount = 0;
        XDP_QUEUE* Queue = Worker->Queues;
        while (Queue) {
            if (!CxPlatSqeInitialize(
                    Worker->EventQ,
                    &Queue->RxIoSqe.Sqe,
                    &Queue->RxIoSqe)) {

                Status = QUIC_STATUS_INTERNAL_ERROR;
                goto Error;
            }
            Queue->RxIoSqe.CqeType = CXPLAT_CQE_TYPE_SOCKET_IO;
            // Queue->RxIoSqe.IoType = DATAPATH_IO_RECV;
            CxPlatSocketContextSetEvents(Queue, EPOLL_CTL_ADD, EPOLLIN);
            // TODOL other queues
            ++QueueCount;
            Queue = Queue->Next;
        }

        QuicTraceLogVerbose(
            XdpWorkerStart,
            "[ xdp][%p] XDP worker start, %u queues",
            Worker,
            QueueCount);
        UNREFERENCED_PARAMETER(QueueCount);

        CxPlatAddExecutionContext(&Worker->Ec, Worker->ProcIndex);
    }

Error:

    // TODO: error handling
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
        // TODO: clean xdp
        // XdpCloseApi(Xdp->XdpApi);
        CxPlatDataPathUninitializeComplete((CXPLAT_DATAPATH*)Xdp);
    // }
    //UNREFERENCED_PARAMETER(Xdp);
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
    for (uint32_t i = 0; i < Xdp->WorkerCount; i++) {
        Xdp->Workers[i].Ec.Ready = TRUE;
        // CxPlatWakeExecutionContext(&Xdp->Workers[i].Ec);
    }
    CxPlatDpRawRelease(Xdp);
}

_IRQL_requires_max_(PASSIVE_LEVEL)
void
CxPlatDpRawPlumbRulesOnSocket(
    _In_ CXPLAT_SOCKET* Socket,
    _In_ BOOLEAN IsCreated
    )
{
    UNREFERENCED_PARAMETER(Socket);
    UNREFERENCED_PARAMETER(IsCreated);
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

_IRQL_requires_max_(DISPATCH_LEVEL)
void
CxPlatDpRawRxFree(
    _In_opt_ const CXPLAT_RECV_DATA* PacketChain
    )
{
    UNREFERENCED_PARAMETER(PacketChain);
}

_IRQL_requires_max_(DISPATCH_LEVEL)
CXPLAT_SEND_DATA*
CxPlatDpRawTxAlloc(
    _In_ CXPLAT_SOCKET* Socket,
    _Inout_ CXPLAT_SEND_CONFIG* Config
    )
{
    // CXPLAT_DBG_ASSERT(Socket != NULL);
    // CXPLAT_DBG_ASSERT(Config->MaxPacketSize <= MAX_UDP_PAYLOAD_LENGTH);

    QUIC_ADDRESS_FAMILY Family = QuicAddrGetFamily(&Config->Route->RemoteAddress);
    XDP_QUEUE* Queue = Config->Route->Queue;
    //XDP_TX_PACKET* Packet = calloc(1, sizeof(XDP_TX_PACKET)); // TODO: use Queue->TxPool
    struct xsk_socket_info* xsk_info = Queue->xsk_info;
    uint32_t tx_idx;
    if (xsk_ring_prod__reserve(&xsk_info->tx, 1, &tx_idx) != 1) {
        return NULL;
    }
    struct xdp_desc *tx_desc = xsk_ring_prod__tx_desc(&xsk_info->tx, tx_idx);
    XDP_TX_PACKET* Packet = (XDP_TX_PACKET*)xsk_umem__get_data(xsk_info->umem->buffer, tx_desc->addr);

    if (Packet) {
        HEADER_BACKFILL HeaderBackfill = CxPlatDpRawCalculateHeaderBackFill(Family, Socket->UseTcp); // TODO - Cache in Route?
        CXPLAT_DBG_ASSERT(Config->MaxPacketSize <= sizeof(Packet->FrameBuffer) - HeaderBackfill.AllLayer);
        Packet->Queue = Queue;
        Packet->Buffer.Length = Config->MaxPacketSize;
        Packet->Buffer.Buffer = &Packet->FrameBuffer[HeaderBackfill.AllLayer];
        Packet->ECN = Config->ECN;
        Packet->tx_desc = tx_desc;
        Packet->tx_desc->addr += FIELD_OFFSET(XDP_TX_PACKET, FrameBuffer); // TODO: check. here?
    }
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
    XDP_TX_PACKET* Packet = (XDP_TX_PACKET*)SendData;
    // TODO: Queue is 0x0
    // XDP_WORKER* Worker = Packet->Queue->Worker;

    // struct xdp_desc *tx_desc;
    fprintf(stderr, "Send Length:%d\n", SendData->Buffer.Length);
    Packet->tx_desc->len = SendData->Buffer.Length;
    // Packet->tx_desc->len = 1024;
    xsk_ring_prod__submit(&Packet->Queue->xsk_info->tx, 1);
    if (sendto(xsk_socket__fd(Packet->Queue->xsk_info->xsk), NULL, 0, MSG_DONTWAIT, NULL, 0) < 0) {
        fprintf(stderr, "sendto failed\n");
    }

    // TODO: use queue for send
    // CxPlatLockAcquire(&Packet->Queue->TxLock);
    // CxPlatListInsertTail(&Packet->Queue->TxQueue, &Packet->Link);
    // CxPlatLockRelease(&Packet->Queue->TxLock);

    // Worker->Ec.Ready = TRUE;
    // CxPlatWakeExecutionContext(&Worker->Ec);
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
    return FALSE;
}

static void xsk_free_umem_frame(struct xsk_socket_info *xsk, uint64_t frame)
{
    assert(xsk->umem_frame_free < NUM_FRAMES);
    xsk->umem_frame_addr[xsk->umem_frame_free++] = frame;
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
    unsigned int rcvd, stock_frames, i;
    uint32_t idx_rx = 0, idx_fq = 0;
    unsigned int ret;

    rcvd = xsk_ring_cons__peek(&xsk->rx, RX_BATCH_SIZE, &idx_rx);
    if (!rcvd) {
        return;
    }

    // Stuff the ring with as much frames as possible
    stock_frames = xsk_prod_nb_free(&xsk->umem->fq,
                    xsk_umem_free_frames(xsk));

    if (stock_frames > 0) {

        ret = xsk_ring_prod__reserve(&xsk->umem->fq, stock_frames,
                         &idx_fq);

        // This should not happen, but just in case
        while (ret != stock_frames)
            ret = xsk_ring_prod__reserve(&xsk->umem->fq, rcvd,
                             &idx_fq);

        for (i = 0; i < stock_frames; i++)
            *xsk_ring_prod__fill_addr(&xsk->umem->fq, idx_fq++) =
                xsk_alloc_umem_frame(xsk);

        xsk_ring_prod__submit(&xsk->umem->fq, stock_frames);
    }

    // Process received packets
    CXPLAT_RECV_DATA* Buffers[RX_BATCH_SIZE];
    uint32_t PacketCount = 0;
    for (i = 0; i < rcvd; i++) {
        uint64_t addr = xsk_ring_cons__rx_desc(&xsk->rx, idx_rx)->addr;
        uint32_t len = xsk_ring_cons__rx_desc(&xsk->rx, idx_rx++)->len;

        uint8_t *FrameBuffer = xsk_umem__get_data(xsk->umem->buffer, addr);

        // TODO: XDP_RX_PACKET*
        CXPLAT_RECV_DATA* Packet = (CXPLAT_RECV_DATA*)(FrameBuffer - sizeof(XDP_TX_PACKET));
        Packet->Route = (CXPLAT_ROUTE*)calloc(1, sizeof(CXPLAT_ROUTE));

        // TODO xsk_free_umem_frame if parse error?
        CxPlatDpRawParseEthernet(
            (CXPLAT_DATAPATH*)Queue->Worker->Xdp,
            (CXPLAT_RECV_DATA*)Packet,
            FrameBuffer,
            (uint16_t)len);
        if (false) {
            xsk_free_umem_frame(xsk, addr);
        }

        //
        // The route has been filled in with the packet's src/dst IP and ETH addresses, so
        // mark it resolved. This allows stateless sends to be issued without performing
        // a route lookup.
        //
        Packet->Route->State = RouteResolved;

        if (Packet->Buffer) {
            Packet->Allocated = TRUE;
            Packet->Route->Queue = Queue;
            // Packet->Queue = Queue;
            Buffers[PacketCount++] = (CXPLAT_RECV_DATA*)Packet;
        } else {
            // CxPlatListPushEntry(&Queue->WorkerRxPool, (CXPLAT_SLIST_ENTRY*)Packet);
        }
    }

    xsk_ring_cons__release(&xsk->rx, rcvd);

    if (rcvd) {
        fprintf(stderr, "CxPlatDpRawRxEthernet recv:%d\n", rcvd);
        CxPlatDpRawRxEthernet(
            (CXPLAT_DATAPATH*)Queue->Worker->Xdp,
            Buffers,
            (uint16_t)rcvd);
    }
}

void
CxPlatDataPathProcessCqe(
    _In_ CXPLAT_CQE* Cqe
    )
{
    if (CxPlatCqeType(Cqe) == CXPLAT_CQE_TYPE_SOCKET_IO) {
        // TODO: use DATAPATH_IO_SQE to distinguish Tx/RX
        DATAPATH_SQE* Sqe = (DATAPATH_SQE*)CxPlatCqeUserData(Cqe);
        XDP_QUEUE* Queue;
        fprintf(stderr, "Recv!! Event:%d\n", Cqe->events & EPOLLIN);
        Queue = CXPLAT_CONTAINING_RECORD(Sqe, XDP_QUEUE, RxIoSqe);
        CxPlatXdpRx(Queue);
        QuicTraceLogVerbose(
            XdpQueueAsyncIoRxComplete,
            "[ xdp][%p] XDP async IO complete (RX)",
            Queue);
        Queue->RxQueued = FALSE;
    }
}
