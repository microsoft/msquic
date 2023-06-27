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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <sys/socket.h>
#include <linux/sockios.h>
#include <linux/ethtool.h>

QUIC_STATUS
CxPlatGetInterfaceRssQueueCount(
    _In_ uint32_t InterfaceIndex,
    _Out_ uint16_t* Count
    )
{
    UNREFERENCED_PARAMETER(InterfaceIndex);
    *Count = 1;
    return QUIC_STATUS_SUCCESS;

    int sockfd;
    struct ifreq ifr;

    sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockfd < 0) {
        perror("Cannot open socket");
        exit(EXIT_FAILURE);
    }

    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, "eth0", IFNAMSIZ - 1);

    int indir_size = 128;
    size_t rss_config_size = sizeof(struct ethtool_rxfh) + indir_size * sizeof(__u32);
    struct ethtool_rxfh *rss_config = malloc(rss_config_size);

    memset(rss_config, 0, rss_config_size);
    rss_config->cmd = ETHTOOL_GRSSH;
    rss_config->rss_context = 0;
    rss_config->indir_size = indir_size;

    ifr.ifr_data = (caddr_t)rss_config;

    if (ioctl(sockfd, SIOCETHTOOL, &ifr) < 0) {
        perror("Cannot get RSS configuration");
        close(sockfd);
        free(rss_config);
        exit(EXIT_FAILURE);
    }

    free(rss_config);
    close(sockfd);
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

QUIC_STATUS
xdp_link_detach(int ifindex, __u32 xdp_flags, __u32 expected_prog_id)
{
	__u32 curr_prog_id;
	int err;

	err = bpf_get_link_xdp_id(ifindex, &curr_prog_id, xdp_flags);
	if (err) {
		fprintf(stderr, "ERR: get link xdp id failed (err=%d): %s\n",
			-err, strerror(-err));
		return QUIC_STATUS_INTERNAL_ERROR;
	}

	if (!curr_prog_id) {
		// if (verbose)
		// 	printf("INFO: %s() no curr XDP prog on ifindex:%d\n",
		// 	       __func__, ifindex);
		return QUIC_STATUS_SUCCESS;
	}

	if (expected_prog_id && curr_prog_id != expected_prog_id) {
		fprintf(stderr, "ERR: %s() "
			"expected prog ID(%d) no match(%d), not removing\n",
			__func__, expected_prog_id, curr_prog_id);
		return QUIC_STATUS_INTERNAL_ERROR;
	}

	if ((err = bpf_set_link_xdp_fd(ifindex, -1, xdp_flags)) < 0) {
		fprintf(stderr, "ERR: %s() link set xdp failed (err=%d): %s\n",
			__func__, err, strerror(-err));
		return QUIC_STATUS_INTERNAL_ERROR;
	}

	// if (verbose)
	// 	printf("INFO: %s() removed XDP prog ID:%d on ifindex:%d\n",
	// 	       __func__, curr_prog_id, ifindex);

	return QUIC_STATUS_SUCCESS;
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

        epoll_ctl(*Queue->Worker->EventQ, EPOLL_CTL_DEL, xsk_socket__fd(Queue->xsk_info->xsk), NULL);
        xsk_socket__delete(Queue->xsk_info->xsk);
        xsk_umem__delete(Queue->xsk_info->umem->umem);
        free(Queue->xsk_info->umem->buffer);
        free(Queue->xsk_info->umem);
        free(Queue->xsk_info);
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

    xdp_link_detach(Interface->IfIndex, 0, 0);
    bpf_object__close(Interface->BpfObj);

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
        .fill_size = PROD_NUM_DESCS,
        .comp_size = CONS_NUM_DESCS,
        .frame_size = FRAME_SIZE, // frame_size is really sensitive to become EINVAL
        .frame_headroom = TxHeadRoom,
        .flags = 0
    };

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
    int offload_ifindex = 0; // ?l
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
    if (xsk->umem_frame_free == 0) {
        return INVALID_UMEM_FRAME;
    }

    frame = xsk->umem_frame_addr[--xsk->umem_frame_free];
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
    const uint32_t RxHeadroom = sizeof(XDP_RX_PACKET) + ALIGN_UP(ClientRecvContextLength, uint32_t);
    const uint32_t TxHeadroom = FIELD_OFFSET(XDP_TX_PACKET, FrameBuffer);
    // WARN: variable frame size cause unexpected behavior
    // TODO: 2K mode
    const uint32_t PacketSize = FRAME_SIZE;
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
    xsk_cfg->bind_flags &= ~XDP_ZEROCOPY;
    xsk_cfg->bind_flags |= XDP_COPY;

    Status = load_bpf_and_xdp_attach("./datapath_raw_xdp_kern.o", "xdp_prog", Interface->IfIndex, &Interface->BpfObj);
    struct bpf_map *map = bpf_object__find_map_by_name(Interface->BpfObj, "xsks_map");
    int xsk_map_fd = bpf_map__fd(map);
    if (xsk_map_fd < 0) {
        fprintf(stderr, "ERROR: no xsks map found: %s\n",
            strerror(xsk_map_fd));
        exit(EXIT_FAILURE);
    }

    // TODO: implement
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

    for (uint8_t queue_id = 0; queue_id < Interface->QueueCount; queue_id++) {
        XDP_QUEUE* Queue = &Interface->Queues[queue_id];

        QuicTraceLogVerbose(
            QueueInit,
            "[ xdp][%p] Setting up Queue on Interface:%p",
            Queue,
            Interface);

        Queue->Interface = Interface;
        // InitializeSListHead(&Queue->RxPool);
        // InitializeSListHead(&Queue->TxPool);
        // CxPlatPoolInitialize(TRUE, sizeof(struct xdp_desc*), QUIC_POOL_DATA, &Queue->TxPool);
        // CxPlatPoolInitialize(TRUE, 16, QUIC_POOL_DATA, &Queue->TxPool);
        CxPlatListInitializeHead(&Queue->TxPool);
        // CxPlatLockInitialize(&Queue->TxLock);
        // CxPlatListInitializeHead(&Queue->TxQueue);
        // CxPlatListInitializeHead(&Queue->WorkerTxQueue);
        // CxPlatDatapathSqeInitialize(&Queue->RxIoSqe.DatapathSqe, CXPLAT_CQE_TYPE_SOCKET_IO); // TODO: for epoll based
        // Queue->RxIoSqe.IoType = DATAPATH_IO_RECV;
        // CxPlatDatapathSqeInitialize(&Queue->TxIoSqe.DatapathSqe, CXPLAT_CQE_TYPE_SOCKET_IO);
        // Queue->TxIoSqe.IoType = DATAPATH_IO_SEND;


        void *packet_buffer; // TODO: free?
        uint64_t packet_buffer_size = NUM_FRAMES * PacketSize;
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
        umem = configure_xsk_umem(packet_buffer, packet_buffer_size, TxHeadroom);
        if (umem == NULL) {
            fprintf(stderr, "ERROR: Can't create umem \"%s\"\n",
                strerror(errno));
            exit(EXIT_FAILURE);
        }
        umem->RxHeadRoom = RxHeadroom;
        umem->TxHeadRoom = TxHeadroom;

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

        ret = xsk_socket__update_xskmap(xsk_info->xsk, xsk_map_fd);
        if (ret) {
            return QUIC_STATUS_INTERNAL_ERROR;
        }

        for (int i = 0; i < NUM_FRAMES; i++) {
            xsk_info->umem_frame_addr[i] = i * PacketSize;
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
        for (uint32_t i = 0; i < XSK_RING_PROD__DEFAULT_NUM_DESCS; i ++) {
            *xsk_ring_prod__fill_addr(&xsk_info->umem->fq, firstIdx++) =
                xsk_alloc_umem_frame(xsk_info) + RxHeadroom;
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

    QuicTraceLogVerbose(
        InterfaceInit,
        "[ xdp][%p] Interface init done",
        Interface);

Error:
    if (QUIC_FAILED(Status)) {
        CxPlatDpRawInterfaceUninitialize(Interface);
    }

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
                QuicTraceEvent(
                    AllocFailure,
                    "Allocation of '%s' failed. (%llu bytes)",
                    "XDP interface",
                    sizeof(*Interface));
                Status = QUIC_STATUS_OUT_OF_MEMORY;
                goto Error;
            }
            // TODO: remove
            // if (memcmp(ifa->ifa_name, "duo", 3) != 0) {
            //     continue;
            // }
            CxPlatZeroMemory(Interface, sizeof(*Interface));

            Interface->IfIndex = if_nametoindex(ifa->ifa_name);
            struct sockaddr_ll *sall = (struct sockaddr_ll*)ifa->ifa_addr;
            memcpy(Interface->PhysicalAddress, sall->sll_addr, sizeof(Interface->PhysicalAddress));

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

        // if (!CxPlatSqeInitialize(
        //         Worker->EventQ,
        //         &Worker->ShutdownSqe.Sqe,
        //         &Worker->ShutdownSqe)) {
        //     Status = QUIC_STATUS_INTERNAL_ERROR;
        //     goto Error;
        // }

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
            CxPlatSocketContextSetEvents(Queue, EPOLL_CTL_ADD, EPOLLIN);

            // if (!CxPlatSqeInitialize(
            //     Worker->EventQ,
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

// static uint64_t xsk_umem_free_frames(struct xsk_socket_info *xsk);

_IRQL_requires_max_(PASSIVE_LEVEL)
void
CxPlatDpRawPlumbRulesOnSocket(
    _In_ CXPLAT_SOCKET* Socket,
    _In_ BOOLEAN IsCreated
    )
{
    CXPLAT_LIST_ENTRY* Entry = Socket->Datapath->Interfaces.Flink;
    for (; Entry != &Socket->Datapath->Interfaces; Entry = Entry->Flink) {
        CXPLAT_INTERFACE* Interface = CXPLAT_CONTAINING_RECORD(Entry, CXPLAT_INTERFACE, Link);

        char ifName[16] = {0};
        if_indextoname(Interface->IfIndex, ifName);
        struct bpf_map *port_map = bpf_object__find_map_by_name(Interface->BpfObj, "port_map");
        if (!port_map) {
            fprintf(stderr, "Failed to find BPF port_map\n");
        }

        int port = Socket->LocalAddress.Ipv4.sin_port;
        fprintf(stderr, "Setting to %s, port:%d\n", ifName, port);
        if (IsCreated) {
            BOOLEAN exist = true;
            if (bpf_map_update_elem(bpf_map__fd(port_map), &port, &exist, BPF_ANY)) {
                fprintf(stderr, "Failed to update BPF map on ifidx:%d\n", Interface->IfIndex);
            }
        } else {
            // XDP_INTERFACE* XInterface = (XDP_INTERFACE*)Interface;
            // for (uint32_t i = 0; XInterface->Queues != NULL && i < XInterface->QueueCount; i++) {
            //     XDP_QUEUE *Queue = &XInterface->Queues[i];
            //     uint32_t rx_idx = 0;
            //     int rcvd = xsk_ring_cons__peek(&Queue->xsk_info->rx, RX_BATCH_SIZE, &rx_idx);
            //     if (rcvd) {
            //         fprintf(stderr, "%s rcvd:%d rx_idx:%d\n", ifName, rcvd, rx_idx);
            //     }
            //     UNREFERENCED_PARAMETER(rcvd);
            //     uint32_t stock_frames = xsk_prod_nb_free(&Queue->xsk_info->umem->fq,
            //                                             xsk_umem_free_frames(Queue->xsk_info));
            //     if (stock_frames > 0) {
            //         uint32_t idx_fq = 0;
            //         uint32_t ret = xsk_ring_prod__reserve(&Queue->xsk_info->umem->fq, stock_frames,
            //                         &idx_fq);
            //         // This should not happen, but just in case
            //         while (ret != stock_frames)
            //             ret = xsk_ring_prod__reserve(&Queue->xsk_info->umem->fq, rcvd,
            //                             &idx_fq);

            //         for (uint32_t i = 0; i < stock_frames; i++) {
            //             *xsk_ring_prod__fill_addr(&Queue->xsk_info->umem->fq, idx_fq++) =
            //                 xsk_alloc_umem_frame(Queue->xsk_info) + Queue->xsk_info->umem->RxHeadRoom;
            //         }

            //         xsk_ring_prod__submit(&Queue->xsk_info->umem->fq, stock_frames);
            //     }
            // }



            if (bpf_map_delete_elem(bpf_map__fd(port_map), &port)) {
                fprintf(stderr, "Failed to delete port %d from BPF map on ifidx:%d\n", port, Interface->IfIndex);
            }
        }

        // NOTE: experimental
        struct bpf_map *ifname_map = bpf_object__find_map_by_name(Interface->BpfObj, "ifname_map");
        if (!ifname_map) {
            fprintf(stderr, "Failed to find BPF ifacename_map\n");
        }

        // TODO: need to care until all packets received?
        int key = 0;
        if (IsCreated) {
            if (bpf_map_update_elem(bpf_map__fd(ifname_map), &key, ifName, BPF_ANY)) {
                fprintf(stderr, "Failed to update BPF map\n");
            }
        } else {
            if (bpf_map_delete_elem(bpf_map__fd(ifname_map), &key)) {
                fprintf(stderr, "Failed to delete name %s from BPF map on ifidx:%d\n", ifName, Interface->IfIndex);
            }
        }

    }
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


static void xsk_free_umem_frame(struct xsk_socket_info *xsk, uint64_t frame)
{
    fprintf(stderr, "[%p] xsk_free_umem_frame:\txsk->umem_frame_free:%d = %ld\n", xsk, xsk->umem_frame_free, frame);
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
    // SLIST_ENTRY* Head = NULL;
    // SLIST_ENTRY** Tail = &Head;
    // SLIST_HEADER* Pool = NULL;
    // uint32_t idx_fq = 0;
    struct xsk_socket_info *xsk_info = ((XDP_RX_PACKET*)PacketChain)->Queue->xsk_info;

    while (PacketChain) {
        const XDP_RX_PACKET* Packet = (XDP_RX_PACKET*)PacketChain;
        PacketChain = PacketChain->Next;
        UNREFERENCED_PARAMETER(Packet);
        fprintf(stderr, "Packet[%p] Queue[%p] addr:%ld frame_free:%d CxPlatDpRawXdpRxFree\n", Packet, Packet->Queue, Packet->addr ,xsk_info->umem_frame_free);
        xsk_free_umem_frame(Packet->Queue->xsk_info, Packet->addr);
        // xsk_free_umem_frame(xsk_info, Packet->addr);
        // *xsk_ring_prod__fill_addr(&xsk_info->umem->fq, idx_fq++) =
        //     xsk_alloc_umem_frame(xsk_info) + xsk_info->umem->RxHeadRoom;

        // if (Pool != &Packet->Queue->RxPool) {
        //     if (Count > 0) {
        //         InterlockedPushListSList(
        //             Pool, Head, CONTAINING_RECORD(Tail, SLIST_ENTRY, Next), Count);
        //         Head = NULL;
        //         Tail = &Head;
        //         Count = 0;
        //     }

        //     Pool = &Packet->Queue->RxPool;
        // }

        // *Tail = (SLIST_ENTRY*)Packet;
        // Tail = &((SLIST_ENTRY*)Packet)->Next;
        Count++;
    }
    fprintf(stderr, "CxPlatDpRawXdpRxFree Count:%d\n", Count);
    if (Count > 0) {
        // uint32_t idx_fq = 0;
        // xsk_ring_prod__reserve(&xsk_info->umem->fq, Count, &idx_fq);
        // // xsk_free_umem_frame(xsk_info, Packet->addr);
        // for (uint32_t i = 0; i < Count; i++) {
        //     // xsk_free_umem_frame(xsk_info, Packet->addr);
        //     *xsk_ring_prod__fill_addr(&xsk_info->umem->fq, idx_fq++) =
        //         xsk_alloc_umem_frame(xsk_info) + xsk_info->umem->RxHeadRoom;
        // }
        // xsk_ring_prod__submit(&xsk_info->umem->fq, Count);

        // InterlockedPushListSList(Pool, Head, CONTAINING_RECORD(Tail, SLIST_ENTRY, Next), Count);
    }
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
    struct xsk_socket_info* xsk_info = Queue->xsk_info;
    // uint64_t base_addr =INVALID_UMEM_FRAME;
    // do {
    //     base_addr = xsk_alloc_umem_frame(xsk_info);
    // } while (base_addr == INVALID_UMEM_FRAME);
    // uint64_t base_addr = xsk_alloc_umem_frame(xsk_info);
    // if (base_addr == INVALID_UMEM_FRAME) {
    //     return NULL;
    // }
    uint64_t base_addr = xsk_alloc_umem_frame(xsk_info);

    uint32_t tx_idx = 0;
    if (xsk_ring_prod__reserve(&xsk_info->tx, 1, &tx_idx) != 1) {
        xsk_free_umem_frame(xsk_info, base_addr);
        return NULL;
    }
    struct xdp_desc *tx_desc = xsk_ring_prod__tx_desc(&xsk_info->tx, tx_idx);
    CXPLAT_FRE_ASSERT(tx_desc != NULL);
    // XDP_TX_PACKET* Packet = (XDP_TX_PACKET*)xsk_umem__get_data(xsk_info->umem->buffer, (tx_idx * FRAME_SIZE));
    XDP_TX_PACKET* Packet = (XDP_TX_PACKET*)xsk_umem__get_data(xsk_info->umem->buffer, base_addr);
    fprintf(stderr, "tx_idx:%d, umem_frame_addr:%d, base_addr:%ld, Packet:%p\n", tx_idx, xsk_info->umem_frame_free - 1, base_addr, Packet);
    // tx_desc->addr = (tx_idx * FRAME_SIZE) + xsk_info->umem->TxHeadRoom;
    tx_desc->addr = base_addr + xsk_info->umem->TxHeadRoom;
    tx_desc->len = FRAME_SIZE - xsk_info->umem->TxHeadRoom;

    // XDP_TX_PACKET* Packet = CXPLAT_CONTAINING_RECORD(CxPlatListRemoveHead(&Queue->TxPool), XDP_TX_PACKET, Link);
    // struct xdp_desc *tx_desc = Packet->tx_desc;
    // fprintf(stderr, ":::: Packet:%p, tx_desc:%p, tx_desc->addr:%lld, tx_desc->len:%d TxAlloc\n", Packet, tx_desc, tx_desc->addr, tx_desc->len);

    if (Packet) {
        HEADER_BACKFILL HeaderBackfill = CxPlatDpRawCalculateHeaderBackFill(Family, Socket->UseTcp); // TODO - Cache in Route?
        CXPLAT_DBG_ASSERT(Config->MaxPacketSize <= sizeof(Packet->FrameBuffer) - HeaderBackfill.AllLayer);
        Packet->Queue = Queue;
        Packet->Buffer.Length = Config->MaxPacketSize;
        Packet->Buffer.Buffer = &Packet->FrameBuffer[HeaderBackfill.AllLayer];
        fprintf(stderr, "===================== BUFFER[%p] Packet[%p] tx_idx[%d] CxPlatDpRawTxAlloc\n", Packet->Buffer.Buffer, Packet, tx_idx);
        Packet->ECN = Config->ECN;
        Packet->tx_desc = tx_desc;
    }
    return (CXPLAT_SEND_DATA*)Packet;
}

_IRQL_requires_max_(DISPATCH_LEVEL)
void
CxPlatDpRawTxFree(
    _In_ CXPLAT_SEND_DATA* SendData
    )
{
    fprintf(stderr, "DEADBEEF TxFree\n");
    UNREFERENCED_PARAMETER(SendData);
    // XDP_TX_PACKET* Packet = (XDP_TX_PACKET*)SendData;
    // CxPlatLockAcquire(&Packet->Queue->TxLock);
    // CxPlatListInsertTail(&Packet->Queue->TxPool, &Packet->Link);
    // CxPlatLockRelease(&Packet->Queue->TxLock);
}

_IRQL_requires_max_(DISPATCH_LEVEL)
void
CxPlatDpRawTxEnqueue(
    _In_ CXPLAT_SEND_DATA* SendData
    )
{
    // TODO: use WorkerTxQueue to submit at once?
    XDP_TX_PACKET* Packet = (XDP_TX_PACKET*)SendData;
    XDP_WORKER* Worker = Packet->Queue->Worker;

    // struct xdp_desc *tx_desc;
    fprintf(stderr, "Send Length[%d]\n", SendData->Buffer.Length);
    Packet->tx_desc->len = SendData->Buffer.Length;
    // Packet->tx_desc->len = 1024;
    xsk_ring_prod__submit(&Packet->Queue->xsk_info->tx, 1);
    if (sendto(xsk_socket__fd(Packet->Queue->xsk_info->xsk), NULL, 0, MSG_DONTWAIT, NULL, 0) < 0) {
        int er = errno;
        QuicTraceLogVerbose(
            FailSendTo,
            "[ xdp][tx  ] Faild sendto. errno:%d, Umem addr:%lld", er, Packet->tx_desc->addr);
    } else {
        QuicTraceLogVerbose(
            DoneSendTo,
            "[ xdp][TX  ] Done sendto. len:%d, Umem addr:%lld", SendData->Buffer.Length, Packet->tx_desc->addr);
    }

    unsigned int completed;
    uint32_t idx_cq;

    /* Collect/free completed TX buffers */
    completed = xsk_ring_cons__peek(&Packet->Queue->xsk_info->umem->cq,
                    XSK_RING_CONS__DEFAULT_NUM_DESCS,
                    &idx_cq);

    if (completed > 0) {
        for (uint32_t i = 0; i < completed; i++) {
            xsk_free_umem_frame(Packet->Queue->xsk_info,
                                *xsk_ring_cons__comp_addr(&Packet->Queue->xsk_info->umem->cq,
                                                          idx_cq++));
        }

        xsk_ring_cons__release(&Packet->Queue->xsk_info->umem->cq, completed);
        QuicTraceLogVerbose(
            ReleaseCons,
            "[ xdp][cq  ] Release %d from completion queue", completed);
    }

    // TODO: use queue for send
    // CxPlatLockAcquire(&Packet->Queue->TxLock);
    // CxPlatListInsertTail(&Packet->Queue->TxPool, &Packet->Link);
    // CxPlatLockRelease(&Packet->Queue->TxLock);

    Worker->Ec.Ready = TRUE;
    CxPlatWakeExecutionContext(&Worker->Ec);
}

_IRQL_requires_max_(PASSIVE_LEVEL)
BOOLEAN
CxPlatXdpExecute(
    _Inout_ void* Context,
    _Inout_ CXPLAT_EXECUTION_STATE* State
    )
{
    // XDP_WORKER* Worker = (XDP_WORKER*)Context;
    // const XDP_DATAPATH* Xdp = Worker->Xdp;

    // if (!Xdp->Running) {
    //     QuicTraceLogVerbose(
    //         XdpWorkerShutdown,
    //         "[ xdp][%p] XDP worker shutdown",
    //         Worker);
    //     CxPlatEventQEnqueue(Worker->EventQ, &Worker->ShutdownSqe.Sqe, &Worker->ShutdownSqe);
    //     return FALSE;
    // }
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
    fprintf(stderr, "CxPlatXdpRx\n");
    struct xsk_socket_info *xsk = Queue->xsk_info;
    unsigned int rcvd, i;
    unsigned int stock_frames;
    uint32_t idx_rx = 0, idx_fq = 0;
    unsigned int ret;

    rcvd = xsk_ring_cons__peek(&xsk->rx, RX_BATCH_SIZE, &idx_rx);
    if (!rcvd) {
        QuicTraceLogVerbose(
            RxConsPeekFail,
            "[ xdp][rx  ] Failed to peek from Rx queue");
        return;
    } else {
        QuicTraceLogVerbose(
            RxConsPeekSucceed,
            "[ xdp][rx  ] Succeed peek %d from Rx queue", rcvd);
        fprintf(stderr, "CxPlatXdpRx rcvd:%d\n", rcvd);
    }

    // Stuff the ring with as much frames as possible
    stock_frames = xsk_prod_nb_free(&xsk->umem->fq,
                    xsk_umem_free_frames(xsk));

    if (stock_frames > 0) {
        fprintf(stderr, "CxPlatXdpRx stock_frames %d\n", stock_frames);
        ret = xsk_ring_prod__reserve(&xsk->umem->fq, stock_frames,
                         &idx_fq);

        // This should not happen, but just in case
        while (ret != stock_frames)
            ret = xsk_ring_prod__reserve(&xsk->umem->fq, rcvd,
                             &idx_fq);

        for (i = 0; i < stock_frames; i++) {
            *xsk_ring_prod__fill_addr(&xsk->umem->fq, idx_fq++) =
                xsk_alloc_umem_frame(xsk) + xsk->umem->RxHeadRoom;
        }

        xsk_ring_prod__submit(&xsk->umem->fq, stock_frames);
    }

    // Process received packets
    CXPLAT_RECV_DATA* Buffers[RX_BATCH_SIZE];
    uint32_t PacketCount = 0;
    for (i = 0; i < rcvd; i++) {
        // const struct xdp_desc *rx_desc = xsk_ring_cons__rx_desc(&xsk->rx, idx_rx);
        uint64_t addr = xsk_ring_cons__rx_desc(&xsk->rx, idx_rx)->addr;
        uint32_t len = xsk_ring_cons__rx_desc(&xsk->rx, idx_rx++)->len;

        // uint8_t *FrameBuffer = xsk_umem__get_data(xsk->umem->buffer, rx_desc->addr);
        uint8_t *FrameBuffer = xsk_umem__get_data(xsk->umem->buffer, addr);
        XDP_RX_PACKET* Packet = (XDP_RX_PACKET*)(FrameBuffer - xsk->umem->RxHeadRoom);
        fprintf(stderr, "==================> CxPlatXdpRx idx_rx:%d, Packet:%p, addr:%ld, len:%d\n", idx_rx, Packet, addr, len);
        CxPlatZeroMemory(Packet, xsk->umem->RxHeadRoom);

        Packet->Route = &Packet->RouteStorage;
        Packet->RouteStorage.Queue = Queue;
        Packet->PartitionIndex = Queue->Worker->ProcIndex;

        // TODO xsk_free_umem_frame if parse error?
        CxPlatDpRawParseEthernet(
            (CXPLAT_DATAPATH*)Queue->Worker->Xdp,
            (CXPLAT_RECV_DATA*)Packet,
            FrameBuffer,
            (uint16_t)len);
        if (false) {
            // free if CxPlatDpRawParseEthernet failed
            // xsk_free_umem_frame(xsk, rx_desc->addr);
            xsk_free_umem_frame(xsk, addr);
        }
        QuicTraceEvent(
            RxConstructPacket,
            "[ xdp][rx  ] Constructing Packet from Rx, local=%!ADDR!, remote=%!ADDR!",
            CASTED_CLOG_BYTEARRAY(sizeof(Packet->RouteStorage.LocalAddress), &Packet->RouteStorage.LocalAddress),
            CASTED_CLOG_BYTEARRAY(sizeof(Packet->RouteStorage.RemoteAddress), &Packet->RouteStorage.RemoteAddress));
        Packet->addr = addr;

        //
        // The route has been filled in with the packet's src/dst IP and ETH addresses, so
        // mark it resolved. This allows stateless sends to be issued without performing
        // a route lookup.
        //
        Packet->Route->State = RouteResolved;

        if (Packet->Buffer) {
            Packet->Allocated = TRUE;
            Packet->Queue = Queue;
            Buffers[PacketCount++] = (CXPLAT_RECV_DATA*)Packet;
        } else {
            // CxPlatListPushEntry(&Queue->WorkerRxPool, (CXPLAT_SLIST_ENTRY*)Packet);
        }
    }

    if (rcvd > 0) {
        // HERE? releasing buffer here might be danger?
        QuicTraceLogVerbose(
            XdpRxRelease,
            "[ xdp][%p] Release %d from Rx queue (TODO:Check necesity here)",
            Queue, rcvd);
        xsk_ring_cons__release(&xsk->rx, rcvd);
    }

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
    switch (CxPlatCqeType(Cqe)) {
    case CXPLAT_CQE_TYPE_SOCKET_SHUTDOWN: {
        // XDP_WORKER* Worker =
        //     CXPLAT_CONTAINING_RECORD(CxPlatCqeUserData(Cqe), XDP_WORKER, ShutdownSqe);
        // QuicTraceLogVerbose(
        //     XdpWorkerShutdownComplete,
        //     "[ xdp][%p] XDP worker shutdown complete",
        //     Worker);
        // CxPlatDpRawRelease((XDP_DATAPATH*)Worker->Xdp);

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
        // fprintf(stderr, "[%p] Recv!! Event:%d\n", Queue, Cqe->events & EPOLLIN);
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
