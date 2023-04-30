/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.

Abstract:

    QUIC datapath Abstraction Layer.

Environment:

    Linux

--*/

#include "platform_internal.h"
#include <linux/filter.h>
#include <linux/in6.h>
#include <netinet/udp.h>

#ifdef QUIC_CLOG
#include "datapath_epoll.c.clog.h"
#endif

CXPLAT_STATIC_ASSERT((SIZEOF_STRUCT_MEMBER(QUIC_BUFFER, Length) <= sizeof(size_t)), "(sizeof(QUIC_BUFFER.Length) == sizeof(size_t) must be TRUE.");
CXPLAT_STATIC_ASSERT((SIZEOF_STRUCT_MEMBER(QUIC_BUFFER, Buffer) == sizeof(void*)), "(sizeof(QUIC_BUFFER.Buffer) == sizeof(void*) must be TRUE.");

//
// The maximum single buffer size for single packet/datagram IO payloads.
//
#define CXPLAT_SMALL_IO_BUFFER_SIZE         MAX_UDP_PAYLOAD_LENGTH

//
// The maximum single buffer size for coalesced IO payloads.
//
#define CXPLAT_LARGE_IO_BUFFER_SIZE         0xFFFF

//
// The maximum batch size of IOs in that can use a single coalesced IO buffer.
// This is calculated base on the number of the smallest possible single
// packet/datagram payloads (i.e. IPv6) that can fit in the large buffer.
//
const uint16_t CXPLAT_MAX_IO_BATCH_SIZE =
    (CXPLAT_LARGE_IO_BUFFER_SIZE / (CXPLAT_MAX_MTU - CXPLAT_MIN_IPV6_HEADER_SIZE - CXPLAT_UDP_HEADER_SIZE));

typedef struct CXPLAT_RECV_SUBBLOCK {

    struct CXPLAT_RECV_BLOCK* RecvBlock;
    CXPLAT_RECV_DATA RecvData;
    // CXPLAT_RECV_PACKET RecvPacket;

} CXPLAT_RECV_SUBBLOCK;

//
// A receive block to receive a UDP packet over the sockets.
//
typedef struct CXPLAT_RECV_BLOCK {
    //
    // The pool owning this recv block.
    //
    CXPLAT_POOL* OwningPool;

    //
    // Represents the network route.
    //
    CXPLAT_ROUTE Route;

    //
    // Ref count of receive data/packets that are using this block.
    //
    long RefCount;

    //
    // An array of sub-blocks to represent the datagram and metadata returned to
    // the app.
    //
    //CXPLAT_RECV_SUBBLOCK SubBlocks[0];

    //
    // Buffer that actually stores the UDP payload.
    //
    //uint8_t Buffer[]; // CXPLAT_SMALL_IO_BUFFER_SIZE or CXPLAT_LARGE_IO_BUFFER_SIZE

} CXPLAT_RECV_BLOCK;

//
// Send context.
//

typedef struct CXPLAT_SEND_DATA {
    //
    // The socket context owning this send.
    //
    struct CXPLAT_SOCKET_CONTEXT* SocketContext;

    //
    // Entry in the pending send list.
    //
    CXPLAT_LIST_ENTRY TxEntry;

    //
    // The local address to bind to.
    //
    QUIC_ADDR LocalAddress;

    //
    // The remote address to send to.
    //
    QUIC_ADDR RemoteAddress;

    //
    // The current QUIC_BUFFER returned to the client for segmented sends.
    //
    QUIC_BUFFER ClientBuffer;

    // eth + iph(ipv6h) + udph (tcph)
    uint16_t HeaderOffset;

    struct xdp_desc *tx_desc;

    //
    // The total buffer size for iovecs.
    //
    uint32_t TotalSize;

    //
    // The send segmentation size the app asked for.
    //
    uint16_t SegmentSize;

    //
    // Total number of packet buffers allocated (and iovecs used if !GSO).
    //
    uint16_t BufferCount;

    //
    // The number of iovecs that have been sent out. Only relavent if not doing
    // GSO.
    //
    uint16_t AlreadySentCount;

    //
    // Length of the calculated ControlBuffer. Value is zero until the data is
    // computed.
    //
    uint8_t ControlBufferLength;

    //
    // The type of ECN markings needed for send.
    //
    uint8_t ECN; // CXPLAT_ECN_TYPE

    //
    // Set of flags set to configure the send behavior.
    //
    uint8_t Flags; // CXPLAT_SEND_FLAGS

    //
    // Indicates that send is on a connected socket.
    //
    uint8_t OnConnectedSocket : 1;

    //
    // Indicates that segmentation is supported for the send data.
    //
    uint8_t SegmentationSupported : 1;

    //
    // Space for ancillary control data.
    //
    alignas(8)
    char ControlBuffer[
        CMSG_SPACE(sizeof(int)) +               // IP_TOS || IPV6_TCLASS
        CMSG_SPACE(sizeof(struct in6_pktinfo))  // IP_PKTINFO || IPV6_PKTINFO
    #ifdef UDP_SEGMENT
        + CMSG_SPACE(sizeof(uint16_t))          // UDP_SEGMENT
    #endif
        ];
    CXPLAT_STATIC_ASSERT(
        CMSG_SPACE(sizeof(struct in6_pktinfo)) >= CMSG_SPACE(sizeof(struct in_pktinfo)),
        "sizeof(struct in6_pktinfo) >= sizeof(struct in_pktinfo) failed");

    //
    // Space for all the packet buffers.
    //

    // TODO: should be from umem?
    //uint8_t Buffer[CXPLAT_LARGE_IO_BUFFER_SIZE];
    uint8_t *Buffer;

    //
    // IO vectors used for sends on the socket.
    //
    struct iovec Iovs[1]; // variable length, depends on if GSO is being used
                          //   if GSO is used, only 1 is needed
                          //   if GSO is not used, then N are needed

} CXPLAT_SEND_DATA;

typedef struct CXPLAT_RECV_MSG_CONTROL_BUFFER {
    char Data[CMSG_SPACE(sizeof(struct in6_pktinfo)) +
              2 * CMSG_SPACE(sizeof(int))];
} CXPLAT_RECV_MSG_CONTROL_BUFFER;

typedef struct CXPLAT_DATAPATH_PROC CXPLAT_DATAPATH_PROC;

//
// Socket context.
//
typedef struct QUIC_CACHEALIGN CXPLAT_SOCKET_CONTEXT {

    //
    // The datapath binding this socket context belongs to.
    //
    CXPLAT_SOCKET* Binding;

    //
    // The datapath proc context this socket belongs to.
    //
    CXPLAT_DATAPATH_PROC* DatapathProc;

    //
    // The socket FD used by this socket context.
    //
    int SocketFd;

    //
    // The submission queue event for shutdown.
    //
    DATAPATH_SQE ShutdownSqe;

    //
    // The submission queue event for IO.
    //
    DATAPATH_SQE IoSqe;

    //
    // The submission queue event for flushing the send queue.
    //
    DATAPATH_SQE FlushTxSqe;

    //
    // The head of list containg all pending sends on this socket.
    //
    CXPLAT_LIST_ENTRY TxQueue;

    //
    // Lock around the PendingSendData list.
    //
    CXPLAT_LOCK TxQueueLock;

    //
    // Rundown for synchronizing clean up with upcalls.
    //
    CXPLAT_RUNDOWN_REF UpcallRundown;

    //
    // Inidicates the SQEs have been initialized.
    //
    BOOLEAN SqeInitialized : 1;

    //
    // Inidicates if the socket has started IO processing.
    //
    BOOLEAN IoStarted : 1;

#if DEBUG
    uint8_t Uninitialized : 1;
    uint8_t Freed : 1;
#endif

    int ActorIdx; // TODO: remove
    // struct xsk_socket_info* xsk_info;
    int dummySock; // to reserve port
} CXPLAT_SOCKET_CONTEXT;

//
// Datapath binding.
//
typedef struct CXPLAT_SOCKET {

    //
    // A pointer to datapath object.
    //
    CXPLAT_DATAPATH* Datapath;

    //
    // The client context for this binding.
    //
    void *ClientContext;

    //
    // The local address for the binding.
    //
    QUIC_ADDR LocalAddress;

    //
    //  The remote address for the binding.
    //
    QUIC_ADDR RemoteAddress;

    //
    // Synchronization mechanism for cleanup.
    //
    CXPLAT_REF_COUNT RefCount;

    //
    // The MTU for this binding.
    //
    uint16_t Mtu;

    //
    // Indicates the binding connected to a remote IP address.
    //
    BOOLEAN Connected : 1;

    //
    // Flag indicates the socket has a default remote destination.
    //
    BOOLEAN HasFixedRemoteAddress : 1;

    //
    // Flag indicates the binding is being used for PCP.
    //
    BOOLEAN PcpBinding : 1;

#if DEBUG
    uint8_t Uninitialized : 1;
    uint8_t Freed : 1;
#endif

    //
    // Set of socket contexts one per proc.
    //
    CXPLAT_SOCKET_CONTEXT SocketContexts[];

} CXPLAT_SOCKET;

//
// A per processor datapath context.
//
typedef struct QUIC_CACHEALIGN CXPLAT_DATAPATH_PROC {

    //
    // A pointer to the datapath.
    //
    CXPLAT_DATAPATH* Datapath;

    //
    // The event queue for this proc context.
    //
    CXPLAT_EVENTQ* EventQ;

    //
    // Synchronization mechanism for cleanup.
    //
    CXPLAT_REF_COUNT RefCount;

    //
    // The ideal processor of the context.
    //
    uint16_t IdealProcessor;

#if DEBUG
    uint8_t Uninitialized : 1;
#endif

    //
    // Pool of receive packet contexts and buffers to be shared by all sockets
    // on this core.
    //
    CXPLAT_POOL RecvBlockPool;

    //
    // Pool of send packet contexts and buffers to be shared by all sockets
    // on this core.
    //
    CXPLAT_POOL SendBlockPool;

} CXPLAT_DATAPATH_PROC;

//
// Represents a datapath object.
//

typedef struct CXPLAT_DATAPATH {

    //
    // UDP handlers.
    //
    CXPLAT_UDP_DATAPATH_CALLBACKS UdpHandlers;

    //
    // Synchronization mechanism for cleanup.
    //
    CXPLAT_REF_COUNT RefCount;

    //
    // Set of supported features.
    //
    uint32_t Features;

    //
    // The proc count to create per proc datapath state.
    //
    uint32_t ProcCount;

    //
    // The length of the CXPLAT_SEND_DATA. Calculated based on the support level
    // for GSO. No GSO support requires a larger send data to hold the extra
    // iovec structs.
    //
    uint32_t SendDataSize;

    //
    // When not using GSO, we preallocate multiple iovec structs to use with
    // sendmmsg (to simulate GSO).
    //
    uint32_t SendIoVecCount;

    //
    // The length of the CXPLAT_RECV_DATA and CXPLAT_RECV_PACKET part of the
    // CXPLAT_RECV_BLOCK.
    //
    uint32_t RecvBlockStride;

    //
    // The offset of the raw buffer in the CXPLAT_RECV_BLOCK.
    //
    uint32_t RecvBlockBufferOffset;

    //
    // The total length of the CXPLAT_RECV_BLOCK. Calculated based on the
    // support level for GRO. No GRO only uses a single CXPLAT_RECV_DATA and
    // CXPLAT_RECV_PACKET, while GRO allows for multiple.
    //
    uint32_t RecvBlockSize;

#if DEBUG
    uint8_t Uninitialized : 1;
    uint8_t Freed : 1;
#endif

    struct xsk_socket_info* xsk_info[2];
    struct xsk_socket_config* xsk_cfg[2];
    struct bpf_object* bpf_objs[2];
    int ifindex[2];

    //
    // The per proc datapath contexts.
    //
    CXPLAT_DATAPATH_PROC Processors[];

} CXPLAT_DATAPATH;

#include <linux/if_link.h>
#include <linux/if_ether.h>
#include <linux/ipv6.h>
#include <bpf/bpf.h>
#include <bpf/xsk.h>
#include <net/if.h>

#define NUM_FRAMES         4096
#define FRAME_SIZE         XSK_UMEM__DEFAULT_FRAME_SIZE
#define RX_BATCH_SIZE      64
#define INVALID_UMEM_FRAME UINT64_MAX

// NOTE: hacky
const char* ifnames[2] = {"duo1", "duo2"};
const uint8_t macs[2][ETH_ALEN] = {{0xe2, 0x00, 0x9f, 0x40, 0x9a, 0xc8},  // duo1
                                   {0xd2, 0xd8, 0x6b, 0x4b, 0x10, 0x65}}; // duo2

struct xsk_socket_info {
	struct xsk_ring_cons rx;
	struct xsk_ring_prod tx;
	struct xsk_umem_info *umem;
	struct xsk_socket *xsk;

	uint64_t umem_frame_addr[NUM_FRAMES];
	uint32_t umem_frame_free;
};

struct xsk_umem_info {
	struct xsk_ring_prod fq;
	struct xsk_ring_cons cq;
	struct xsk_umem *umem;
	void *buffer;
};


CXPLAT_DATAPATH_PROC*
CxPlatDataPathGetProc(
    _In_ CXPLAT_DATAPATH* Datapath,
    _In_ uint16_t Processor
    )
{
    for (uint32_t i = 0; i < Datapath->ProcCount; ++i) {
        if (Datapath->Processors[i].IdealProcessor == Processor) {
            return &Datapath->Processors[i];
        }
    }
    CXPLAT_FRE_ASSERT(FALSE); // TODO - What now?!
    return NULL;
}

void
CxPlatProcessorContextInitialize(
    _In_ CXPLAT_DATAPATH* Datapath,
    _In_ uint16_t IdealProcessor,
    _Out_ CXPLAT_DATAPATH_PROC* DatapathProc
    )
{
    CXPLAT_DBG_ASSERT(Datapath != NULL);
    DatapathProc->Datapath = Datapath;
    DatapathProc->IdealProcessor = IdealProcessor;
    DatapathProc->EventQ = CxPlatWorkerGetEventQ(IdealProcessor);
    CxPlatRefInitialize(&DatapathProc->RefCount);
    CxPlatPoolInitialize(TRUE, Datapath->RecvBlockSize, QUIC_POOL_DATA, &DatapathProc->RecvBlockPool);
    CxPlatPoolInitialize(TRUE, Datapath->SendDataSize, QUIC_POOL_DATA, &DatapathProc->SendBlockPool);
}

// TODO: use QUIC error code
/* Exit return codes */
#define EXIT_OK 		 0 /* == EXIT_SUCCESS (stdlib.h) man exit(3) */
#define EXIT_FAIL		 1 /* == EXIT_FAILURE (stdlib.h) man exit(3) */
#define EXIT_FAIL_OPTION	 2
#define EXIT_FAIL_XDP		30
#define EXIT_FAIL_BPF		40

int xdp_link_attach(int ifindex, __u32 xdp_flags, int prog_fd)
{
	int err;

	/* libbpf provide the XDP net_device link-level hook attach helper */
	err = bpf_set_link_xdp_fd(ifindex, prog_fd, xdp_flags);
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
			break;
		case EOPNOTSUPP:
			fprintf(stderr, "Hint: Native-XDP not supported"
				" use --skb-mode or --auto-mode\n");
			break;
		default:
			break;
		}
		return EXIT_FAIL_XDP;
	}

	return EXIT_OK;
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

struct bpf_object *load_bpf_and_xdp_attach(const char* filename, char* progsec, int ifindex)
{
	struct bpf_program *bpf_prog;
	struct bpf_object *bpf_obj;
	int offload_ifindex = 0; // ?
	int prog_fd = -1;
	int err;

    bpf_obj = load_bpf_object_file(filename, offload_ifindex);
	if (!bpf_obj) {
		fprintf(stderr, "ERR: loading file: %s\n", filename);
		exit(EXIT_FAIL_BPF);
	}
	/* At this point: All XDP/BPF programs from the cfg->filename have been
	 * loaded into the kernel, and evaluated by the verifier. Only one of
	 * these gets attached to XDP hook, the others will get freed once this
	 * process exit.
	 */
    bpf_prog = bpf_object__find_program_by_title(bpf_obj, progsec);
	if (!bpf_prog) {
		fprintf(stderr, "ERR: couldn't find a program in ELF section '%s'\n", progsec);
		exit(EXIT_FAIL_BPF);
	}

	//strncpy(progsec, bpf_program__section_name(bpf_prog), 32);

	prog_fd = bpf_program__fd(bpf_prog);
	if (prog_fd <= 0) {
		fprintf(stderr, "ERR: bpf_program__fd failed\n");
		exit(EXIT_FAIL_BPF);
	}

	/* At this point: BPF-progs are (only) loaded by the kernel, and prog_fd
	 * is our select file-descriptor handle. Next step is attaching this FD
	 * to a kernel hook point, in this case XDP net_device link-level hook.
	 */
    int xdp_flags = 0;
	err = xdp_link_attach(ifindex, xdp_flags, prog_fd);
	if (err)
		exit(err);

	return bpf_obj;
}

static uint64_t xsk_alloc_umem_frame(struct xsk_socket_info *xsk)
{
	uint64_t frame;
	if (xsk->umem_frame_free == 0)
		return INVALID_UMEM_FRAME;

	frame = xsk->umem_frame_addr[--xsk->umem_frame_free];
	xsk->umem_frame_addr[xsk->umem_frame_free] = INVALID_UMEM_FRAME;
	return frame;
}

static struct xsk_umem_info *configure_xsk_umem(void *buffer, uint64_t size)
{
	struct xsk_umem_info *umem;
	int ret;

	umem = calloc(1, sizeof(*umem));
	if (!umem)
		return NULL;

	ret = xsk_umem__create(&umem->umem, buffer, size, &umem->fq, &umem->cq,
			       NULL);
	if (ret) {
		errno = -ret;
		return NULL;
	}

	umem->buffer = buffer;
	return umem;
}


QUIC_STATUS
CxPlatDataPathInitialize(
    _In_ uint32_t ClientRecvContextLength,
    _In_opt_ const CXPLAT_UDP_DATAPATH_CALLBACKS* UdpCallbacks,
    _In_opt_ const CXPLAT_TCP_DATAPATH_CALLBACKS* TcpCallbacks,
    _In_opt_ QUIC_EXECUTION_CONFIG* Config,
    _Out_ CXPLAT_DATAPATH** NewDataPath
    )
{
    UNREFERENCED_PARAMETER(TcpCallbacks);
    if (NewDataPath == NULL) {
        return QUIC_STATUS_INVALID_PARAMETER;
    }
    if (UdpCallbacks != NULL) {
        if (UdpCallbacks->Receive == NULL || UdpCallbacks->Unreachable == NULL) {
            return QUIC_STATUS_INVALID_PARAMETER;
        }
    }

    if (!CxPlatWorkersLazyStart(Config)) {
        return QUIC_STATUS_OUT_OF_MEMORY;
    }

    // TODO: remove
    const uint16_t* ProcessorList;
    uint32_t ProcessorCount;
    if (Config && Config->ProcessorCount) {
        ProcessorCount = Config->ProcessorCount;
        ProcessorList = Config->ProcessorList;
    } else {
        ProcessorCount = CxPlatProcMaxCount();
        ProcessorList = NULL;
    }

    const size_t DatapathLength =
        sizeof(CXPLAT_DATAPATH) + ProcessorCount * sizeof(CXPLAT_DATAPATH_PROC);

    CXPLAT_DATAPATH* Datapath =
        (CXPLAT_DATAPATH*)CXPLAT_ALLOC_PAGED(DatapathLength, QUIC_POOL_DATAPATH);
    if (Datapath == NULL) {
        QuicTraceEvent(
            AllocFailure,
            "Allocation of '%s' failed. (%llu bytes)",
            "CXPLAT_DATAPATH",
            DatapathLength);
        return QUIC_STATUS_OUT_OF_MEMORY;
    }

    CxPlatZeroMemory(Datapath, DatapathLength);
    if (UdpCallbacks) {
        Datapath->UdpHandlers = *UdpCallbacks;
    }
    Datapath->ProcCount = ProcessorCount;
    Datapath->Features = CXPLAT_DATAPATH_FEATURE_LOCAL_PORT_SHARING;
    CxPlatRefInitializeEx(&Datapath->RefCount, Datapath->ProcCount);

    // TODO: support segmentation/coalescing feature
    Datapath->SendDataSize = sizeof(CXPLAT_SEND_DATA);
    Datapath->SendIoVecCount = 1;
    Datapath->RecvBlockStride =
        sizeof(CXPLAT_RECV_SUBBLOCK) + ClientRecvContextLength;
    Datapath->RecvBlockBufferOffset =
        sizeof(CXPLAT_RECV_BLOCK) + Datapath->RecvBlockStride;
    Datapath->RecvBlockSize =
        Datapath->RecvBlockBufferOffset + CXPLAT_SMALL_IO_BUFFER_SIZE;

    // TODO: remove
    //
    // Initialize the per processor contexts.
    //
    for (uint32_t i = 0; i < Datapath->ProcCount; i++) {
        CxPlatProcessorContextInitialize(
            Datapath,
            ProcessorList ? ProcessorList[i] : (uint16_t)i,
            &Datapath->Processors[i]);
    }

    // XDP init area, 2 is for loopback test
    // TODO: remove hacky part
    for (int ii = 0; ii < 2; ii++)
    {
        // TODO: input via config?
        const char* ifname = ifnames[ii];
        int ifindex = if_nametoindex(ifname);
        struct xsk_socket_config *xsk_cfg = (struct xsk_socket_config*)calloc(1, sizeof(struct xsk_socket_config)); // TODO: free
        xsk_cfg->rx_size = XSK_RING_CONS__DEFAULT_NUM_DESCS;
        xsk_cfg->tx_size = XSK_RING_PROD__DEFAULT_NUM_DESCS;
        // TODO: auto detect?
        xsk_cfg->libbpf_flags = 0;
        // xsk_cfg.xdp_flags = XDP_FLAGS_SKB_MODE;
        // xsk_cfg.bind_flags = XDP_COPY;
        xsk_cfg->xdp_flags = 0;
        xsk_cfg->bind_flags = 0;
        uint32_t idx;
        uint32_t prog_id = 0;
        int i;
        int ret;

        struct bpf_object *bpf_obj = load_bpf_and_xdp_attach("./datapath_raw_xdp_kern.o", "xdp_prog", ifindex);
        struct bpf_map *map = bpf_object__find_map_by_name(bpf_obj, "xsks_map");
        int xsks_map_fd = bpf_map__fd(map);
        if (xsks_map_fd < 0) {
            fprintf(stderr, "ERROR: no xsks map found: %s\n",
                strerror(xsks_map_fd));
            exit(EXIT_FAILURE);
        }

        void *packet_buffer;
        uint64_t packet_buffer_size;
        /* Allocate memory for NUM_FRAMES of the default XDP frame size */
        packet_buffer_size = NUM_FRAMES * FRAME_SIZE;
        if (posix_memalign(&packet_buffer,
                getpagesize(), /* PAGE_SIZE aligned */
                packet_buffer_size)) {
            fprintf(stderr, "ERROR: Can't allocate buffer memory \"%s\"\n",
                strerror(errno));
            exit(EXIT_FAILURE);
        }

        /* Initialize shared packet_buffer for umem usage */
        struct xsk_umem_info *umem;
        umem = configure_xsk_umem(packet_buffer, packet_buffer_size);
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
            goto Exit;
        }

        // TODO: share port from Binding->LocalAddress to BPF map
        xsk_info->umem = umem;
        int queue_id = 0; // TODO:check
        ret = xsk_socket__create(&xsk_info->xsk, ifname,
                    queue_id++, umem->umem, &xsk_info->rx,
                    &xsk_info->tx, xsk_cfg);
        // fprintf(stderr, "xsk_socket__create:%d\n", ret);
        if (ret) {
            // Status = errno;
            // QuicTraceEvent(
            //     DatapathErrorStatus,
            //     "[data] ERROR, %u, %s.",
            //     Status,
            //     "socket failed");
            goto Exit;
        }
        CxPlatSleep(20);

        for (i = 0; i < NUM_FRAMES; i++)
            xsk_info->umem_frame_addr[i] = i * FRAME_SIZE;

        xsk_info->umem_frame_free = NUM_FRAMES;

        ret = bpf_get_link_xdp_id(ifindex, &prog_id, xsk_cfg->xdp_flags);
        if (ret) {
            goto Exit;
        }

        /* Stuff the receive path with buffers, we assume we have enough */
        ret = xsk_ring_prod__reserve(&xsk_info->umem->fq,
                        XSK_RING_PROD__DEFAULT_NUM_DESCS,
                        &idx);
        if (ret != XSK_RING_PROD__DEFAULT_NUM_DESCS) {
            goto Exit;
        }

        for (i = 0; i < XSK_RING_PROD__DEFAULT_NUM_DESCS; i ++) {
            *xsk_ring_prod__fill_addr(&xsk_info->umem->fq, idx++) =
                xsk_alloc_umem_frame(xsk_info);
        }

        xsk_ring_prod__submit(&xsk_info->umem->fq,
                    XSK_RING_PROD__DEFAULT_NUM_DESCS);        

        Datapath->xsk_info[ii] = xsk_info;
        Datapath->xsk_cfg[ii] = xsk_cfg;
        Datapath->bpf_objs[ii] = bpf_obj;
        Datapath->ifindex[ii] = ifindex;
    }

    CXPLAT_FRE_ASSERT(CxPlatRundownAcquire(&CxPlatWorkerRundown));
    *NewDataPath = Datapath;

Exit:
    // TODO: cleanup

    return QUIC_STATUS_SUCCESS;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
void
CxPlatDataPathRelease(
    _In_ CXPLAT_DATAPATH* Datapath
    )
{
    if (CxPlatRefDecrement(&Datapath->RefCount)) {
#if DEBUG
        CXPLAT_DBG_ASSERT(!Datapath->Freed);
        CXPLAT_DBG_ASSERT(Datapath->Uninitialized);
        Datapath->Freed = TRUE;
#endif
        CXPLAT_FREE(Datapath, QUIC_POOL_DATAPATH);
        CxPlatRundownRelease(&CxPlatWorkerRundown);
    }
}

_IRQL_requires_max_(PASSIVE_LEVEL)
void
CxPlatProcessorContextRelease(
    _In_ CXPLAT_DATAPATH_PROC* DatapathProc
    )
{
    if (CxPlatRefDecrement(&DatapathProc->RefCount)) {
#if DEBUG
        CXPLAT_DBG_ASSERT(!DatapathProc->Uninitialized);
        DatapathProc->Uninitialized = TRUE;
#endif
        CxPlatPoolUninitialize(&DatapathProc->SendBlockPool);
        CxPlatPoolUninitialize(&DatapathProc->RecvBlockPool);
        CxPlatDataPathRelease(DatapathProc->Datapath);
    }
}

int xdp_link_detach(int ifindex, __u32 xdp_flags, __u32 expected_prog_id)
{
	__u32 curr_prog_id;
	int err;

	err = bpf_get_link_xdp_id(ifindex, &curr_prog_id, xdp_flags);
	if (err) {
		fprintf(stderr, "ERR: get link xdp id failed (err=%d): %s\n",
			-err, strerror(-err));
		return EXIT_FAIL_XDP;
	}

	if (!curr_prog_id) {
		// if (verbose)
		// 	printf("INFO: %s() no curr XDP prog on ifindex:%d\n",
		// 	       __func__, ifindex);
		return EXIT_OK;
	}

	if (expected_prog_id && curr_prog_id != expected_prog_id) {
		fprintf(stderr, "ERR: %s() "
			"expected prog ID(%d) no match(%d), not removing\n",
			__func__, expected_prog_id, curr_prog_id);
		return EXIT_FAIL;
	}

	if ((err = bpf_set_link_xdp_fd(ifindex, -1, xdp_flags)) < 0) {
		fprintf(stderr, "ERR: %s() link set xdp failed (err=%d): %s\n",
			__func__, err, strerror(-err));
		return EXIT_FAIL_XDP;
	}

	// if (verbose)
	// 	printf("INFO: %s() removed XDP prog ID:%d on ifindex:%d\n",
	// 	       __func__, curr_prog_id, ifindex);

	return EXIT_OK;
}

void
CxPlatDataPathUninitialize(
    _In_ CXPLAT_DATAPATH* Datapath
    )
{
    if (Datapath != NULL) {
#if DEBUG
        CXPLAT_DBG_ASSERT(!Datapath->Uninitialized);
        Datapath->Uninitialized = TRUE;
#endif
        const uint16_t ProcCount = Datapath->ProcCount;
        for (uint32_t i = 0; i < ProcCount; i++) {
            CxPlatProcessorContextRelease(&Datapath->Processors[i]);
        }
    }

    // TODO: in datapath_raw_xdp ?
    for (int ii = 0; ii < 2; ii++) {
        if (Datapath->xsk_info[ii]) {
            xsk_socket__delete(Datapath->xsk_info[ii]->xsk);
            xsk_umem__delete(Datapath->xsk_info[ii]->umem->umem);
            xdp_link_detach(Datapath->ifindex[ii], Datapath->xsk_cfg[ii]->xdp_flags, 0);
            bpf_object__close(Datapath->bpf_objs[ii]);
            free(Datapath->xsk_info[ii]->umem);
            free(Datapath->xsk_info[ii]);
            free(Datapath->xsk_cfg[ii]);
        }
    }
}

_IRQL_requires_max_(DISPATCH_LEVEL)
uint32_t
CxPlatDataPathGetSupportedFeatures(
    _In_ CXPLAT_DATAPATH* Datapath
    )
{
    // TODO: implement features, its flags and return
    UNREFERENCED_PARAMETER(Datapath);
    return 0;
}

BOOLEAN
CxPlatDataPathIsPaddingPreferred(
    _In_ CXPLAT_DATAPATH* Datapath
    )
{
    return !!(Datapath->Features & CXPLAT_DATAPATH_FEATURE_SEND_SEGMENTATION);
}

void
CxPlatDataPathPopulateTargetAddress(
    _In_ QUIC_ADDRESS_FAMILY Family,
    _In_ ADDRINFO* AddrInfo,
    _Out_ QUIC_ADDR* Address
    )
{
    struct sockaddr_in6* SockAddrIn6 = NULL;
    struct sockaddr_in* SockAddrIn = NULL;

    CxPlatZeroMemory(Address, sizeof(QUIC_ADDR));

    if (AddrInfo->ai_addr->sa_family == AF_INET6) {
        CXPLAT_DBG_ASSERT(sizeof(struct sockaddr_in6) == AddrInfo->ai_addrlen);

        //
        // Is this a mapped ipv4 one?
        //

        SockAddrIn6 = (struct sockaddr_in6*)AddrInfo->ai_addr;

        if (Family == QUIC_ADDRESS_FAMILY_UNSPEC && IN6_IS_ADDR_V4MAPPED(&SockAddrIn6->sin6_addr)) {
            SockAddrIn = &Address->Ipv4;

            //
            // Get the ipv4 address from the mapped address.
            //

            SockAddrIn->sin_family = QUIC_ADDRESS_FAMILY_INET;
            memcpy(&SockAddrIn->sin_addr.s_addr, &SockAddrIn6->sin6_addr.s6_addr[12], 4);
            SockAddrIn->sin_port = SockAddrIn6->sin6_port;

            return;
        }
        Address->Ipv6 = *SockAddrIn6;
        Address->Ipv6.sin6_family = QUIC_ADDRESS_FAMILY_INET6;
        return;
    }

    if (AddrInfo->ai_addr->sa_family == AF_INET) {
        CXPLAT_DBG_ASSERT(sizeof(struct sockaddr_in) == AddrInfo->ai_addrlen);
        SockAddrIn = (struct sockaddr_in*)AddrInfo->ai_addr;
        Address->Ipv4 = *SockAddrIn;
        Address->Ipv4.sin_family = QUIC_ADDRESS_FAMILY_INET;
        return;
    }

    CXPLAT_FRE_ASSERT(FALSE);
}

_IRQL_requires_max_(PASSIVE_LEVEL)
_Success_(QUIC_SUCCEEDED(return))
QUIC_STATUS
CxPlatDataPathGetLocalAddresses(
    _In_ CXPLAT_DATAPATH* Datapath,
    _Outptr_ _At_(*Addresses, __drv_allocatesMem(Mem))
        CXPLAT_ADAPTER_ADDRESS** Addresses,
    _Out_ uint32_t* AddressesCount
    )
{
    UNREFERENCED_PARAMETER(Datapath);
    *Addresses = NULL;
    *AddressesCount = 0;
    return QUIC_STATUS_NOT_SUPPORTED;
}

QUIC_STATUS
CxPlatDataPathGetGatewayAddresses(
    _In_ CXPLAT_DATAPATH* Datapath,
    _Outptr_ _At_(*GatewayAddresses, __drv_allocatesMem(Mem))
        QUIC_ADDR** GatewayAddresses,
    _Out_ uint32_t* GatewayAddressesCount
    )
{
    UNREFERENCED_PARAMETER(Datapath);
    *GatewayAddresses = NULL;
    *GatewayAddressesCount = 0;
    return QUIC_STATUS_NOT_SUPPORTED;
}

QUIC_STATUS
CxPlatDataPathResolveAddress(
    _In_ CXPLAT_DATAPATH* Datapath,
    _In_z_ const char* HostName,
    _Inout_ QUIC_ADDR* Address
    )
{
    UNREFERENCED_PARAMETER(Datapath);
    QUIC_STATUS Status = QUIC_STATUS_SUCCESS;
    ADDRINFO Hints = {0};
    ADDRINFO* AddrInfo = NULL;
    int Result = 0;

    //
    // Prepopulate hint with input family. It might be unspecified.
    //
    Hints.ai_family = Address->Ip.sa_family;
    if (Hints.ai_family == QUIC_ADDRESS_FAMILY_INET6) {
        Hints.ai_family = AF_INET6;
    }

    //
    // Try numeric name first.
    //
    Hints.ai_flags = AI_NUMERICHOST;
    Result = getaddrinfo(HostName, NULL, &Hints, &AddrInfo);
    if (Result == 0) {
        CxPlatDataPathPopulateTargetAddress(Hints.ai_family, AddrInfo, Address);
        freeaddrinfo(AddrInfo);
        AddrInfo = NULL;
        goto Exit;
    }

    //
    // Try canonical host name.
    //
    Hints.ai_flags = AI_CANONNAME;
    Result = getaddrinfo(HostName, NULL, &Hints, &AddrInfo);
    if (Result == 0) {
        CxPlatDataPathPopulateTargetAddress(Hints.ai_family, AddrInfo, Address);
        freeaddrinfo(AddrInfo);
        AddrInfo = NULL;
        goto Exit;
    }

    QuicTraceEvent(
        LibraryErrorStatus,
        "[ lib] ERROR, %u, %s.",
        (uint32_t)Result,
        "Resolving hostname to IP");
    QuicTraceLogError(
        DatapathResolveHostNameFailed,
        "[%p] Couldn't resolve hostname '%s' to an IP address",
        Datapath,
        HostName);
    Status = (QUIC_STATUS)Result;

Exit:

    return Status;
}

//
// Socket context interface. It abstracts a (generally per-processor) UDP socket
// and the corresponding logic/functionality like send and receive processing.
//

QUIC_STATUS
CxPlatSocketContextInitialize(
    _Inout_ CXPLAT_SOCKET_CONTEXT* SocketContext
    )
{
    QUIC_STATUS Status = QUIC_STATUS_SUCCESS;
    BOOLEAN ShutdownSqeInitialized = FALSE;
    BOOLEAN IoSqeInitialized = FALSE;
    BOOLEAN FlushTxInitialized = FALSE;

    CXPLAT_SOCKET* Binding = SocketContext->Binding;

    CXPLAT_DBG_ASSERT(SocketContext->Binding->Datapath == SocketContext->DatapathProc->Datapath);

    if (!CxPlatSqeInitialize(
            SocketContext->DatapathProc->EventQ,
            &SocketContext->ShutdownSqe.Sqe,
            &SocketContext->ShutdownSqe)) {
        Status = errno;
        QuicTraceEvent(
            DatapathErrorStatus,
            "[data][%p] ERROR, %u, %s.",
            Binding,
            Status,
            "CxPlatSqeInitialize failed");
        goto Exit;
    }
    ShutdownSqeInitialized = TRUE;

    if (!CxPlatSqeInitialize(
            SocketContext->DatapathProc->EventQ,
            &SocketContext->IoSqe.Sqe,
            &SocketContext->IoSqe)) {
        Status = errno;
        QuicTraceEvent(
            DatapathErrorStatus,
            "[data][%p] ERROR, %u, %s.",
            Binding,
            Status,
            "CxPlatSqeInitialize failed");
        goto Exit;
    }
    IoSqeInitialized = TRUE;

    if (!CxPlatSqeInitialize(
            SocketContext->DatapathProc->EventQ,
            &SocketContext->FlushTxSqe.Sqe,
            &SocketContext->FlushTxSqe)) {
        Status = errno;
        QuicTraceEvent(
            DatapathErrorStatus,
            "[data][%p] ERROR, %u, %s.",
            Binding,
            Status,
            "CxPlatSqeInitialize failed");
        goto Exit;
    }
    FlushTxInitialized = TRUE;

    SocketContext->SocketFd = xsk_socket__fd(Binding->Datapath->xsk_info[SocketContext->ActorIdx]->xsk);
    // // SocketContext->Binding->AuxSocket = xsk_socket__fd(SocketContext->xsk_info->xsk);
	
    QUIC_ADDR MappedAddress = {0};
    CxPlatCopyMemory(&MappedAddress, &Binding->LocalAddress, sizeof(MappedAddress));
    if (MappedAddress.Ipv6.sin6_family == QUIC_ADDRESS_FAMILY_INET6) {
        MappedAddress.Ipv6.sin6_family = AF_INET6;
    }

    // dummy sock for taking random ephemeral port
    SocketContext->dummySock = socket(AF_INET6,
            SOCK_DGRAM | SOCK_NONBLOCK | SOCK_CLOEXEC,
            IPPROTO_UDP);
    if (SocketContext->dummySock == INVALID_SOCKET) {
        Status = errno;
        QuicTraceEvent(
            DatapathErrorStatus,
            "[data][%p] ERROR, %u, %s.",
            Binding,
            Status,
            "socket failed");
        goto Exit;
    }
    int Result =
        bind(
            SocketContext->dummySock,
            &MappedAddress.Ip,
            sizeof(MappedAddress));
    if (Result == SOCKET_ERROR) {
        Status = errno;
        QuicTraceEvent(
            DatapathErrorStatus,
            "[data][%p] ERROR, %u, %s.",
            Binding,
            Status,
            "bind failed");
        goto Exit;
    }

    //
    // If no specific local port was indicated, then the stack just
    // assigned this socket a port. We need to query it and use it for
    // all the other sockets we are going to create.
    //
    uint32_t AssignedLocalAddressLength = sizeof(Binding->LocalAddress);
    Result =
        getsockname(
            SocketContext->dummySock,
            (struct sockaddr *)&Binding->LocalAddress,
            &AssignedLocalAddressLength);
    if (Result == SOCKET_ERROR) {
        Status = errno;
        QuicTraceEvent(
            DatapathErrorStatus,
            "[data][%p] ERROR, %u, %s.",
            Binding,
            Status,
            "getsockname failed");
        goto Exit;
    }

    // share ephemeral port to XDP
    struct bpf_map *port_map = bpf_object__find_map_by_name(SocketContext->Binding->Datapath->bpf_objs[SocketContext->ActorIdx], "port_map");
    if (!port_map) {
        fprintf(stderr, "Failed to find BPF port_map\n");
        return 1;
    }

    int key = 0; // single port for now
    int value_to_share = Binding->LocalAddress.Ipv4.sin_port;
    // TODO: need to care until all packets received?
    if (bpf_map_update_elem(bpf_map__fd(port_map), &key, &value_to_share, BPF_ANY)) {
        fprintf(stderr, "Failed to update BPF map\n");
        return 1;
    }

    SocketContext->SqeInitialized = TRUE;

Exit:

    if (QUIC_FAILED(Status)) {
        if (SocketContext->dummySock != INVALID_SOCKET) {
            close(SocketContext->dummySock);
        }
        SocketContext->SocketFd = INVALID_SOCKET;
        if (ShutdownSqeInitialized) {
            CxPlatSqeCleanup(SocketContext->DatapathProc->EventQ, &SocketContext->ShutdownSqe.Sqe);
        }
        if (IoSqeInitialized) {
            CxPlatSqeCleanup(SocketContext->DatapathProc->EventQ, &SocketContext->IoSqe.Sqe);
        }
        if (FlushTxInitialized) {
            CxPlatSqeCleanup(SocketContext->DatapathProc->EventQ, &SocketContext->FlushTxSqe.Sqe);
        }
    }

    return Status;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
void
CxPlatSocketRelease(
    _In_ CXPLAT_SOCKET* Socket
    )
{
    if (CxPlatRefDecrement(&Socket->RefCount)) {
#if DEBUG
        CXPLAT_DBG_ASSERT(!Socket->Freed);
        CXPLAT_DBG_ASSERT(Socket->Uninitialized);
        Socket->Freed = TRUE;
#endif
        CXPLAT_FREE(Socket, QUIC_POOL_SOCKET);
    }
}

void
CxPlatSocketContextUninitializeComplete(
    _In_ CXPLAT_SOCKET_CONTEXT* SocketContext
    )
{
#if DEBUG
    CXPLAT_DBG_ASSERT(!SocketContext->Freed);
    SocketContext->Freed = TRUE;
#endif

    while (!CxPlatListIsEmpty(&SocketContext->TxQueue)) {
        CxPlatSendDataFree(
            CXPLAT_CONTAINING_RECORD(
                CxPlatListRemoveHead(&SocketContext->TxQueue),
                CXPLAT_SEND_DATA,
                TxEntry));
    }

    if (SocketContext->dummySock != INVALID_SOCKET) {
        close(SocketContext->dummySock);
    }

    if (SocketContext->SocketFd != INVALID_SOCKET) {
        epoll_ctl(*SocketContext->DatapathProc->EventQ, EPOLL_CTL_DEL, SocketContext->SocketFd, NULL);
        SocketContext->SocketFd = INVALID_SOCKET;
    }

    if (SocketContext->SqeInitialized) {
        CxPlatSqeCleanup(SocketContext->DatapathProc->EventQ, &SocketContext->ShutdownSqe.Sqe);
        CxPlatSqeCleanup(SocketContext->DatapathProc->EventQ, &SocketContext->IoSqe.Sqe);
        CxPlatSqeCleanup(SocketContext->DatapathProc->EventQ, &SocketContext->FlushTxSqe.Sqe);
    }

    CxPlatLockUninitialize(&SocketContext->TxQueueLock);
    CxPlatRundownUninitialize(&SocketContext->UpcallRundown);

    if (SocketContext->DatapathProc) {
        CxPlatProcessorContextRelease(SocketContext->DatapathProc);
    }
    CxPlatSocketRelease(SocketContext->Binding);
}

void
CxPlatSocketContextUninitialize(
    _In_ CXPLAT_SOCKET_CONTEXT* SocketContext
    )
{
#if DEBUG
    CXPLAT_DBG_ASSERT(!SocketContext->Uninitialized);
    SocketContext->Uninitialized = TRUE;
#endif

    if (!SocketContext->IoStarted) {
        CxPlatSocketContextUninitializeComplete(SocketContext);
    } else {
        CxPlatRundownReleaseAndWait(&SocketContext->UpcallRundown); // Block until all upcalls complete.

        //
        // Cancel and clean up any pending IO.
        //
        epoll_ctl(*SocketContext->DatapathProc->EventQ, EPOLL_CTL_DEL, SocketContext->SocketFd, NULL);

        CXPLAT_FRE_ASSERT(
            CxPlatEventQEnqueue(
                SocketContext->DatapathProc->EventQ,
                &SocketContext->ShutdownSqe.Sqe,
                &SocketContext->ShutdownSqe));
    }
}

void
CxPlatSocketContextSetEvents(
    _In_ CXPLAT_SOCKET_CONTEXT* SocketContext,
    _In_ int Operation,
    _In_ uint32_t Events
    )
{
    struct epoll_event SockFdEpEvt = {
        .events = Events, .data = { .ptr = &SocketContext->IoSqe, } };

    int Ret =
        epoll_ctl(
            *SocketContext->DatapathProc->EventQ,
            Operation,
            SocketContext->SocketFd,
            &SockFdEpEvt);
    if (Ret != 0) {
        QuicTraceEvent(
            DatapathErrorStatus,
            "[data][%p] ERROR, %u, %s.",
            SocketContext->Binding,
            errno,
            "epoll_ctl failed");
    }
}

//
// Datapath binding interface.
//

QUIC_STATUS
CxPlatSocketCreateUdp(
    _In_ CXPLAT_DATAPATH* Datapath,
    _In_ const CXPLAT_UDP_CONFIG* Config,
    _Out_ CXPLAT_SOCKET** NewBinding
    )
{
    QUIC_STATUS Status = QUIC_STATUS_SUCCESS;
    BOOLEAN IsServerSocket = Config->RemoteAddress == NULL;

    CXPLAT_DBG_ASSERT(Datapath->UdpHandlers.Receive != NULL || Config->Flags & CXPLAT_SOCKET_FLAG_PCP);

    const uint32_t CurrentProc = CxPlatProcCurrentNumber() % Datapath->ProcCount;
    const size_t BindingLength =
        sizeof(CXPLAT_SOCKET) + sizeof(CXPLAT_SOCKET_CONTEXT);

    CXPLAT_SOCKET* Binding =
        (CXPLAT_SOCKET*)CXPLAT_ALLOC_PAGED(BindingLength, QUIC_POOL_SOCKET);
    if (Binding == NULL) {
        Status = QUIC_STATUS_OUT_OF_MEMORY;
        QuicTraceEvent(
            AllocFailure,
            "Allocation of '%s' failed. (%llu bytes)",
            "CXPLAT_SOCKET",
            BindingLength);
        goto Exit;
    }

    QuicTraceEvent(
        DatapathCreated,
        "[data][%p] Created, local=%!ADDR!, remote=%!ADDR!",
        Binding,
        CASTED_CLOG_BYTEARRAY(Config->LocalAddress ? sizeof(*Config->LocalAddress) : 0, Config->LocalAddress),
        CASTED_CLOG_BYTEARRAY(Config->RemoteAddress ? sizeof(*Config->RemoteAddress) : 0, Config->RemoteAddress));

    CxPlatZeroMemory(Binding, BindingLength);
    Binding->Datapath = Datapath;
    Binding->ClientContext = Config->CallbackContext;
    Binding->HasFixedRemoteAddress = (Config->RemoteAddress != NULL);
    Binding->Mtu = CXPLAT_MAX_MTU;
    CxPlatRefInitializeEx(&Binding->RefCount, 1);
    if (Config->LocalAddress) {
        CxPlatConvertToMappedV6(Config->LocalAddress, &Binding->LocalAddress);
    } else {
        Binding->LocalAddress.Ip.sa_family = QUIC_ADDRESS_FAMILY_INET6;
    }

    Binding->SocketContexts[0].Binding = Binding;
    Binding->SocketContexts[0].SocketFd = INVALID_SOCKET;
    Binding->SocketContexts[0].dummySock = INVALID_SOCKET;
    Binding->SocketContexts[0].ShutdownSqe.CqeType = CXPLAT_CQE_TYPE_SOCKET_SHUTDOWN;
    Binding->SocketContexts[0].IoSqe.CqeType = CXPLAT_CQE_TYPE_SOCKET_IO;
    Binding->SocketContexts[0].FlushTxSqe.CqeType = CXPLAT_CQE_TYPE_SOCKET_FLUSH_TX;
    Binding->SocketContexts[0].DatapathProc =
        IsServerSocket ?
            &Datapath->Processors[0] :
            CxPlatDataPathGetProc(Datapath, CurrentProc);
    // NOTE: hack for loopback test. server: 0, client: 1
    Binding->SocketContexts[0].ActorIdx = !IsServerSocket;
    CxPlatRefIncrement(&Binding->SocketContexts[0].DatapathProc->RefCount);
    CxPlatListInitializeHead(&Binding->SocketContexts[0].TxQueue);
    CxPlatLockInitialize(&Binding->SocketContexts[0].TxQueueLock);
    CxPlatRundownInitialize(&Binding->SocketContexts[0].UpcallRundown);

    if (Config->Flags & CXPLAT_SOCKET_FLAG_PCP) {
        Binding->PcpBinding = TRUE;
    }

    Status = CxPlatSocketContextInitialize(&Binding->SocketContexts[0]);
    if (QUIC_FAILED(Status)) {
        goto Exit;
    }

    CxPlatConvertFromMappedV6(&Binding->LocalAddress, &Binding->LocalAddress);
    Binding->LocalAddress.Ipv6.sin6_scope_id = 0;

    if (Config->RemoteAddress != NULL) {
        Binding->RemoteAddress = *Config->RemoteAddress;
    } else {
        Binding->RemoteAddress.Ipv4.sin_port = 0;
    }

    //
    // Must set output pointer before starting receive path, as the receive path
    // will try to use the output.
    //
    *NewBinding = Binding;

    CxPlatSocketContextSetEvents(&Binding->SocketContexts[0], EPOLL_CTL_ADD, EPOLLIN);
    Binding->SocketContexts[0].IoStarted = TRUE;

    Binding = NULL;

Exit:

    if (Binding != NULL) {
        CxPlatSocketDelete(Binding);
    }

    return Status;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
QUIC_STATUS
CxPlatSocketCreateTcp(
    _In_ CXPLAT_DATAPATH* Datapath,
    _In_opt_ const QUIC_ADDR* LocalAddress,
    _In_ const QUIC_ADDR* RemoteAddress,
    _In_opt_ void* CallbackContext,
    _Out_ CXPLAT_SOCKET** Socket
    )
{
    UNREFERENCED_PARAMETER(Datapath);
    UNREFERENCED_PARAMETER(LocalAddress);
    UNREFERENCED_PARAMETER(RemoteAddress);
    UNREFERENCED_PARAMETER(CallbackContext);
    UNREFERENCED_PARAMETER(Socket);
    return QUIC_STATUS_NOT_SUPPORTED;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
QUIC_STATUS
CxPlatSocketCreateTcpListener(
    _In_ CXPLAT_DATAPATH* Datapath,
    _In_opt_ const QUIC_ADDR* LocalAddress,
    _In_opt_ void* CallbackContext,
    _Out_ CXPLAT_SOCKET** Socket
    )
{
    UNREFERENCED_PARAMETER(Datapath);
    UNREFERENCED_PARAMETER(LocalAddress);
    UNREFERENCED_PARAMETER(CallbackContext);
    UNREFERENCED_PARAMETER(Socket);
    return QUIC_STATUS_NOT_SUPPORTED;
}

void
CxPlatSocketDelete(
    _Inout_ CXPLAT_SOCKET* Socket
    )
{
    CXPLAT_DBG_ASSERT(Socket != NULL);
    QuicTraceEvent(
        DatapathDestroyed,
        "[data][%p] Destroyed",
        Socket);

#if DEBUG
    CXPLAT_DBG_ASSERT(!Socket->Uninitialized);
    Socket->Uninitialized = TRUE;
#endif

    CxPlatSocketContextUninitialize(&Socket->SocketContexts[0]);
}

uint16_t
CxPlatSocketGetLocalMtu(
    _In_ CXPLAT_SOCKET* Socket
    )
{
    CXPLAT_DBG_ASSERT(Socket != NULL);
    return Socket->Mtu;
}

void
CxPlatSocketGetLocalAddress(
    _In_ CXPLAT_SOCKET* Socket,
    _Out_ QUIC_ADDR* Address
    )
{
    CXPLAT_DBG_ASSERT(Socket != NULL);
    *Address = Socket->LocalAddress;
}

void
CxPlatSocketGetRemoteAddress(
    _In_ CXPLAT_SOCKET* Socket,
    _Out_ QUIC_ADDR* Address
    )
{
    CXPLAT_DBG_ASSERT(Socket != NULL);
    *Address = Socket->RemoteAddress;
}

//
// Receive Path
//

CXPLAT_RECV_DATA*
CxPlatDataPathRecvPacketToRecvData(
    _In_ const CXPLAT_RECV_PACKET* const Packet
    )
{
    return (CXPLAT_RECV_DATA*)((char *)Packet - sizeof(CXPLAT_RECV_DATA));
}

CXPLAT_RECV_PACKET*
CxPlatDataPathRecvDataToRecvPacket(
    _In_ const CXPLAT_RECV_DATA* const RecvData
    )
{
    return (CXPLAT_RECV_PACKET*)(RecvData + 1);
}

void
CxPlatSocketHandleErrors(
    _In_ CXPLAT_SOCKET_CONTEXT* SocketContext
    )
{
    int ErrNum = 0;
    socklen_t OptLen = sizeof(ErrNum);
    ssize_t Ret =
        getsockopt(
            SocketContext->SocketFd,
            SOL_SOCKET,
            SO_ERROR,
            &ErrNum,
            &OptLen);
    if (Ret < 0) {
        QuicTraceEvent(
            DatapathErrorStatus,
            "[data][%p] ERROR, %u, %s.",
            SocketContext->Binding,
            errno,
            "getsockopt(SO_ERROR) failed");
    } else {
        QuicTraceEvent(
            DatapathErrorStatus,
            "[data][%p] ERROR, %u, %s.",
            SocketContext->Binding,
            ErrNum,
            "Socket error event");

        //
        // Send unreachable notification to MsQuic if any related
        // errors were received.
        //
        if (ErrNum == ECONNREFUSED ||
            ErrNum == EHOSTUNREACH ||
            ErrNum == ENETUNREACH) {
            if (!SocketContext->Binding->PcpBinding) {
                SocketContext->Binding->Datapath->UdpHandlers.Unreachable(
                    SocketContext->Binding,
                    SocketContext->Binding->ClientContext,
                    &SocketContext->Binding->RemoteAddress);
            }
        }
    }
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

//#include "datapath_raw.h"
#include "datapath_raw_framing.h"

_IRQL_requires_max_(DISPATCH_LEVEL)
void
CxPlatDpRawRxEthernet(
    //_In_ const CXPLAT_DATAPATH* Datapath,
    _In_ const CXPLAT_SOCKET_CONTEXT* SocketContext,
    _In_reads_(PacketCount)
        CXPLAT_RECV_DATA** Packets,
    _In_ uint16_t PacketCount
    )
{
    //CXPLAT_DATAPATH* Datapath = SocketContext->Binding->Datapath;
    for (uint16_t i = 0; i < PacketCount; i++) {
        CXPLAT_SOCKET* Socket = NULL;
        CXPLAT_RECV_DATA* PacketChain = Packets[i];
        CXPLAT_DBG_ASSERT(PacketChain->Next == NULL);

        if (PacketChain->Reserved >= L4_TYPE_UDP) {
            Socket = SocketContext->Binding;
                // CxPlatGetSocket(
                //     &Datapath->SocketPool,
                //     &PacketChain->Route->LocalAddress,
                //     &PacketChain->Route->RemoteAddress);
        }

        if (Socket) {
            if (PacketChain->Reserved == L4_TYPE_UDP || PacketChain->Reserved == L4_TYPE_TCP) {
                // uint8_t SocketType = Socket->UseTcp ? L4_TYPE_TCP : L4_TYPE_UDP;
                uint8_t SocketType = L4_TYPE_UDP;

                //
                // Found a match. Chain and deliver contiguous packets with the same 4-tuple.
                //
                while (i < PacketCount) {
                    // QuicTraceEvent(
                    //     DatapathRecv,
                    //     "[data][%p] Recv %u bytes (segment=%hu) Src=%!ADDR! Dst=%!ADDR!",
                    //     Socket,
                    //     Packets[i]->BufferLength,
                    //     Packets[i]->BufferLength,
                    //     CASTED_CLOG_BYTEARRAY(sizeof(Packets[i]->Route->LocalAddress), &Packets[i]->Route->LocalAddress),
                    //     CASTED_CLOG_BYTEARRAY(sizeof(Packets[i]->Route->RemoteAddress), &Packets[i]->Route->RemoteAddress));
                    if (i == PacketCount - 1 ||
                        Packets[i+1]->Reserved != SocketType ||
                        Packets[i+1]->Route->LocalAddress.Ipv4.sin_port != Socket->LocalAddress.Ipv4.sin_port /*||
                        !CxPlatSocketCompare(Socket, &Packets[i+1]->Route->LocalAddress, &Packets[i+1]->Route->RemoteAddress)*/) {
                        break;
                    }
                    Packets[i]->Next = Packets[i+1];
                    CXPLAT_DBG_ASSERT(Packets[i+1]->Next == NULL);
                    i++;
                }
                SocketContext->Binding->Datapath->UdpHandlers.Receive(
                    SocketContext->Binding,
                    SocketContext->Binding->ClientContext,
                    (CXPLAT_RECV_DATA*)PacketChain);                
            }
            // else if (PacketChain->Reserved == L4_TYPE_TCP_SYN || PacketChain->Reserved == L4_TYPE_TCP_SYNACK) {
            //     CxPlatDpRawSocketAckSyn(Socket, PacketChain);
            //     CxPlatDpRawRxFree(PacketChain);
            // } else if (PacketChain->Reserved == L4_TYPE_TCP_FIN) {
            //     CxPlatDpRawSocketAckFin(Socket, PacketChain);
            //     CxPlatDpRawRxFree(PacketChain);
            // } else {
            //     CxPlatDpRawRxFree(PacketChain);
            // }

            // CxPlatRundownRelease(&Socket->Rundown);
        } else {
            // CxPlatDpRawRxFree(PacketChain);
        }
    }
}

void handle_receive_packets(
    _In_ CXPLAT_SOCKET_CONTEXT* SocketContext
    )
{
    CXPLAT_DATAPATH *Datapath = SocketContext->DatapathProc->Datapath;
    struct xsk_socket_info *xsk = Datapath->xsk_info[SocketContext->ActorIdx];
    unsigned int rcvd, stock_frames, i;
	uint32_t idx_rx = 0, idx_fq = 0;
	unsigned int ret;

	rcvd = xsk_ring_cons__peek(&xsk->rx, RX_BATCH_SIZE, &idx_rx);
	if (!rcvd)
		return;

	/* Stuff the ring with as much frames as possible */
	stock_frames = xsk_prod_nb_free(&xsk->umem->fq,
					xsk_umem_free_frames(xsk));

	if (stock_frames > 0) {

		ret = xsk_ring_prod__reserve(&xsk->umem->fq, stock_frames,
					     &idx_fq);

		/* This should not happen, but just in case */
		while (ret != stock_frames)
			ret = xsk_ring_prod__reserve(&xsk->umem->fq, rcvd,
						     &idx_fq);

		for (i = 0; i < stock_frames; i++)
			*xsk_ring_prod__fill_addr(&xsk->umem->fq, idx_fq++) =
				xsk_alloc_umem_frame(xsk);

		xsk_ring_prod__submit(&xsk->umem->fq, stock_frames);
	}

	/* Process received packets */
    CXPLAT_RECV_DATA* Buffers[RX_BATCH_SIZE];
    uint32_t PacketCount = 0;
	for (i = 0; i < rcvd; i++) {
		uint64_t addr = xsk_ring_cons__rx_desc(&xsk->rx, idx_rx)->addr;
		uint32_t len = xsk_ring_cons__rx_desc(&xsk->rx, idx_rx++)->len;

        CXPLAT_RECV_DATA* Packet = (CXPLAT_RECV_DATA*)malloc(sizeof(CXPLAT_RECV_DATA)); // TODO: free
        CxPlatZeroMemory(Packet, sizeof(CXPLAT_RECV_DATA));
        Packet->Route = (CXPLAT_ROUTE*)calloc(1, sizeof(CXPLAT_ROUTE)); // TODO: free
        // Packet->Route->Queue
        // Packet->RouteStorage.Queue = Queue;
        // Packet->PartitionIndex = ProcIndex;

	    uint8_t *FrameBuffer = xsk_umem__get_data(xsk->umem->buffer, addr);
        // TODO xsk_free_umem_frame if parse error?
        CxPlatDpRawParseEthernet(
            (CXPLAT_DATAPATH*)SocketContext->Binding->Datapath,
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
            // Packet->Queue = Queue;
            Buffers[PacketCount++] = (CXPLAT_RECV_DATA*)Packet;
        } else {
            // CxPlatListPushEntry(&Queue->WorkerRxPool, (CXPLAT_SLIST_ENTRY*)Packet);
        }
	}

	xsk_ring_cons__release(&xsk->rx, rcvd);

    if (rcvd) {
        CxPlatDpRawRxEthernet(
            // (CXPLAT_DATAPATH*)SocketContext->Binding->Datapath,
            SocketContext,
            Buffers,
            (uint16_t)rcvd);
    }
}

void
CxPlatSocketReceive(
    _In_ CXPLAT_SOCKET_CONTEXT* SocketContext
    )
{
    handle_receive_packets(SocketContext);
}

void
CxPlatRecvDataReturn(
    _In_opt_ CXPLAT_RECV_DATA* RecvDataChain
    )
{
    // TODO: release data
    // UNREFERENCED_PARAMETER(RecvDataChain);
    free(RecvDataChain->Route);
    free(RecvDataChain);
    // CxPlatDpRawRxFree((const CXPLAT_RECV_DATA*)RecvDataChain);
    // CXPLAT_RECV_DATA* Datagram;
    // while ((Datagram = RecvDataChain) != NULL) {
    //     RecvDataChain = RecvDataChain->Next;
    //     CXPLAT_RECV_SUBBLOCK* SubBlock =
    //         CXPLAT_CONTAINING_RECORD(Datagram, CXPLAT_RECV_SUBBLOCK, RecvData);
    //     fprintf(stderr, "CxPlatRecvDataReturn %ld\n", SubBlock->RecvBlock->RefCount);
    //     if (InterlockedDecrement(&SubBlock->RecvBlock->RefCount) == 0) {
    //         CxPlatPoolFree(SubBlock->RecvBlock->OwningPool, SubBlock->RecvBlock);
    //     }
    // }
}

//
// Send Path
//

_IRQL_requires_max_(DISPATCH_LEVEL)
_Success_(return != NULL)
CXPLAT_SEND_DATA*
CxPlatSendDataAlloc(
    _In_ CXPLAT_SOCKET* Socket,
    _Inout_ CXPLAT_SEND_CONFIG* Config
    )
{
    // TODO: xsk_ring_prod__reserve

    CXPLAT_DBG_ASSERT(Socket != NULL);
    CXPLAT_DBG_ASSERT(Config->MaxPacketSize <= MAX_UDP_PAYLOAD_LENGTH);
    if (Config->Route->Queue == NULL) {
        Config->Route->Queue = &Socket->SocketContexts[0];
    }

    CXPLAT_SOCKET_CONTEXT* SocketContext = Config->Route->Queue;
    CXPLAT_DBG_ASSERT(SocketContext->Binding == Socket);
    CXPLAT_DBG_ASSERT(SocketContext->Binding->Datapath == SocketContext->DatapathProc->Datapath);
    CXPLAT_SEND_DATA* SendData = CxPlatPoolAlloc(&SocketContext->DatapathProc->SendBlockPool);
    if (SendData != NULL) {
        SendData->SocketContext = SocketContext;

        { //TODO: experimenting block
            QUIC_ADDR RemoteAddress;
            CxPlatSocketGetLocalAddress(Socket, &RemoteAddress);
            if (SocketContext->ActorIdx == 0) { // TODO: better algo, server SocketContext doesn't haveRemoteAddress
                SendData->HeaderOffset = sizeof(struct ethhdr) + sizeof(struct ipv6hdr) + sizeof(struct udphdr);
            } else {
                if (QuicAddrGetFamily(&RemoteAddress) == QUIC_ADDRESS_FAMILY_INET) {
                    SendData->HeaderOffset = sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct udphdr);
                } else {
                    SendData->HeaderOffset = sizeof(struct ethhdr) + sizeof(struct ipv6hdr) + sizeof(struct udphdr);
                }
            }

            CXPLAT_DATAPATH *Datapath = SocketContext->DatapathProc->Datapath;
            struct xsk_socket_info* xsk_info = Datapath->xsk_info[SocketContext->ActorIdx];
            uint32_t tx_idx;
            if (xsk_ring_prod__reserve(&xsk_info->tx, 1, &tx_idx) != 1) {
                return FALSE;
            }
            struct xdp_desc *tx_desc = xsk_ring_prod__tx_desc(&xsk_info->tx, tx_idx);
            void* PacketP = xsk_umem__get_data(xsk_info->umem->buffer, tx_desc->addr);
            SendData->ClientBuffer.Buffer = PacketP + SendData->HeaderOffset;
            SendData->tx_desc = tx_desc;
        }

        SendData->ClientBuffer.Length = 0;
        SendData->TotalSize = 0;
        SendData->SegmentSize = Config->MaxPacketSize;
        SendData->BufferCount = 0;
        SendData->AlreadySentCount = 0;
        SendData->ControlBufferLength = 0;
        SendData->ECN = Config->ECN;
        SendData->Flags = Config->Flags;
        SendData->OnConnectedSocket = Socket->Connected;
        SendData->SegmentationSupported =
            !!(Socket->Datapath->Features & CXPLAT_DATAPATH_FEATURE_SEND_SEGMENTATION);
        SendData->Iovs[0].iov_len = 0;
        SendData->Iovs[0].iov_base = SendData->Buffer;
    }

    return SendData;
}

_IRQL_requires_max_(DISPATCH_LEVEL)
void
CxPlatSendDataFree(
    _In_ CXPLAT_SEND_DATA* SendData
    )
{
    // TODO: tx should be cleaned?
    CxPlatPoolFree(&SendData->SocketContext->DatapathProc->SendBlockPool, SendData);
}

static
void
CxPlatSendDataFinalizeSendBuffer(
    _In_ CXPLAT_SEND_DATA* SendData
    )
{
    if (SendData->ClientBuffer.Length == 0) { // No buffer to finalize.
        return;
    }

    CXPLAT_DBG_ASSERT(SendData->SegmentSize == 0 || SendData->ClientBuffer.Length <= SendData->SegmentSize);
    CXPLAT_DBG_ASSERT(SendData->TotalSize + SendData->ClientBuffer.Length <= sizeof(SendData->Buffer));

    SendData->BufferCount++;
    SendData->TotalSize += SendData->ClientBuffer.Length;
    if (SendData->SegmentationSupported) {
        SendData->Iovs[0].iov_len += SendData->ClientBuffer.Length;
        if (SendData->SegmentSize == 0 ||
            SendData->ClientBuffer.Length < SendData->SegmentSize ||
            SendData->TotalSize + SendData->SegmentSize > sizeof(SendData->Buffer)) {
            SendData->ClientBuffer.Buffer = NULL;
        } else {
            SendData->ClientBuffer.Buffer += SendData->SegmentSize;
        }
    } else {
        struct iovec* IoVec = &SendData->Iovs[SendData->BufferCount - 1];
        IoVec->iov_base = SendData->ClientBuffer.Buffer;
        IoVec->iov_len = SendData->ClientBuffer.Length;
        if (SendData->TotalSize + SendData->SegmentSize > sizeof(SendData->Buffer) ||
            SendData->BufferCount == SendData->SocketContext->DatapathProc->Datapath->SendIoVecCount) {
            SendData->ClientBuffer.Buffer = NULL;
        } else {
            SendData->ClientBuffer.Buffer += SendData->ClientBuffer.Length;
        }
    }
    SendData->ClientBuffer.Length = 0;
}

_IRQL_requires_max_(DISPATCH_LEVEL)
_Success_(return != NULL)
QUIC_BUFFER*
CxPlatSendDataAllocBuffer(
    _In_ CXPLAT_SEND_DATA* SendData,
    _In_ uint16_t MaxBufferLength
    )
{
    // TODO: xsk_umem__alloc
    // TODO: use umem buffer as it is instead of copying in XdpSend

    CXPLAT_DBG_ASSERT(SendData != NULL);
    CXPLAT_DBG_ASSERT(MaxBufferLength > 0);
    CxPlatSendDataFinalizeSendBuffer(SendData);
    CXPLAT_DBG_ASSERT(SendData->SegmentSize == 0 || SendData->SegmentSize >= MaxBufferLength);
    // CXPLAT_DBG_ASSERT(SendData->TotalSize + MaxBufferLength <= sizeof(SendData->Buffer)); // TODO: use umem frame size?
    CXPLAT_DBG_ASSERT(
        SendData->SegmentationSupported ||
        SendData->BufferCount < SendData->SocketContext->DatapathProc->Datapath->SendIoVecCount);
    UNREFERENCED_PARAMETER(MaxBufferLength);
    if (SendData->ClientBuffer.Buffer == NULL) {
        return NULL;
    }
    SendData->ClientBuffer.Length = MaxBufferLength;
    return &SendData->ClientBuffer;
}

_IRQL_requires_max_(DISPATCH_LEVEL)
void
CxPlatSendDataFreeBuffer(
    _In_ CXPLAT_SEND_DATA* SendData,
    _In_ QUIC_BUFFER* Buffer
    )
{
    //
    // This must be the final send buffer; intermediate Iovs cannot be freed.
    //
    CXPLAT_DBG_ASSERT(Buffer == &SendData->ClientBuffer);
    Buffer->Length = 0;
    UNREFERENCED_PARAMETER(SendData);
}

_IRQL_requires_max_(DISPATCH_LEVEL)
BOOLEAN
CxPlatSendDataIsFull(
    _In_ CXPLAT_SEND_DATA* SendData
    )
{
    CxPlatSendDataFinalizeSendBuffer(SendData);
    return SendData->ClientBuffer.Buffer == NULL;
}

QUIC_STATUS
CxPlatSendDataSend(
    _In_ CXPLAT_SEND_DATA* SendData
    );

QUIC_STATUS
CxPlatSocketSend(
    _In_ CXPLAT_SOCKET* Socket,
    _In_ const CXPLAT_ROUTE* Route,
    _In_ CXPLAT_SEND_DATA* SendData
    )
{
    UNREFERENCED_PARAMETER(Socket);

    //
    // Finalize the state of the send data and log the send.
    //
    // CxPlatSendDataFinalizeSendBuffer(SendData);
    QuicTraceEvent(
        DatapathSend,
        "[data][%p] Send %u bytes in %hhu buffers (segment=%hu) Dst=%!ADDR!, Src=%!ADDR!",
        Socket,
        SendData->TotalSize,
        SendData->BufferCount,
        SendData->SegmentSize,
        CASTED_CLOG_BYTEARRAY(sizeof(Route->RemoteAddress), &Route->RemoteAddress),
        CASTED_CLOG_BYTEARRAY(sizeof(Route->LocalAddress), &Route->LocalAddress));

    //
    // Cache the address, mapping the remote address as necessary.
    //
    CxPlatConvertToMappedV6(&Route->RemoteAddress, &SendData->RemoteAddress);
    SendData->LocalAddress = Route->LocalAddress;

    //
    // Check to see if we need to pend because there's already queue.
    //
    BOOLEAN SendPending = FALSE, FlushTxQueue = FALSE;
    CXPLAT_SOCKET_CONTEXT* SocketContext = SendData->SocketContext;
    CxPlatLockAcquire(&SocketContext->TxQueueLock);
    if (/*SendData->Flags & CXPLAT_SEND_FLAGS_MAX_THROUGHPUT ||*/
        !CxPlatListIsEmpty(&SocketContext->TxQueue)) {
        FlushTxQueue = CxPlatListIsEmpty(&SocketContext->TxQueue);
        CxPlatListInsertTail(&SocketContext->TxQueue, &SendData->TxEntry);
        SendPending = TRUE;
    }
    CxPlatLockRelease(&SocketContext->TxQueueLock);
    if (SendPending) {
        if (FlushTxQueue) {
            // TODO: sendto for tx?
            CXPLAT_FRE_ASSERT(
                CxPlatEventQEnqueue(
                    SocketContext->DatapathProc->EventQ,
                    &SocketContext->FlushTxSqe.Sqe,
                    &SocketContext->FlushTxSqe));
        }
        return QUIC_STATUS_SUCCESS;
    }

    //
    // Go ahead and try to send on the socket.
    //
    QUIC_STATUS Status = CxPlatSendDataSend(SendData);
    if (Status == QUIC_STATUS_PENDING) {
        //
        // Couldn't send right now, so queue up the send and wait for send
        // (EPOLLOUT) to be ready.
        //
        CxPlatLockAcquire(&SocketContext->TxQueueLock);
        CxPlatListInsertTail(&SocketContext->TxQueue, &SendData->TxEntry);
        CxPlatLockRelease(&SocketContext->TxQueueLock);
        CxPlatSocketContextSetEvents(SocketContext, EPOLL_CTL_MOD, EPOLLIN | EPOLLOUT);
        Status = QUIC_STATUS_SUCCESS;
    } else {
        CxPlatSendDataFree(SendData);
    }

    return Status;
}

BOOLEAN
XdpSend(
    _In_ CXPLAT_SEND_DATA* SendData
    )
{
    CXPLAT_DATAPATH *Datapath = SendData->SocketContext->DatapathProc->Datapath;
    int ActorIdx = SendData->SocketContext->ActorIdx;
    struct xsk_socket_info* xsk_info = Datapath->xsk_info[ActorIdx];
    QUIC_BUFFER *buffer = &SendData->ClientBuffer;


    fprintf(stderr, "Actor[%d]: should be sending, errno:%d\n", ActorIdx, errno);

    if (framing_packet(buffer->Length,
            macs[ActorIdx], macs[ActorIdx ^ 1],
            &SendData->LocalAddress, &SendData->RemoteAddress,
            SendData->LocalAddress.Ipv4.sin_port, SendData->RemoteAddress.Ipv4.sin_port,
            SendData->ECN,
            (struct ethhdr*) (buffer->Buffer - SendData->HeaderOffset)) != 0) { // TODO: remove pkt_len
        return FALSE;
    }
    uint32_t pkt_len = buffer->Length + SendData->HeaderOffset;

    // Set the packet length and release the TX descriptor
    SendData->tx_desc->len = pkt_len;
    xsk_ring_prod__submit(&xsk_info->tx, 1);

    // TODO: how about move to flush tx
    // Kick the TX
    return sendto(xsk_socket__fd(xsk_info->xsk), NULL, 0, MSG_DONTWAIT, NULL, 0) >= 0;
}

QUIC_STATUS
CxPlatSendDataSend(
    _In_ CXPLAT_SEND_DATA* SendData
    )
{
    CXPLAT_DBG_ASSERT(SendData != NULL);
    CXPLAT_DBG_ASSERT(SendData->AlreadySentCount < CXPLAT_MAX_IO_BATCH_SIZE);

    QUIC_STATUS Status = QUIC_STATUS_SUCCESS;
    CXPLAT_SOCKET_CONTEXT* SocketContext = SendData->SocketContext;
    BOOLEAN Success = XdpSend(SendData);
    if (!Success) {
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            Status = QUIC_STATUS_PENDING;
        } else {
            Status = errno;
            QuicTraceEvent(
                DatapathErrorStatus,
                "[data][%p] ERROR, %u, %s.",
                SocketContext->Binding,
                Status,
                "sendmmsg failed");

            //
            // Unreachable events can sometimes come synchronously.
            // Send unreachable notification to MsQuic if any related
            // errors were received.
            //
            if (Status == ECONNREFUSED ||
                Status == EHOSTUNREACH ||
                Status == ENETUNREACH) {
                if (!SocketContext->Binding->PcpBinding) {
                    SocketContext->Binding->Datapath->UdpHandlers.Unreachable(
                        SocketContext->Binding,
                        SocketContext->Binding->ClientContext,
                        &SocketContext->Binding->RemoteAddress);
                }
            }
        }
    }

    return Status;
}

//
// Returns TRUE if the queue was completely drained, and FALSE if there are
// still pending sends.
//
void
CxPlatSocketContextFlushTxQueue(
    _In_ CXPLAT_SOCKET_CONTEXT* SocketContext,
    _In_ BOOLEAN SendAlreadyPending
    )
{
    CXPLAT_SEND_DATA* SendData = NULL;
    CxPlatLockAcquire(&SocketContext->TxQueueLock);
    if (!CxPlatListIsEmpty(&SocketContext->TxQueue)) {
        SendData =
            CXPLAT_CONTAINING_RECORD(
                SocketContext->TxQueue.Flink,
                CXPLAT_SEND_DATA,
                TxEntry);
    }
    CxPlatLockRelease(&SocketContext->TxQueueLock);

    while (SendData != NULL) {
        if (CxPlatSendDataSend(SendData) == QUIC_STATUS_PENDING) {
            if (!SendAlreadyPending) {
                //
                // Add the EPOLLOUT event since we have more pending sends.
                //
                CxPlatSocketContextSetEvents(SocketContext, EPOLL_CTL_MOD, EPOLLIN | EPOLLOUT);
            }
            return;
        }

        // TODO: maybe this does not work for xdp
        //       normal socket copy data buffer to kernel, so user level buffer can be freed
        //       xdp requires to watch Cq then free.
        CxPlatLockAcquire(&SocketContext->TxQueueLock);
        CxPlatListRemoveHead(&SocketContext->TxQueue);
        CxPlatSendDataFree(SendData);
        if (!CxPlatListIsEmpty(&SocketContext->TxQueue)) {
            SendData =
                CXPLAT_CONTAINING_RECORD(
                    SocketContext->TxQueue.Flink,
                    CXPLAT_SEND_DATA,
                    TxEntry);
        } else {
            SendData = NULL;
        }
        CxPlatLockRelease(&SocketContext->TxQueueLock);
    }

    if (SendAlreadyPending) {
        //
        // Remove the EPOLLOUT event since we don't have any more pending sends.
        //
        CxPlatSocketContextSetEvents(SocketContext, EPOLL_CTL_MOD, EPOLLIN);
    }
}

void
CxPlatDataPathSocketProcessIoCompletion(
    _In_ CXPLAT_SOCKET_CONTEXT* SocketContext,
    _In_ CXPLAT_CQE* Cqe
    )
{
    if (CxPlatRundownAcquire(&SocketContext->UpcallRundown)) {
        if (EPOLLERR & Cqe->events) {
            CxPlatSocketHandleErrors(SocketContext);
        }
        if (EPOLLIN & Cqe->events) {
            CxPlatSocketReceive(SocketContext);
        }
        if (EPOLLOUT & Cqe->events) {
            CxPlatSocketContextFlushTxQueue(SocketContext, TRUE);
        }
        CxPlatRundownRelease(&SocketContext->UpcallRundown);
    }
}

void
CxPlatDataPathProcessCqe(
    _In_ CXPLAT_CQE* Cqe
    )
{
    switch (CxPlatCqeType(Cqe)) {
    case CXPLAT_CQE_TYPE_SOCKET_SHUTDOWN: {
        CXPLAT_SOCKET_CONTEXT* SocketContext =
            CXPLAT_CONTAINING_RECORD(CxPlatCqeUserData(Cqe), CXPLAT_SOCKET_CONTEXT, ShutdownSqe);
        CxPlatSocketContextUninitializeComplete(SocketContext);
        break;
    }
    case CXPLAT_CQE_TYPE_SOCKET_IO: {
        CXPLAT_SOCKET_CONTEXT* SocketContext =
            CXPLAT_CONTAINING_RECORD(CxPlatCqeUserData(Cqe), CXPLAT_SOCKET_CONTEXT, IoSqe);
        CxPlatDataPathSocketProcessIoCompletion(SocketContext, Cqe);
        break;
    }
    case CXPLAT_CQE_TYPE_SOCKET_FLUSH_TX: {
        CXPLAT_SOCKET_CONTEXT* SocketContext =
            CXPLAT_CONTAINING_RECORD(CxPlatCqeUserData(Cqe), CXPLAT_SOCKET_CONTEXT, FlushTxSqe);
        CxPlatSocketContextFlushTxQueue(SocketContext, FALSE);
        break;
    }
    }
}
