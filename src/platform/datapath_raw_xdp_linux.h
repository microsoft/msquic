/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.

--*/

#include "platform_internal.h"
#include "datapath_raw_xdp.h"
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <bpf/xsk.h>
#include <ifaddrs.h>
#include <net/if.h>
#include <linux/if_link.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <netinet/in.h>

#define NUM_FRAMES         4096
#define CONS_NUM_DESCS     XSK_RING_CONS__DEFAULT_NUM_DESCS
#define PROD_NUM_DESCS     XSK_RING_PROD__DEFAULT_NUM_DESCS
#define FRAME_SIZE         XSK_UMEM__DEFAULT_FRAME_SIZE // TODO: 2K mode
#define INVALID_UMEM_FRAME UINT64_MAX

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
    uint32_t RxHeadRoom;
    uint32_t TxHeadRoom;
};

typedef struct XDP_DATAPATH {
    CXPLAT_DATAPATH;
    __attribute__((aligned(64)))
    //
    // Currently, all XDP interfaces share the same config.
    //
    CXPLAT_REF_COUNT RefCount;
    uint32_t WorkerCount;
    uint32_t RxBufferCount; // TODO: remove
    uint32_t RxRingSize;
    uint32_t TxBufferCount; // TODO: remove
    uint32_t TxRingSize;
    uint32_t BufferCount;

    uint32_t PollingIdleTimeoutUs;
    BOOLEAN TxAlwaysPoke;
    BOOLEAN SkipXsum;
    BOOLEAN Running;        // Signal to stop workers.
    // const XDP_API_TABLE *XdpApi;

    XDP_WORKER Workers[0];
} XDP_DATAPATH;

typedef struct XDP_INTERFACE {
    CXPLAT_INTERFACE;
    uint16_t QueueCount;
    uint8_t RuleCount;
    CXPLAT_LOCK RuleLock;
    // XDP_RULE* Rules;
    XDP_QUEUE* Queues; // An array of queues.
    const struct XDP_DATAPATH* Xdp;
    //const char* IfName;
} XDP_INTERFACE;

typedef struct XDP_QUEUE {
    const XDP_INTERFACE* Interface;
    XDP_WORKER* Worker;
    struct XDP_QUEUE* Next;
    uint8_t* RxBuffers;
    // HANDLE RxXsk;
    DATAPATH_SQE RxIoSqe; // DATAPATH_IO_SQE?
    // XSK_RING RxFillRing;
    // XSK_RING RxRing;
    // HANDLE RxProgram;
    uint8_t* TxBuffers;
    // HANDLE TxXsk;
    DATAPATH_IO_SQE TxIoSqe;
    // XSK_RING TxRing;
    // XSK_RING TxCompletionRing;
    BOOLEAN RxQueued;
    BOOLEAN TxQueued;
    BOOLEAN Error;

    CXPLAT_LIST_ENTRY WorkerTxQueue;
    CXPLAT_SLIST_ENTRY WorkerRxPool;

    // Move contended buffer pools to their own cache lines.
    // TODO: Use better (more scalable) buffer algorithms.
    // DECLSPEC_CACHEALIGN SLIST_HEADER RxPool;
    CXPLAT_LIST_ENTRY TxPool;

    // Move TX queue to its own cache line.
    // DECLSPEC_CACHEALIGN
    CXPLAT_LOCK TxLock;
    CXPLAT_LIST_ENTRY TxQueue;

    // TODO: temporally. could be replaced by TxPool implementation
    struct xsk_socket_info* xsk_info;
} XDP_QUEUE;

// -> CxPlat
typedef struct __attribute__((aligned(64))) XDP_RX_PACKET {
    CXPLAT_RECV_DATA;
    CXPLAT_ROUTE RouteStorage;
    XDP_QUEUE* Queue;
    uint64_t addr;
    // Followed by:
    // uint8_t ClientContext[...];
    // uint8_t FrameBuffer[MAX_ETH_FRAME_SIZE];
} XDP_RX_PACKET;

typedef struct __attribute__((aligned(64))) XDP_TX_PACKET {
    CXPLAT_SEND_DATA;
    struct xdp_desc *tx_desc; // TODO: here?
    XDP_QUEUE* Queue;
    CXPLAT_LIST_ENTRY Link;
    uint8_t FrameBuffer[MAX_ETH_FRAME_SIZE];
} XDP_TX_PACKET;