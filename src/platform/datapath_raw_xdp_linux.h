/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.

--*/

#include "platform_internal.h"
#include "datapath_raw_xdp.h"
// #include <bpf/bpf.h>
// #include <bpf/libbpf.h>
// #include <bpf/xsk.h>
#include "libbpf.h"
#include "bpf.h"
#include "xsk.h"
#include "libxdp.h"
#include <linux/sockios.h>
#include <linux/ethtool.h>
#include <netpacket/packet.h>

#define NUM_FRAMES         8192 * 2
#define CONS_NUM_DESCS     NUM_FRAMES / 2
#define PROD_NUM_DESCS     NUM_FRAMES / 2
#define FRAME_SIZE         XSK_UMEM__DEFAULT_FRAME_SIZE // TODO: 2K mode
#define INVALID_UMEM_FRAME UINT64_MAX

struct xsk_socket_info {
    struct xsk_ring_cons rx;
    struct xsk_ring_prod tx;
    struct xsk_umem_info *umem;
    struct xsk_socket *xsk;

    CXPLAT_LOCK UmemLock;
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
    uint32_t PartitionCount;
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

    XDP_PARTITION Partitions[0];
} XDP_DATAPATH;

typedef struct XDP_INTERFACE {
    CXPLAT_INTERFACE;
    uint16_t QueueCount;
    XDP_QUEUE* Queues; // An array of queues.
    const struct XDP_DATAPATH* Xdp;
    struct xsk_socket_config *XskCfg;
    struct bpf_object *BpfObj;
    struct xdp_program *XdpProg;
    char IfName[IFNAMSIZ];
} XDP_INTERFACE;

typedef struct XDP_QUEUE {
    const XDP_INTERFACE* Interface;
    XDP_PARTITION* Partition;
    struct XDP_QUEUE* Next;
    DATAPATH_SQE RxIoSqe;
    DATAPATH_IO_SQE TxIoSqe;
    BOOLEAN RxQueued;
    BOOLEAN TxQueued;
    BOOLEAN Error;

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

    struct xsk_socket_info* xsk_info;
} XDP_QUEUE;

// -> CxPlat
typedef struct __attribute__((aligned(64))) XDP_RX_PACKET {
    XDP_QUEUE* Queue;
    CXPLAT_ROUTE RouteStorage;
    uint64_t addr;
    CXPLAT_RECV_DATA RecvData;
    // Followed by:
    // uint8_t ClientContext[...];
    // uint8_t FrameBuffer[MAX_ETH_FRAME_SIZE];
} XDP_RX_PACKET;

typedef struct __attribute__((aligned(64))) XDP_TX_PACKET {
    CXPLAT_SEND_DATA;
    uint64_t UmemRelativeAddr;
    XDP_QUEUE* Queue;
    CXPLAT_LIST_ENTRY Link;
    uint8_t FrameBuffer[MAX_ETH_FRAME_SIZE];
} XDP_TX_PACKET;