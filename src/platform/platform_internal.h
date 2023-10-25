/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.

--*/

#pragma once

#pragma warning(disable:28922) // Redundant Pointer Test
#pragma warning(disable:26451) // Arithmetic overflow: Using operator '+' on a 4 byte value and then casting the result to a 8 byte value.

#define QUIC_API_ENABLE_PREVIEW_FEATURES 1

#include "quic_platform.h"
#include "quic_datapath.h"
#include "quic_pcp.h"
#include "quic_storage.h"
#include "quic_tls.h"
#include "quic_versions.h"
#include "quic_trace.h"

#include "msquic.h"
#include "msquicp.h"

// Must be included after msquic.h for QUIC_CERTIFICATE_FLAGS
#include "quic_cert.h"

#ifdef QUIC_FUZZER
#include "msquic_fuzz.h"

#define QUIC_DISABLED_BY_FUZZER_START if (!MsQuicFuzzerContext.RedirectDataPath) {
#define QUIC_DISABLED_BY_FUZZER_END }

#else

#define QUIC_DISABLED_BY_FUZZER_START
#define QUIC_DISABLED_BY_FUZZER_END

#endif

typedef struct DATAPATH_SQE {
    uint32_t CqeType;
#ifdef CXPLAT_SQE
    CXPLAT_SQE Sqe;
#endif
} DATAPATH_SQE;

typedef struct CXPLAT_DATAPATH_COMMON {
    //
    // The UDP callback function pointers.
    //
    CXPLAT_UDP_DATAPATH_CALLBACKS UdpHandlers;

    //
    // The TCP callback function pointers.
    //
    CXPLAT_TCP_DATAPATH_CALLBACKS TcpHandlers;
} CXPLAT_DATAPATH_COMMON;

typedef struct CXPLAT_SOCKET_COMMON {
    //
    // The local address and port.
    //
    QUIC_ADDR LocalAddress;

    //
    // The remote address and port.
    //
    QUIC_ADDR RemoteAddress;
} CXPLAT_SOCKET_COMMON;

typedef struct CXPLAT_SEND_DATA_COMMON {
    uint16_t DatapathType; // CXPLAT_DATAPATH_TYPE

    //
    // The type of ECN markings needed for send.
    //
    uint8_t ECN; // CXPLAT_ECN_TYPE
} CXPLAT_SEND_DATA_COMMON;

typedef enum CXPLAT_DATAPATH_TYPE {
    CXPLAT_DATAPATH_TYPE_UNKNOWN = 0,
    CXPLAT_DATAPATH_TYPE_USER,
    CXPLAT_DATAPATH_TYPE_RAW, // currently raw == xdp
} CXPLAT_DATAPATH_TYPE;

//
// Type of IO.
//
typedef enum DATAPATH_IO_TYPE {
    DATAPATH_IO_SIGNATURE         = 'WINU',
    DATAPATH_IO_RECV              = DATAPATH_IO_SIGNATURE + 1,
    DATAPATH_IO_SEND              = DATAPATH_IO_SIGNATURE + 2,
    DATAPATH_IO_QUEUE_SEND        = DATAPATH_IO_SIGNATURE + 3,
    DATAPATH_IO_ACCEPTEX          = DATAPATH_IO_SIGNATURE + 4,
    DATAPATH_IO_CONNECTEX         = DATAPATH_IO_SIGNATURE + 5,
    DATAPATH_IO_RIO_NOTIFY        = DATAPATH_IO_SIGNATURE + 6,
    DATAPATH_IO_RIO_RECV          = DATAPATH_IO_SIGNATURE + 7,
    DATAPATH_IO_RIO_SEND          = DATAPATH_IO_SIGNATURE + 8,
    DATAPATH_IO_RECV_FAILURE      = DATAPATH_IO_SIGNATURE + 9,
    DATAPATH_IO_MAX
} DATAPATH_IO_TYPE;

//
// Type of IO for XDP.
//
typedef enum DATAPATH_XDP_IO_TYPE {
    DATAPATH_XDP_IO_SIGNATURE         = 'XDPD',
    DATAPATH_XDP_IO_RECV              = DATAPATH_XDP_IO_SIGNATURE + 1,
    DATAPATH_XDP_IO_SEND              = DATAPATH_XDP_IO_SIGNATURE + 2
} DATAPATH_XDP_IO_TYPE;

//
// IO header for SQE->CQE based completions.
//
typedef struct DATAPATH_IO_SQE {
    DATAPATH_IO_TYPE IoType;
    DATAPATH_SQE DatapathSqe;
} DATAPATH_IO_SQE;

typedef enum CXPLAT_SOCKET_TYPE {
    CXPLAT_SOCKET_UDP             = 0,
    CXPLAT_SOCKET_TCP_LISTENER    = 1,
    CXPLAT_SOCKET_TCP             = 2,
    CXPLAT_SOCKET_TCP_SERVER      = 3
} CXPLAT_SOCKET_TYPE;

#ifdef _KERNEL_MODE

#define CXPLAT_BASE_REG_PATH L"\\Registry\\Machine\\System\\CurrentControlSet\\Services\\MsQuic\\Parameters\\"

typedef struct CX_PLATFORM {

    //
    // Random number algorithm loaded for DISPATCH_LEVEL usage.
    //
    BCRYPT_ALG_HANDLE RngAlgorithm;

#ifdef DEBUG
    //
    // 1/Denominator of allocations to fail.
    // Negative is Nth allocation to fail.
    //
    int32_t AllocFailDenominator;

    //
    // Count of allocations.
    //
    long AllocCounter;
#endif

} CX_PLATFORM;

#elif _WIN32

#pragma warning(push)
#pragma warning(disable:6385) // Invalid data: accessing [buffer-name], the readable size is size1 bytes but size2 bytes may be read
#pragma warning(disable:6101) // Returning uninitialized memory
#include <ws2tcpip.h>
#include <mstcpip.h>
#pragma warning(pop)

#include <mswsock.h>

#if DEBUG
#include <crtdbg.h>
#endif

#define CXPLAT_BASE_REG_PATH "System\\CurrentControlSet\\Services\\MsQuic\\Parameters\\"

typedef struct CX_PLATFORM {

    //
    // Heap used for all allocations.
    //
    HANDLE Heap;

#ifdef DEBUG
    //
    // 1/Denominator of allocations to fail.
    // Negative is Nth allocation to fail.
    //
    int32_t AllocFailDenominator;

    //
    // Count of allocations.
    //
    long AllocCounter;
#endif

} CX_PLATFORM;

//
// Represents a single IO completion port and thread for processing work that is
// completed on a single processor.
//
typedef struct QUIC_CACHEALIGN CXPLAT_DATAPATH_PROC {

    //
    // Parent datapath.
    //
    CXPLAT_DATAPATH* Datapath;

    //
    // Event queue used for processing work.
    //
    CXPLAT_EVENTQ* EventQ;

    //
    // Used to synchronize clean up.
    //
    CXPLAT_REF_COUNT RefCount;

    //
    // The index into the execution config processor array.
    //
    uint16_t PartitionIndex;

    //
    // Debug flags
    //
    uint8_t Uninitialized : 1;

    //
    // Pool of send contexts to be shared by all sockets on this core.
    //
    CXPLAT_POOL SendDataPool;

    //
    // Pool of send contexts to be shared by all RIO sockets on this core.
    //
    CXPLAT_POOL RioSendDataPool;

    //
    // Pool of send buffers to be shared by all sockets on this core.
    //
    CXPLAT_POOL SendBufferPool;

    //
    // Pool of large segmented send buffers to be shared by all sockets on this
    // core.
    //
    CXPLAT_POOL LargeSendBufferPool;

    //
    // Pool of send buffers to be shared by all RIO sockets on this core.
    //
    CXPLAT_POOL RioSendBufferPool;

    //
    // Pool of large segmented send buffers to be shared by all RIO sockets on
    // this core.
    //
    CXPLAT_POOL RioLargeSendBufferPool;

    //
    // Pool of receive datagram contexts and buffers to be shared by all sockets
    // on this core.
    //
    CXPLAT_POOL RecvDatagramPool;

    //
    // Pool of RIO receive datagram contexts and buffers to be shared by all
    // RIO sockets on this core.
    //
    CXPLAT_POOL RioRecvPool;

} CXPLAT_DATAPATH_PARTITION;

//
// Per-processor socket state.
//
typedef struct QUIC_CACHEALIGN CXPLAT_SOCKET_PROC {
    //
    // Used to synchronize clean up.
    //
    CXPLAT_REF_COUNT RefCount;

    //
    // Submission queue event for IO completion
    //
    DATAPATH_IO_SQE IoSqe;

    //
    // Submission queue event for RIO IO completion
    //
    DATAPATH_IO_SQE RioSqe;

    //
    // The datapath per-processor context.
    //
    CXPLAT_DATAPATH_PARTITION* DatapathProc;

    //
    // Parent CXPLAT_SOCKET.
    //
    CXPLAT_SOCKET* Parent;

    //
    // Socket handle to the networking stack.
    //
    SOCKET Socket;

    //
    // Rundown for synchronizing upcalls to the app and downcalls on the Socket.
    //
    CXPLAT_RUNDOWN_REF RundownRef;

    //
    // Flag indicates the socket started processing IO.
    //
    BOOLEAN IoStarted : 1;

    //
    // Flag indicates a persistent out-of-memory failure for the receive path.
    //
    BOOLEAN RecvFailure : 1;

    //
    // Debug Flags
    //
    uint8_t Uninitialized : 1;
    uint8_t Freed : 1;

    //
    // The set of parameters/state passed to WsaRecvMsg for the IP stack to
    // populate to indicate the result of the receive.
    //

    union {
    //
    // Normal TCP/UDP socket data
    //
    struct {
    RIO_CQ RioCq;
    RIO_RQ RioRq;
    ULONG RioRecvCount;
    ULONG RioSendCount;
    CXPLAT_LIST_ENTRY RioSendOverflow;
    BOOLEAN RioNotifyArmed;
    };
    //
    // TCP Listener socket data
    //
    struct {
    CXPLAT_SOCKET* AcceptSocket;
    char AcceptAddrSpace[
        sizeof(SOCKADDR_INET) + 16 +
        sizeof(SOCKADDR_INET) + 16
        ];
    };
    };
} CXPLAT_SOCKET_PROC;

//
// Main structure for tracking all UDP abstractions.
//
typedef struct CXPLAT_DATAPATH {
    CXPLAT_DATAPATH_COMMON;

    //
    // Function pointer to AcceptEx.
    //
    LPFN_ACCEPTEX AcceptEx;

    //
    // Function pointer to ConnectEx.
    //
    LPFN_CONNECTEX ConnectEx;

    //
    // Function pointer to WSASendMsg.
    //
    LPFN_WSASENDMSG WSASendMsg;

    //
    // Function pointer to WSARecvMsg.
    //
    LPFN_WSARECVMSG WSARecvMsg;

    //
    // Function pointer table for RIO.
    //
    RIO_EXTENSION_FUNCTION_TABLE RioDispatch;

    //
    // Used to synchronize clean up.
    //
    CXPLAT_REF_COUNT RefCount;

    //
    // Set of supported features.
    //
    uint32_t Features;

    //
    // The size of each receive datagram array element, including client context,
    // internal context, and padding.
    //
    uint32_t DatagramStride;

    //
    // The offset of the receive payload buffer from the start of the receive
    // context.
    //
    uint32_t RecvPayloadOffset;

    //
    // The number of processors.
    //
    uint16_t PartitionCount;

    //
    // Maximum batch sizes supported for send.
    //
    uint8_t MaxSendBatchSize;

    //
    // Uses RIO interface instead of normal asyc IO.
    //
    uint8_t UseRio : 1;

    //
    // Debug flags
    //
    uint8_t Uninitialized : 1;
    uint8_t Freed : 1;

    uint8_t UseTcp : 1;

    CXPLAT_DATAPATH_RAW* RawDataPath;

    //
    // Per-processor completion contexts.
    //
    CXPLAT_DATAPATH_PARTITION Partitions[0];

} CXPLAT_DATAPATH;

//
// Per-port state. Multiple sockets are created on each port.
//
typedef struct CXPLAT_SOCKET {
    CXPLAT_SOCKET_COMMON;

    //
    // Parent datapath.
    //
    // CXPLAT_DATAPATH_BASE* Datapath;
    CXPLAT_DATAPATH* Datapath;

    //
    // Client context pointer.
    //
    void *ClientContext;

    //
    // Synchronization mechanism for cleanup.
    //
    CXPLAT_REF_COUNT RefCount;

    //
    // The size of a receive buffer's payload.
    //
    uint32_t RecvBufLen;

    //
    // The local interface's MTU.
    //
    uint16_t Mtu;

    //
    // Indicates the binding connected to a remote IP address.
    //
    BOOLEAN Connected : 1;

    //
    // Socket type.
    //
    uint8_t Type : 2; // CXPLAT_SOCKET_TYPE

    //
    // Flag indicates the socket has more than one socket, affinitized to all
    // the processors.
    //
    uint16_t NumPerProcessorSockets : 1;

    //
    // Flag indicates the socket has a default remote destination.
    //
    uint8_t HasFixedRemoteAddress : 1;

    //
    // Flag indicates the socket indicated a disconnect event.
    //
    uint8_t DisconnectIndicated : 1;

    //
    // Flag indicates the binding is being used for PCP.
    //
    uint8_t PcpBinding : 1;

    //
    // Flag indicates the socket is using RIO instead of traditional Winsock.
    //
    uint8_t UseRio : 1;

    //
    // Debug flags.
    //
    uint8_t Uninitialized : 1;
    uint8_t Freed : 1;

    uint8_t UseTcp : 1;                  // Quic over TCP

    uint8_t RawSocketAvailable : 1;

    //
    // Per-processor socket contexts.
    //
    CXPLAT_SOCKET_PROC PerProcSockets[0];

} CXPLAT_SOCKET;

#elif defined(CX_PLATFORM_LINUX) || defined(CX_PLATFORM_DARWIN)

typedef struct CX_PLATFORM {

    void* Reserved; // Nothing right now.

#ifdef DEBUG
    //
    // 1/Denominator of allocations to fail.
    // Negative is Nth allocation to fail.
    //
    int32_t AllocFailDenominator;

    //
    // Count of allocations.
    //
    long AllocCounter;
#endif

} CX_PLATFORM;

#else

#error "Unsupported Platform"

#endif

#pragma warning(disable:4204)  // nonstandard extension used: non-constant aggregate initializer
#pragma warning(disable:4200)  // nonstandard extension used: zero-sized array in struct/union

//
// Global Platform variables/state.
//
extern CX_PLATFORM CxPlatform;

//
// PCP Receive Callback
//
CXPLAT_DATAPATH_RECEIVE_CALLBACK CxPlatPcpRecvCallback;

#if _WIN32 // Some Windows Helpers

//
// Converts IPv6 or IPV4 address to a (possibly mapped) IPv6.
//
inline
void
CxPlatConvertToMappedV6(
    _In_ const QUIC_ADDR* InAddr,
    _Out_ QUIC_ADDR* OutAddr
    )
{
    if (InAddr->si_family == QUIC_ADDRESS_FAMILY_INET) {
        SCOPE_ID unspecified_scope = {0};
        IN6ADDR_SETV4MAPPED(
            &OutAddr->Ipv6,
            &InAddr->Ipv4.sin_addr,
            unspecified_scope,
            InAddr->Ipv4.sin_port);
    } else {
        *OutAddr = *InAddr;
    }
}

//
// Converts (possibly mapped) IPv6 address to a IPv6 or IPV4 address. Does
// support InAdrr == OutAddr.
//
#pragma warning(push)
#pragma warning(disable: 6101) // Intentially don't overwrite output if unable to convert
inline
void
CxPlatConvertFromMappedV6(
    _In_ const QUIC_ADDR* InAddr,
    _Out_ QUIC_ADDR* OutAddr
    )
{
    CXPLAT_DBG_ASSERT(InAddr->si_family == QUIC_ADDRESS_FAMILY_INET6);
    if (IN6_IS_ADDR_V4MAPPED(&InAddr->Ipv6.sin6_addr)) {
        OutAddr->si_family = QUIC_ADDRESS_FAMILY_INET;
        OutAddr->Ipv4.sin_port = InAddr->Ipv6.sin6_port;
        OutAddr->Ipv4.sin_addr =
            *(IN_ADDR UNALIGNED *)
            IN6_GET_ADDR_V4MAPPED(&InAddr->Ipv6.sin6_addr);
    } else if (OutAddr != InAddr) {
        *OutAddr = *InAddr;
    }
}
#pragma warning(pop)

#endif

//
// Crypt Initialization
//

QUIC_STATUS
CxPlatCryptInitialize(
    void
    );

void
CxPlatCryptUninitialize(
    void
    );

//
// Platform Worker APIs
//

void
CxPlatWorkersInit(
    void
    );

void
CxPlatWorkersUninit(
    void
    );

BOOLEAN
CxPlatWorkersLazyStart(
    _In_opt_ QUIC_EXECUTION_CONFIG* Config
    );

CXPLAT_EVENTQ*
CxPlatWorkerGetEventQ(
    _In_ uint16_t Index // Into the config processor array
    );

void
CxPlatDataPathProcessCqe(
    _In_ CXPLAT_CQE* Cqe
    );

BOOLEAN // Returns FALSE no work was done.
CxPlatDataPathPoll(
    _In_ void* Context,
    _Out_ BOOLEAN* RemoveFromPolling
    );

//
// Queries the raw datapath stack for the total size needed to allocate the
// datapath structure.
//
_IRQL_requires_max_(PASSIVE_LEVEL)
size_t
CxPlatDpRawGetDatapathSize(
    _In_opt_ const QUIC_EXECUTION_CONFIG* Config
    );

#define CXPLAT_CQE_TYPE_WORKER_WAKE         CXPLAT_CQE_TYPE_QUIC_BASE + 1
#define CXPLAT_CQE_TYPE_WORKER_UPDATE_POLL  CXPLAT_CQE_TYPE_QUIC_BASE + 2
#define CXPLAT_CQE_TYPE_SOCKET_SHUTDOWN     CXPLAT_CQE_TYPE_QUIC_BASE + 3
#define CXPLAT_CQE_TYPE_SOCKET_IO           CXPLAT_CQE_TYPE_QUIC_BASE + 4
#define CXPLAT_CQE_TYPE_SOCKET_FLUSH_TX     CXPLAT_CQE_TYPE_QUIC_BASE + 5

extern CXPLAT_RUNDOWN_REF CxPlatWorkerRundown;

#if defined(CX_PLATFORM_LINUX)

typedef struct CXPLAT_DATAPATH_PARTITION CXPLAT_DATAPATH_PARTITION;

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
    CXPLAT_DATAPATH_PARTITION* DatapathPartition;

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

    CXPLAT_SOCKET* AcceptSocket;

} CXPLAT_SOCKET_CONTEXT;

//
// Datapath binding.
//
typedef struct CXPLAT_SOCKET {
    CXPLAT_SOCKET_COMMON;

    //
    // A pointer to datapath object.
    //
    CXPLAT_DATAPATH* Datapath;

    //
    // The client context for this binding.
    //
    void *ClientContext;

    //
    // Synchronization mechanism for cleanup.
    //
    CXPLAT_REF_COUNT RefCount;

    //
    // The MTU for this binding.
    //
    uint16_t Mtu;

    //
    // The size of a receive buffer's payload.
    //
    uint32_t RecvBufLen;

    //
    // Indicates the binding connected to a remote IP address.
    //
    BOOLEAN Connected : 1;

    //
    // Socket type.
    //
    uint8_t Type : 2; // CXPLAT_SOCKET_TYPE

    //
    // Flag indicates the socket has more than one socket, affinitized to all
    // the processors.
    //
    uint8_t NumPerProcessorSockets : 1;

    //
    // Flag indicates the socket has a default remote destination.
    //
    BOOLEAN HasFixedRemoteAddress : 1;

    //
    // Flag indicates the socket indicated a disconnect event.
    //
    uint8_t DisconnectIndicated : 1;

    //
    // Flag indicates the binding is being used for PCP.
    //
    BOOLEAN PcpBinding : 1;

#if DEBUG
    uint8_t Uninitialized : 1;
    uint8_t Freed : 1;
#endif

    uint8_t UseTcp : 1;                  // Quic over TCP

    //
    // Set of socket contexts one per proc.
    //
    CXPLAT_SOCKET_CONTEXT SocketContexts[];

} CXPLAT_SOCKET;

//
// A per processor datapath context.
//
typedef struct QUIC_CACHEALIGN CXPLAT_DATAPATH_PARTITION {

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
    uint16_t PartitionIndex;

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

} CXPLAT_DATAPATH_PARTITION;

//
// Represents a datapath object.
//

typedef struct CXPLAT_DATAPATH {
    CXPLAT_DATAPATH_COMMON;

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
    uint32_t PartitionCount;

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
    // The length of the CXPLAT_RECV_DATA and client data part of the
    // DATAPATH_RX_IO_BLOCK.
    //
    uint32_t RecvBlockStride;

    //
    // The offset of the raw buffer in the DATAPATH_RX_IO_BLOCK.
    //
    uint32_t RecvBlockBufferOffset;

    //
    // The total length of the DATAPATH_RX_IO_BLOCK. Calculated based on the
    // support level for GRO. No GRO only uses a single CXPLAT_RECV_DATA and
    // client data, while GRO allows for multiple.
    //
    uint32_t RecvBlockSize;

#if DEBUG
    uint8_t Uninitialized : 1;
    uint8_t Freed : 1;
#endif

    //
    // The per proc datapath contexts.
    //
    CXPLAT_DATAPATH_PARTITION Partitions[];

} CXPLAT_DATAPATH;

#endif // CX_PLATFORM_LINUX

#if defined(CX_PLATFORM_LINUX) || _WIN32

typedef struct CXPLAT_SOCKET_RAW CXPLAT_SOCKET_RAW;

_IRQL_requires_max_(PASSIVE_LEVEL)
QUIC_STATUS
SocketCreateUdp(
    _In_ CXPLAT_DATAPATH* DataPath,
    _In_ const CXPLAT_UDP_CONFIG* Config,
    _Out_ CXPLAT_SOCKET** NewSocket
    );

_IRQL_requires_max_(PASSIVE_LEVEL)
QUIC_STATUS
SocketCreateTcp(
    _In_ CXPLAT_DATAPATH* Datapath,
    _In_opt_ const QUIC_ADDR* LocalAddress,
    _In_ const QUIC_ADDR* RemoteAddress,
    _In_opt_ void* CallbackContext,
    _Out_ CXPLAT_SOCKET** Socket
    );

_IRQL_requires_max_(PASSIVE_LEVEL)
QUIC_STATUS
SocketCreateTcpListener(
    _In_ CXPLAT_DATAPATH* Datapath,
    _In_opt_ const QUIC_ADDR* LocalAddress,
    _In_opt_ void* RecvCallbackContext,
    _Out_ CXPLAT_SOCKET** NewSocket
    );

_IRQL_requires_max_(PASSIVE_LEVEL)
void
SocketDelete(
    _In_ CXPLAT_SOCKET* Socket
    );

_IRQL_requires_max_(PASSIVE_LEVEL)
QUIC_STATUS
DataPathInitialize(
    _In_ uint32_t ClientRecvDataLength,
    _In_opt_ const CXPLAT_UDP_DATAPATH_CALLBACKS* UdpCallbacks,
    _In_opt_ const CXPLAT_TCP_DATAPATH_CALLBACKS* TcpCallbacks,
    _In_opt_ QUIC_EXECUTION_CONFIG* Config,
    _Out_ CXPLAT_DATAPATH** NewDatapath
    );

_IRQL_requires_max_(PASSIVE_LEVEL)
void
DataPathUninitialize(
    _In_ CXPLAT_DATAPATH* Datapath
    );

_IRQL_requires_max_(PASSIVE_LEVEL)
void
DataPathUpdateConfig(
    _In_ CXPLAT_DATAPATH* Datapath,
    _In_ QUIC_EXECUTION_CONFIG* Config
    );

_IRQL_requires_max_(DISPATCH_LEVEL)
uint32_t
DataPathGetSupportedFeatures(
    _In_ CXPLAT_DATAPATH* Datapath
    );

_IRQL_requires_max_(DISPATCH_LEVEL)
BOOLEAN
DataPathIsPaddingPreferred(
    _In_ CXPLAT_DATAPATH* Datapath
    );

_IRQL_requires_max_(DISPATCH_LEVEL)
void
RecvDataReturn(
    _In_ CXPLAT_RECV_DATA* RecvDataChain
    );

_IRQL_requires_max_(DISPATCH_LEVEL)
_Success_(return != NULL)
CXPLAT_SEND_DATA*
SendDataAlloc(
    _In_ CXPLAT_SOCKET* Socket,
    _Inout_ CXPLAT_SEND_CONFIG* Config
    );

_IRQL_requires_max_(DISPATCH_LEVEL)
void
SendDataFree(
    _In_ CXPLAT_SEND_DATA* SendData
    );

_IRQL_requires_max_(DISPATCH_LEVEL)
_Success_(return != NULL)
QUIC_BUFFER*
SendDataAllocBuffer(
    _In_ CXPLAT_SEND_DATA* SendData,
    _In_ uint16_t MaxBufferLength
    );

_IRQL_requires_max_(DISPATCH_LEVEL)
void
SendDataFreeBuffer(
    _In_ CXPLAT_SEND_DATA* SendData,
    _In_ QUIC_BUFFER* Buffer
    );

_IRQL_requires_max_(DISPATCH_LEVEL)
BOOLEAN
SendDataIsFull(
    _In_ CXPLAT_SEND_DATA* SendData
    );

_IRQL_requires_max_(DISPATCH_LEVEL)
QUIC_STATUS
SocketSend(
    _In_ CXPLAT_SOCKET* Socket,
    _In_ const CXPLAT_ROUTE* Route,
    _In_ CXPLAT_SEND_DATA* SendData
    );

void
DataPathProcessCqe(
    _In_ CXPLAT_CQE* Cqe
    );

CXPLAT_SOCKET*
CxPlatRawToSocket(
    _In_ CXPLAT_SOCKET_RAW* Socket
    );

CXPLAT_SOCKET_RAW*
CxPlatSocketToRaw(
    _In_ CXPLAT_SOCKET* Socketh
    );

uint32_t
CxPlatGetRawSocketSize(void);

_IRQL_requires_max_(PASSIVE_LEVEL)
QUIC_STATUS
RawSocketCreateUdp(
    _In_ CXPLAT_DATAPATH_RAW* DataPath,
    _In_ const CXPLAT_UDP_CONFIG* Config,
    _Inout_ CXPLAT_SOCKET_RAW* NewSocket
    );

_IRQL_requires_max_(PASSIVE_LEVEL)
void
RawSocketDelete(
    _In_ CXPLAT_SOCKET_RAW* Socket
    );

_IRQL_requires_max_(PASSIVE_LEVEL)
QUIC_STATUS
RawDataPathInitialize(
    _In_ uint32_t ClientRecvContextLength,
    _In_opt_ QUIC_EXECUTION_CONFIG* Config,
    _In_opt_ const CXPLAT_DATAPATH* ParentDataPath,
    _Out_ CXPLAT_DATAPATH_RAW** DataPath
    );

_IRQL_requires_max_(PASSIVE_LEVEL)
void
RawDataPathUninitialize(
    _In_ CXPLAT_DATAPATH_RAW* Datapath
    );

_IRQL_requires_max_(PASSIVE_LEVEL)
void
RawDataPathUpdateConfig(
    _In_ CXPLAT_DATAPATH_RAW* Datapath,
    _In_ QUIC_EXECUTION_CONFIG* Config
    );

_IRQL_requires_max_(DISPATCH_LEVEL)
uint32_t
RawDataPathGetSupportedFeatures(
    _In_ CXPLAT_DATAPATH_RAW* Datapath
    );

_IRQL_requires_max_(DISPATCH_LEVEL)
BOOLEAN
RawDataPathIsPaddingPreferred(
    _In_ CXPLAT_DATAPATH* Datapath
    );

_IRQL_requires_max_(PASSIVE_LEVEL)
QUIC_STATUS
RawSocketUpdateQeo(
    _In_ CXPLAT_SOCKET_RAW* Socket,
    _In_reads_(OffloadCount)
        const CXPLAT_QEO_CONNECTION* Offloads,
    _In_ uint32_t OffloadCount
    );

_IRQL_requires_max_(DISPATCH_LEVEL)
uint16_t
RawSocketGetLocalMtu(
    _In_ CXPLAT_SOCKET_RAW* Socket
    );

_IRQL_requires_max_(DISPATCH_LEVEL)
void
RawRecvDataReturn(
    _In_ CXPLAT_RECV_DATA* RecvDataChain
    );

_IRQL_requires_max_(DISPATCH_LEVEL)
_Success_(return != NULL)
CXPLAT_SEND_DATA*
RawSendDataAlloc(
    _In_ CXPLAT_SOCKET_RAW* Socket,
    _Inout_ CXPLAT_SEND_CONFIG* Config
    );

_IRQL_requires_max_(DISPATCH_LEVEL)
void
RawSendDataFree(
    _In_ CXPLAT_SEND_DATA* SendData
    );

_IRQL_requires_max_(DISPATCH_LEVEL)
_Success_(return != NULL)
QUIC_BUFFER*
RawSendDataAllocBuffer(
    _In_ CXPLAT_SEND_DATA* SendData,
    _In_ uint16_t MaxBufferLength
    );

_IRQL_requires_max_(DISPATCH_LEVEL)
void
RawSendDataFreeBuffer(
    _In_ CXPLAT_SEND_DATA* SendData,
    _In_ QUIC_BUFFER* Buffer
    );

_IRQL_requires_max_(DISPATCH_LEVEL)
BOOLEAN
RawSendDataIsFull(
    _In_ CXPLAT_SEND_DATA* SendData
    );

_IRQL_requires_max_(DISPATCH_LEVEL)
QUIC_STATUS
RawSocketSend(
    _In_ CXPLAT_SOCKET_RAW* Socket,
    _In_ const CXPLAT_ROUTE* Route,
    _In_ CXPLAT_SEND_DATA* SendData
    );

void
RawResolveRouteComplete(
    _In_ void* Context,
    _Inout_ CXPLAT_ROUTE* Route,
    _In_reads_bytes_(6) const uint8_t* PhysicalAddress,
    _In_ uint8_t PathId
    );

_IRQL_requires_max_(PASSIVE_LEVEL)
QUIC_STATUS
RawResolveRoute(
    _In_ CXPLAT_SOCKET_RAW* Sock,
    _Inout_ CXPLAT_ROUTE* Route,
    _In_ uint8_t PathId,
    _In_ void* Context,
    _In_ CXPLAT_ROUTE_RESOLUTION_CALLBACK_HANDLER Callback
    );

void
RawDataPathProcessCqe(
    _In_ CXPLAT_CQE* Cqe
    );

_IRQL_requires_max_(PASSIVE_LEVEL)
void
RawUpdateRoute(
    _Inout_ CXPLAT_ROUTE* DstRoute,
    _In_ CXPLAT_ROUTE* SrcRoute
    );

#endif // CX_PLATFORM_LINUX || _WIN32