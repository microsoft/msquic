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
    _In_ uint16_t IdealProcessor
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

typedef struct DATAPATH_SQE {
    uint32_t CqeType;
#ifdef CXPLAT_SQE
    CXPLAT_SQE Sqe;
#endif
} DATAPATH_SQE;

typedef struct CXPLAT_DATAPATH_PROC CXPLAT_DATAPATH_PROC;

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
// IO header for SQE->CQE based completions.
//
typedef struct DATAPATH_IO_SQE {
    DATAPATH_IO_TYPE IoType;
    DATAPATH_SQE DatapathSqe;
} DATAPATH_IO_SQE;

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
    CXPLAT_DATAPATH_PROC* DatapathProc;

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
    // The index of ideal processor for this datapath.
    //
    uint16_t IdealProcessor;

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

} CXPLAT_DATAPATH_PROC;

//
// Main structure for tracking all UDP abstractions.
//
typedef struct CXPLAT_DATAPATH {
    CXPLAT_DATAPATH_BASE;

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
    uint16_t ProcCount;

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

    CXPLAT_DATAPATH_RAW* RawDataPath;

    //
    // Per-processor completion contexts.
    //
    CXPLAT_DATAPATH_PROC Processors[0];

} CXPLAT_DATAPATH;

//
// Per-port state. Multiple sockets are created on each port.
//
typedef struct CXPLAT_SOCKET {
    CXPLAT_SOCKET_BASE;

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
    // The local interface's MTU.
    //
    uint16_t Mtu;

    //
    // The size of a receive buffer's payload.
    //
    uint32_t RecvBufLen;

    //
    // Socket type.
    //
    uint8_t Type : 2; // CXPLAT_SOCKET_TYPE

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
    // TODO: Move to base
    uint8_t Uninitialized : 1;
    uint8_t Freed : 1;

    //
    // Per-processor socket contexts.
    //
    CXPLAT_SOCKET_PROC Processors[0];

} CXPLAT_SOCKET;

uint32_t
CxPlatGetRawSocketSize ();

CXPLAT_SOCKET*
CxPlatRawToSocket(CXPLAT_SOCKET_RAW* Socket);

CXPLAT_SOCKET_RAW*
CxPlatSocketToRaw(CXPLAT_SOCKET* Socket);

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
