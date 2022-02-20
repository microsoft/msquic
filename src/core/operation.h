/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.

--*/

#ifdef QUIC_CLOG
#include "operation.h.clog.h"
#endif

typedef struct QUIC_SEND_REQUEST QUIC_SEND_REQUEST;

//
// For logging.
//
typedef enum QUIC_SCHEDULE_STATE {
    QUIC_SCHEDULE_IDLE,
    QUIC_SCHEDULE_QUEUED,
    QUIC_SCHEDULE_PROCESSING

} QUIC_SCHEDULE_STATE;

typedef enum QUIC_OPERATION_TYPE {
    QUIC_OPER_TYPE_API_CALL,            // Process an API call from the app.
    QUIC_OPER_TYPE_FLUSH_RECV,          // Process queue of receive packets.
    QUIC_OPER_TYPE_UNREACHABLE,         // Process UDP unreachable event.
    QUIC_OPER_TYPE_FLUSH_STREAM_RECV,   // Indicate a stream data to the app.
    QUIC_OPER_TYPE_FLUSH_SEND,          // Frame packets and send them.
    QUIC_OPER_TYPE_DEPRECATED,          // No longer used.
    QUIC_OPER_TYPE_TIMER_EXPIRED,       // A timer expired.
    QUIC_OPER_TYPE_TRACE_RUNDOWN,       // A trace rundown was triggered.
    QUIC_OPER_TYPE_ROUTE_COMPLETION,    // Process route completion event.

    //
    // All stateless operations follow.
    //

    QUIC_OPER_TYPE_VERSION_NEGOTIATION, // A version negotiation needs to be sent.
    QUIC_OPER_TYPE_STATELESS_RESET,     // A stateless reset needs to be sent.
    QUIC_OPER_TYPE_RETRY,               // A retry needs to be sent.

} QUIC_OPERATION_TYPE;

typedef enum QUIC_API_TYPE {

    QUIC_API_TYPE_CONN_CLOSE,
    QUIC_API_TYPE_CONN_SHUTDOWN,
    QUIC_API_TYPE_CONN_START,
    QUIC_API_TYPE_CONN_SET_CONFIGURATION,
    QUIC_API_TYPE_CONN_SEND_RESUMPTION_TICKET,

    QUIC_API_TYPE_STRM_CLOSE,
    QUIC_API_TYPE_STRM_SHUTDOWN,
    QUIC_API_TYPE_STRM_START,
    QUIC_API_TYPE_STRM_SEND,
    QUIC_API_TYPE_STRM_RECV_COMPLETE,
    QUIC_API_TYPE_STRM_RECV_SET_ENABLED,

    QUIC_API_TYPE_SET_PARAM,
    QUIC_API_TYPE_GET_PARAM,

    QUIC_API_TYPE_DATAGRAM_SEND,

} QUIC_API_TYPE;

//
// Context for an API call. This is allocated separately from QUIC_OPERATION
// so that non-API-call operations will take less space.
//
typedef struct QUIC_API_CONTEXT {

    QUIC_API_TYPE Type;

    //
    // A pointer to the return status for the operation. If this pointer is
    // NULL, this the operation is performed asynchronously, with no
    // completion event being set, nor the status being returned. If the
    // pointer is set, then the operation is completed synchronously by setting
    // the status and signaling the Completed event.
    //
    QUIC_STATUS* Status;

    //
    // Used for synchronous operations (see above).
    //
    CXPLAT_EVENT* Completed;

    union {
        struct {
            void* Reserved; // Nothing.
        } CONN_OPEN;
        struct {
            void* Reserved; // Nothing.
        } CONN_CLOSED;
        struct {
            QUIC_CONNECTION_SHUTDOWN_FLAGS Flags;
            BOOLEAN RegistrationShutdown;
            QUIC_VAR_INT ErrorCode;
        } CONN_SHUTDOWN;
        struct {
            QUIC_CONFIGURATION* Configuration;
            _Null_terminated_
            const char* ServerName;
            uint16_t ServerPort;
            QUIC_ADDRESS_FAMILY Family;
        } CONN_START;
        struct {
            QUIC_CONFIGURATION* Configuration;
        } CONN_SET_CONFIGURATION;
        struct {
            QUIC_SEND_RESUMPTION_FLAGS Flags;
            uint8_t* ResumptionAppData;
            uint16_t AppDataLength;
        } CONN_SEND_RESUMPTION_TICKET;

        struct {
            QUIC_STREAM_OPEN_FLAGS Flags;
            QUIC_STREAM_CALLBACK_HANDLER Handler;
            void* Context;
            HQUIC* NewStream;
        } STRM_OPEN;
        struct {
            QUIC_STREAM* Stream;
        } STRM_CLOSE;
        struct {
            QUIC_STREAM* Stream;
            QUIC_STREAM_START_FLAGS Flags;
        } STRM_START;
        struct {
            QUIC_STREAM* Stream;
            QUIC_STREAM_SHUTDOWN_FLAGS Flags;
            QUIC_VAR_INT ErrorCode;
        } STRM_SHUTDOWN;
        struct {
            QUIC_STREAM* Stream;
        } STRM_SEND;
        struct {
            QUIC_STREAM* Stream;
            uint64_t BufferLength;
        } STRM_RECV_COMPLETE;
        struct {
            QUIC_STREAM* Stream;
            BOOLEAN IsEnabled;
        } STRM_RECV_SET_ENABLED;

        struct {
            HQUIC Handle;
            uint32_t Param;
            uint32_t BufferLength;
            const void* Buffer;
        } SET_PARAM;
        struct {
            HQUIC Handle;
            uint32_t Param;
            uint32_t* BufferLength;
            void* Buffer;
        } GET_PARAM;
    };

} QUIC_API_CONTEXT;

typedef enum QUIC_CONN_TIMER_TYPE {

    QUIC_CONN_TIMER_PACING,
    QUIC_CONN_TIMER_ACK_DELAY,
    QUIC_CONN_TIMER_LOSS_DETECTION,
    QUIC_CONN_TIMER_KEEP_ALIVE,
    QUIC_CONN_TIMER_IDLE,
    QUIC_CONN_TIMER_SHUTDOWN,

    QUIC_CONN_TIMER_COUNT

} QUIC_CONN_TIMER_TYPE;

typedef struct QUIC_STATELESS_CONTEXT {
    QUIC_BINDING* Binding;
    QUIC_WORKER* Worker;
    QUIC_ADDR RemoteAddress;
    CXPLAT_LIST_ENTRY ListEntry;
    CXPLAT_HASHTABLE_ENTRY TableEntry;
    CXPLAT_RECV_DATA* Datagram;
    uint32_t CreationTimeMs;
    uint8_t HasBindingRef : 1;
    uint8_t IsProcessed : 1;
    uint8_t IsExpired : 1;
} QUIC_STATELESS_CONTEXT;

//
// A single unit of work for a connection.
//
typedef struct QUIC_OPERATION {

    CXPLAT_LIST_ENTRY Link;
    QUIC_OPERATION_TYPE Type;

    //
    // Some operations are allocated on the stack rather than via
    // QuicOperationAlloc. This flag is used to differentiate
    // between the two. Only operations allocated with
    // QuicOperationAlloc should be freed with QuicOperationFree.
    //
    BOOLEAN FreeAfterProcess;

    union {
        struct {
            void* Reserved; // Nothing.
        } INITIALIZE;
        struct {
            QUIC_API_CONTEXT* Context;
        } API_CALL;
        struct {
            void* Reserved; // Nothing.
        } FLUSH_RECEIVE;
        struct {
            QUIC_ADDR RemoteAddress;
        } UNREACHABLE;
        struct {
            QUIC_STREAM* Stream;
        } FLUSH_STREAM_RECEIVE;
        struct {
            void* Reserved; // Nothing.
        } FLUSH_SEND;
        struct {
            QUIC_CONN_TIMER_TYPE Type;
        } TIMER_EXPIRED;
        struct {
            QUIC_STATELESS_CONTEXT* Context;
        } STATELESS; // Stateless reset, retry and VN
        struct {
            uint8_t PhysicalAddress[6];
            uint8_t PathId;
            BOOLEAN Succeeded;
        } ROUTE;
    };

} QUIC_OPERATION;

inline
_IRQL_requires_max_(DISPATCH_LEVEL)
void
QuicOperLog(
    _In_ const void* Connection,
    _In_ QUIC_OPERATION* Oper
    )
{
    UNREFERENCED_PARAMETER(Connection);
    switch (Oper->Type) {
        case QUIC_OPER_TYPE_API_CALL:
            QuicTraceEvent(
                ConnExecApiOper,
                "[conn][%p] Execute: %u",
                Connection,
                Oper->API_CALL.Context->Type);
            break;
        case QUIC_OPER_TYPE_TIMER_EXPIRED:
            QuicTraceEvent(
                ConnExecTimerOper,
                "[conn][%p] Execute: %u",
                Connection,
                Oper->TIMER_EXPIRED.Type);
            break;
        default:
            QuicTraceEvent(
                ConnExecOper,
                "[conn][%p] Execute: %u",
                Connection,
                Oper->Type);
            break;
    }
}

//
// A queue of operations to be executed for a connection.
//
typedef struct QUIC_OPERATION_QUEUE {

    //
    // TRUE if the queue is being drained.
    //
    BOOLEAN ActivelyProcessing;

    //
    // Queue of pending operations.
    //
    CXPLAT_DISPATCH_LOCK Lock;
    CXPLAT_LIST_ENTRY List;

} QUIC_OPERATION_QUEUE;

//
// Initializes an operation queue.
//
_IRQL_requires_max_(DISPATCH_LEVEL)
void
QuicOperationQueueInitialize(
    _Inout_ QUIC_OPERATION_QUEUE* OperQ
    );

//
// Uninitializes an operation queue.
//
_IRQL_requires_max_(DISPATCH_LEVEL)
void
QuicOperationQueueUninitialize(
    _In_ QUIC_OPERATION_QUEUE* OperQ
    );

//
// Allocates an operation.
//
_IRQL_requires_max_(DISPATCH_LEVEL)
QUIC_OPERATION*
QuicOperationAlloc(
    _In_ QUIC_WORKER* Worker,
    _In_ QUIC_OPERATION_TYPE Type
    );

//
// Frees an operation.
//
_IRQL_requires_max_(PASSIVE_LEVEL)
void
QuicOperationFree(
    _In_ QUIC_WORKER* Worker,
    _In_ QUIC_OPERATION* Oper
    );

//
// Enqueues an operation. Returns TRUE if the queue was previously empty and not
// already being processed.
//
_IRQL_requires_max_(DISPATCH_LEVEL)
BOOLEAN
QuicOperationEnqueue(
    _In_ QUIC_OPERATION_QUEUE* OperQ,
    _In_ QUIC_OPERATION* Oper
    );

//
// Enqueues an operation at the front of the queue. Returns TRUE if the queue
// was previously empty and not already being processed.
//
_IRQL_requires_max_(DISPATCH_LEVEL)
BOOLEAN
QuicOperationEnqueueFront(
    _In_ QUIC_OPERATION_QUEUE* OperQ,
    _In_ QUIC_OPERATION* Oper
    );

//
// Dequeues an operation. Returns NULL if the queue is empty.
//
_IRQL_requires_max_(DISPATCH_LEVEL)
QUIC_OPERATION*
QuicOperationDequeue(
    _In_ QUIC_OPERATION_QUEUE* OperQ
    );

//
// Dequeues and frees all operations.
//
_IRQL_requires_max_(DISPATCH_LEVEL)
void
QuicOperationQueueClear(
    _In_ QUIC_WORKER* Worker,
    _In_ QUIC_OPERATION_QUEUE* OperQ
    );
