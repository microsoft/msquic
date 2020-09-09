/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.

--*/

//
// A worker thread for draining queued operations on a connection.
//
typedef struct QUIC_CACHEALIGN QUIC_WORKER {

    //
    // TRUE if the worker is currently running.
    //
    BOOLEAN Enabled;

    //
    // TRUE if the worker is currently processing connections.
    //
    BOOLEAN IsActive;

    //
    // The worker's ideal processor.
    //
    uint16_t IdealProcessor;

    //
    // The identifier of the platform thread.
    //
    QUIC_THREAD_ID ThreadID;

    //
    // The average queue delay connections experience, in microseconds.
    //
    uint32_t AverageQueueDelay;

    //
    // Timers for the worker's connections.
    //
    QUIC_TIMER_WHEEL TimerWheel;

    //
    // An event to kick the thread.
    //
    QUIC_EVENT Ready;

    //
    // A thread for draining operations from queued connections.
    //
    QUIC_THREAD Thread;

    //
    // Serializes access to the connection and operation lists.
    //
    QUIC_DISPATCH_LOCK Lock;

    //
    // Queue of connections with operations to be processed.
    //
    QUIC_LIST_ENTRY Connections;

    //
    // Queue of stateless operations to be processed.
    //
    QUIC_LIST_ENTRY Operations;
    uint32_t OperationCount;
    uint64_t DroppedOperationCount;

    QUIC_POOL StreamPool; // QUIC_STREAM
    QUIC_POOL DefaultReceiveBufferPool; // QUIC_DEFAULT_STREAM_RECV_BUFFER_SIZE
    QUIC_POOL SendRequestPool; // QUIC_SEND_REQUEST
    QUIC_SENT_PACKET_POOL SentPacketPool; // QUIC_SENT_PACKET_METADATA
    QUIC_POOL ApiContextPool; // QUIC_API_CONTEXT
    QUIC_POOL StatelessContextPool; // QUIC_STATELESS_CONTEXT
    QUIC_POOL OperPool; // QUIC_OPERATION

} QUIC_WORKER;

//
// A set of workers.
//
typedef struct QUIC_WORKER_POOL {

    //
    // Number of workers in the pool.
    //
    uint16_t WorkerCount;

    //
    // Last least loaded worker.
    //
    uint16_t LastWorker;

    //
    // All the workers.
    //
    _Field_size_(WorkerCount)
    QUIC_WORKER Workers[0];

} QUIC_WORKER_POOL;

//
// Returns TRUE if the worker is currently overloaded and shouldn't take on more
// work, if at all possible.
//
_IRQL_requires_max_(DISPATCH_LEVEL)
inline
BOOLEAN
QuicWorkerIsOverloaded(
    _In_ QUIC_WORKER* Worker
    )
{
    return Worker->AverageQueueDelay > MsQuicLib.Settings.MaxWorkerQueueDelayUs;
}

//
// Initializes the worker pool.
//
_IRQL_requires_max_(PASSIVE_LEVEL)
QUIC_STATUS
QuicWorkerPoolInitialize(
    _In_opt_ const void* Owner,
    _In_ uint16_t ThreadFlags,
    _In_ uint16_t WorkerCount,
    _Out_ QUIC_WORKER_POOL** WorkerPool
    );

//
// Cleans up the worker pool.
//
_IRQL_requires_max_(PASSIVE_LEVEL)
void
QuicWorkerPoolUninitialize(
    _In_ QUIC_WORKER_POOL* WorkerPool
    );

//
// Returns TRUE if the all the workers in the pool are currently overloaded.
//
_IRQL_requires_max_(DISPATCH_LEVEL)
BOOLEAN
QuicWorkerPoolIsOverloaded(
    _In_ QUIC_WORKER_POOL* WorkerPool
    );

//
// Gets the worker index with the smallest current load.
//
_IRQL_requires_max_(DISPATCH_LEVEL)
uint16_t
QuicWorkerPoolGetLeastLoadedWorker(
    _In_ QUIC_WORKER_POOL* WorkerPool
    );

//
// Assigns the connection to a worker.
//
_IRQL_requires_max_(DISPATCH_LEVEL)
void
QuicWorkerAssignConnection(
    _In_ QUIC_WORKER* Worker,
    _In_ QUIC_CONNECTION* Connection
    );

//
// Queues the connection onto the worker, and kicks the worker thread if
// necessary.
//
_IRQL_requires_max_(DISPATCH_LEVEL)
void
QuicWorkerQueueConnection(
    _In_ QUIC_WORKER* Worker,
    _In_ QUIC_CONNECTION* Connection
    );

//
// Queues the operation onto the worker, and kicks the worker thread if
// necessary.
//
_IRQL_requires_max_(DISPATCH_LEVEL)
void
QuicWorkerQueueOperation(
    _In_ QUIC_WORKER* Worker,
    _In_ QUIC_OPERATION* Operation
    );
