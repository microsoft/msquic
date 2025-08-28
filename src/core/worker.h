/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.

--*/

//
// A worker thread for draining queued operations on a connection.
//
typedef struct QUIC_CACHEALIGN QUIC_WORKER {

    //
    // Context for execution callbacks and state management.
    //
    CXPLAT_EXECUTION_CONTEXT ExecutionContext;

    //
    // The partition this worker is affinitized to.
    //
    QUIC_PARTITION* Partition;

    //
    // Event to signal when the execution context (i.e. worker thread) is
    // complete.
    //
    CXPLAT_EVENT Done;

    //
    // Indicates if this work is handled by an external (to QUIC) execution context.
    //
    BOOLEAN IsExternal;

    //
    // TRUE if the worker is currently running.
    //
    BOOLEAN Enabled;

    //
    // TRUE if the worker is currently processing work.
    //
    BOOLEAN IsActive;

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
    CXPLAT_EVENT Ready;

    //
    // A thread for draining operations.
    //
    CXPLAT_THREAD Thread;

    //
    // Serializes access to the connection, listener, and operation lists.
    //
    CXPLAT_DISPATCH_LOCK Lock;

    //
    // Queue of connections with operations to be processed.
    //
    CXPLAT_LIST_ENTRY Connections;
    CXPLAT_LIST_ENTRY** PriorityConnectionsTail;

    //
    // Queue of listeners with operations to be processed.
    //
    CXPLAT_LIST_ENTRY Listeners;

    //
    // Queue of stateless operations to be processed.
    //
    CXPLAT_LIST_ENTRY Operations;
    uint32_t OperationCount;
    uint64_t DroppedOperationCount;

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
QUIC_INLINE
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
    _In_ const QUIC_REGISTRATION* Registration,
    _In_ QUIC_EXECUTION_PROFILE ExecProfile,
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
// Queues a priority connection onto the worker, and kicks the worker thread if
// necessary.
//
_IRQL_requires_max_(DISPATCH_LEVEL)
void
QuicWorkerQueuePriorityConnection(
    _In_ QUIC_WORKER* Worker,
    _In_ QUIC_CONNECTION* Connection
    );

_IRQL_requires_max_(DISPATCH_LEVEL)
void
QuicWorkerAssignListener(
    _In_ QUIC_WORKER* Worker,
    _In_ QUIC_LISTENER* Listener
    );

_IRQL_requires_max_(DISPATCH_LEVEL)
void
QuicWorkerQueueListener(
    _In_ QUIC_WORKER* Worker,
    _In_ QUIC_LISTENER* Listener
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

BOOLEAN
QuicWorkerPoolIsInPartition(
    _In_ QUIC_WORKER_POOL* WorkerPool,
    _In_ uint16_t PartitionIndex
    );
