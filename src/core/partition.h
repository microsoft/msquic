/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.

Abstract:

    The partitioned storage for global library state. The partitioning allows
    multiple threads to operate on the library simultaneously with minimal
    contention.

    The primary goal of partitioning is to allow multiple threads to allocate
    and free pool memory simultaneously without contention. It also maintains
    isolation for other state that may be commonly accessed by multiple threads,
    such as performance counters and stateless resets and retries.

    A partition is always (soft) affinitized to a single, specific processor. By
    default, partitions are one to one with processors. Though, an application
    may choose to create partitions on a subset of processors. In this case, the
    partition may be used by work queued on processors that are not explicitly
    affinitized to a partition. In general, though, the library will try to only
    execute on those processors with assigned partitions.

    Several things make use of partitions, including memory pools, various keys
    used for global state and performance counters.

    There are various different pools for allocating different fixed size
    objects. These are used to reduce the cost of allocating and freeing these
    objects. Memory is then returned back to the pool if was allocated from on
    free.

    They keys and associated state for stateless Reset and Retry functionality
    are stored in the partition. This allows for multiple processors to be
    generating stateless resets and retries simultaneously without contention.
    For Retry, it employes a single base secret/key (stored in the library as
    a singteton) and then generates the actual keys based on elapsed time
    intervales. Each key only last for 30 seconds to protect from attack.
    Additionally, these keys are only created as necessary.

--*/

#if defined(__cplusplus)
extern "C" {
#endif

typedef struct QUIC_RETRY_KEY {
    CXPLAT_KEY* Key;
    int64_t Index;
} QUIC_RETRY_KEY;

typedef struct QUIC_CACHEALIGN QUIC_PARTITION {

    //
    // The index into the global array of partitions.
    //
    uint16_t Index;

    //
    // The processor that this partition is affinitized to.
    //
    uint16_t Processor;

    //
    // Log correlation ID for events.
    //
    uint64_t SendBatchId;
    uint64_t SendPacketId;
    uint64_t ReceivePacketId;

    //
    // Used for generating stateless reset hashes.
    //
    CXPLAT_HASH* ResetTokenHash;
    CXPLAT_LOCK ResetTokenLock;

    //
    // Two most recent keys used for generating stateless retries.
    //
    CXPLAT_DISPATCH_LOCK StatelessRetryKeysLock;
    QUIC_RETRY_KEY StatelessRetryKeys[2];

    //
    // Pools for allocations.
    //
    CXPLAT_POOL ConnectionPool;             // QUIC_CONNECTION
    CXPLAT_POOL TransportParamPool;         // QUIC_TRANSPORT_PARAMETER
    CXPLAT_POOL PacketSpacePool;            // QUIC_PACKET_SPACE
    CXPLAT_POOL StreamPool;                 // QUIC_STREAM
    CXPLAT_POOL DefaultReceiveBufferPool;   // QUIC_DEFAULT_STREAM_RECV_BUFFER_SIZE
    CXPLAT_POOL SendRequestPool;            // QUIC_SEND_REQUEST
    QUIC_SENT_PACKET_POOL SentPacketPool;   // QUIC_SENT_PACKET_METADATA
    CXPLAT_POOL ApiContextPool;             // QUIC_API_CONTEXT
    CXPLAT_POOL StatelessContextPool;       // QUIC_STATELESS_CONTEXT
    CXPLAT_POOL OperPool;                   // QUIC_OPERATION
    CXPLAT_POOL AppBufferChunkPool;         // QUIC_RECV_CHUNK

    //
    // Per-processor performance counters.
    //
    int64_t PerfCounters[QUIC_PERF_COUNTER_MAX];

} QUIC_PARTITION;

//
// N.B.: All partitions are assumed to be preallocated with zeroed memory.
//
QUIC_STATUS
QuicPartitionInitialize(
    _Inout_ QUIC_PARTITION* Partition,
    _In_ uint16_t Index,
    _In_ uint16_t Processor,
    _In_ CXPLAT_HASH_TYPE HashType,
    _In_reads_(ResetHashKeyLength)
        const uint8_t* const ResetHashKey,
    _In_ uint32_t ResetHashKeyLength
    );

void
QuicPartitionUninitialize(
    _Inout_ QUIC_PARTITION* Partition
    );

//
// Returns the current stateless retry key.
//
_IRQL_requires_max_(DISPATCH_LEVEL)
_Requires_lock_held_(Partition->StatelessRetryKeysLock)
_Ret_maybenull_
CXPLAT_KEY*
QuicPartitionGetCurrentStatelessRetryKey(
    _In_ QUIC_PARTITION* Partition
    );

//
// Returns the stateless retry key for that timestamp.
//
_IRQL_requires_max_(DISPATCH_LEVEL)
_Requires_lock_held_(Partition->StatelessRetryKeysLock)
_Ret_maybenull_
CXPLAT_KEY*
QuicPartitionGetStatelessRetryKeyForTimestamp(
    _In_ QUIC_PARTITION* Partition,
    _In_ int64_t Timestamp
    );

_IRQL_requires_max_(PASSIVE_LEVEL)
QUIC_INLINE
QUIC_STATUS
QuicPartitionUpdateStatelessResetKey(
    _Inout_ QUIC_PARTITION* Partition,
    _In_ CXPLAT_HASH_TYPE HashType,
    _In_reads_(ResetHashKeyLength)
        const uint8_t* const ResetHashKey,
    _In_ uint32_t ResetHashKeyLength
    )
{
    CXPLAT_HASH* NewResetTokenHash = NULL;
    QUIC_STATUS Status =
        CxPlatHashCreate(
            HashType,
            ResetHashKey,
            ResetHashKeyLength,
            &NewResetTokenHash);
    if (QUIC_FAILED(Status)) {
        return Status;
    }

    CxPlatLockAcquire(&Partition->ResetTokenLock);
    CxPlatHashFree(Partition->ResetTokenHash);
    Partition->ResetTokenHash = NewResetTokenHash;
    CxPlatLockRelease(&Partition->ResetTokenLock);

    return QUIC_STATUS_SUCCESS;
}

_IRQL_requires_max_(DISPATCH_LEVEL)
QUIC_INLINE
void
QuicPerfCounterAdd(
    _In_ QUIC_PARTITION* Partition,
    _In_ QUIC_PERFORMANCE_COUNTERS Type,
    _In_ int64_t Value
    )
{
    CXPLAT_DBG_ASSERT(Type >= 0 && Type < QUIC_PERF_COUNTER_MAX);
    InterlockedExchangeAdd64(&Partition->PerfCounters[Type], Value);
}

#define QuicPerfCounterIncrement(Partition, Type) QuicPerfCounterAdd(Partition, Type, 1)
#define QuicPerfCounterDecrement(Partition, Type) QuicPerfCounterAdd(Partition, Type, -1)

#if defined(__cplusplus)
}
#endif
