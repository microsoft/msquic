/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.

--*/

#if defined(__cplusplus)
extern "C" {
#endif

//
// The different possible types of handles.
//
typedef enum QUIC_HANDLE_TYPE {

    QUIC_HANDLE_TYPE_REGISTRATION,
    QUIC_HANDLE_TYPE_CONFIGURATION,
    QUIC_HANDLE_TYPE_LISTENER,
    QUIC_HANDLE_TYPE_CONNECTION_CLIENT,
    QUIC_HANDLE_TYPE_CONNECTION_SERVER,
    QUIC_HANDLE_TYPE_STREAM

} QUIC_HANDLE_TYPE;

//
// The base type for all QUIC handles.
//
typedef struct QUIC_HANDLE {

    //
    // The current type of handle (client/server/child).
    //
    QUIC_HANDLE_TYPE Type;

    //
    // The API client context pointer.
    //
    void* ClientContext;

} QUIC_HANDLE;

//
// Represents the storage for global library state.
//
typedef struct QUIC_LIBRARY {

    //
    // Tracks whether the library loaded (DllMain or DriverEntry invoked on Windows).
    //
    BOOLEAN Loaded : 1;

    //
    // Tracks whether the library's lazy initialization has completed.
    //
    BOOLEAN LazyInitComplete : 1;

    //
    // Indicates the app has configured their own execution contexts.
    //
    BOOLEAN CustomExecutions : 1;

    //
    // Indicates the app has configured non-default (per-processor) partitioning.
    //
    BOOLEAN CustomPartitions : 1;

    //
    // Whether the datapath will be initialized with support for DSCP on receive.
    // As of Windows 26100, requesting DSCP on the receive path causes packets to fall out of
    // the Windows fast path causing a large performance regression.
    //
    BOOLEAN EnableDscpOnRecv : 1;

#ifdef CxPlatVerifierEnabled
    //
    // The app or driver verifier is globally enabled.
    //
    BOOLEAN IsVerifying : 1;
#endif

    //
    // Tracks whether the library has started being used, either by a listener
    // or a client connection being started. Once this state is set, some
    // global settings are not allowed to change.
    //
    BOOLEAN InUse;

    //
    // Indicates if the stateless retry feature is currently enabled.
    //
    BOOLEAN SendRetryEnabled;

    //
    // Current binary version.
    //
    uint32_t Version[4];

    //
    // Binary Git Hash
    //
    const char* GitHash;

    //
    // Configurable (app & registry) settings.
    //
    QUIC_SETTINGS_INTERNAL Settings;

    //
    // Controls access to all non-datapath internal state of the library.
    //
    CXPLAT_LOCK Lock;

    //
    // Controls access to all datapath internal state of the library.
    //
    CXPLAT_DISPATCH_LOCK DatapathLock;

    //
    // Total outstanding references from calls to MsQuicLoadLibrary.
    //
    volatile short LoadRefCount;

    //
    // Total outstanding references from calls to MsQuicOpenVersion.
    //
    uint16_t OpenRefCount;

    //
    // Number of partitions currently being used.
    //
    _Field_range_(>, 0)
    uint16_t PartitionCount;

    //
    // Mask for the worker index in the connection's partition ID.
    //
    uint16_t PartitionMask;

#if DEBUG
    //
    // Number of connections current allocated.
    //
    long ConnectionCount;
#endif

    //
    // Estimated timer resolution for the platform.
    //
    uint8_t TimerResolutionMs;

    //
    // Length of various parts of locally generated connection IDs.
    //
    _Field_range_(0, QUIC_MAX_CID_SID_LENGTH)
    uint8_t CidServerIdLength;
    // uint8_t CidPartitionIdLength; // Currently hard coded (QUIC_CID_PID_LENGTH)
    _Field_range_(QUIC_MIN_INITIAL_CONNECTION_ID_LENGTH, QUIC_CID_MAX_LENGTH)
    uint8_t CidTotalLength;

    //
    // An identifier used for correlating connection logs and statistics.
    //
    uint64_t ConnectionCorrelationId;

    //
    // The maximum total memory usage for handshake connections before the retry
    // feature gets enabled.
    //
    uint64_t HandshakeMemoryLimit;

    //
    // The estimated current total memory usage for handshake connections.
    //
    uint64_t CurrentHandshakeMemoryUsage;

    //
    // Handle to global persistent storage (registry).
    //
    CXPLAT_STORAGE* Storage;

    //
    // Configuration for execution of the library (optionally set by the app).
    //
    QUIC_GLOBAL_EXECUTION_CONFIG* ExecutionConfig;

    //
    // Datapath instance for the library.
    //
    CXPLAT_DATAPATH* Datapath;

    //
    // List of all registrations in the current process (or kernel).
    //
    CXPLAT_LIST_ENTRY Registrations;

    //
    // List of all UDP bindings in the current process (or kernel).
    //
    CXPLAT_LIST_ENTRY Bindings;

    //
    // Contains all (server) connections currently not in an app's registration.
    //
    QUIC_REGISTRATION* StatelessRegistration;

    //
    // Protects all registration close completion fields.
    CXPLAT_LOCK RegistrationCloseCleanupLock;

    //
    // Event set when the registration worker needs to wake.
    //
    CXPLAT_EVENT RegistrationCloseCleanupEvent;

    //
    // Set to true to shut down the worker thread.
    //
    BOOLEAN RegistrationCloseCleanupShutdown;

    //
    // A dedicated worker thread to clean up async registration close.
    //
    CXPLAT_THREAD RegistrationCloseCleanupWorker;

    //
    // List of registrations needing asynchronous close completion indications.
    //
    CXPLAT_LIST_ENTRY RegistrationCloseCleanupList;

    //
    // Rundown protection for the registration close cleanup worker.
    //
    CXPLAT_RUNDOWN_REF RegistrationCloseCleanupRundown;

    //
    // Per-partition storage. Count of `PartitionCount`.
    //
    _Field_size_(PartitionCount)
    QUIC_PARTITION* Partitions;

    struct {
        //
        // Lock protecting the stateless retry configuration.
        //
        CXPLAT_DISPATCH_RW_LOCK Lock;

        //
        // The base secret used to generate keys for the stateless retry token.
        //
        uint8_t BaseSecret[CXPLAT_AEAD_MAX_SIZE];

        //
        // Length of the secret stored in BaseSecret. Depents on the algorithm type.
        //
        uint32_t SecretLength;

        //
        // The AEAD algorithm to use for the retry key.
        //
        CXPLAT_AEAD_TYPE AeadAlgorithm;

        //
        // The number of milliseconds between key rotations.
        //
        uint32_t KeyRotationMs;

    } StatelessRetry;

    //
    // The Toeplitz hash used for hashing received long header packets.
    //
    CXPLAT_TOEPLITZ_HASH ToeplitzHash;

#if QUIC_TEST_DATAPATH_HOOKS_ENABLED
    //
    // An optional callback to allow test code to modify the data path.
    //
    QUIC_TEST_DATAPATH_HOOKS* TestDatapathHooks;
#endif

    //
    // Default client compatibility list. Use for connections that don't
    // specify a custom list. Generated for QUIC_VERSION_LATEST
    //
    const uint32_t* DefaultCompatibilityList;
    uint32_t DefaultCompatibilityListLength;

    //
    // Last sample of the performance counters
    //
    uint64_t PerfCounterSamplesTime;
    int64_t PerfCounterSamples[QUIC_PERF_COUNTER_MAX];

    //
    // The worker pool
    //
    CXPLAT_WORKER_POOL* WorkerPool;

} QUIC_LIBRARY;

extern QUIC_LIBRARY MsQuicLib;

#if DEBUG // Enable all verifier checks in debug builds
#define QUIC_LIB_VERIFY(Expr) CXPLAT_FRE_ASSERT(Expr)
#elif defined(CxPlatVerifierEnabled)
#define QUIC_LIB_VERIFY(Expr) \
    if (MsQuicLib.IsVerifying) { CXPLAT_FRE_ASSERT(Expr); }
#else
#define QUIC_LIB_VERIFY(Expr)
#endif

QUIC_INLINE
QUIC_PARTITION*
QuicLibraryGetPartitionFromProcessorIndex(
    uint32_t ProcessorIndex
    )
{
    CXPLAT_DBG_ASSERT(MsQuicLib.Partitions != NULL);

    if (MsQuicLib.CustomPartitions) {
        //
        // Try to find a partition close to the current processor. Walk the list
        // of partitions to find the first one that is greater than or equal to
        // the current processor.
        //
        for (uint32_t i = 0; i < MsQuicLib.PartitionCount; ++i) {
            if (ProcessorIndex <= MsQuicLib.Partitions[i].Processor) {
                return &MsQuicLib.Partitions[i];
            }
        }

        //
        // None found, return the last one.
        //
        return &MsQuicLib.Partitions[MsQuicLib.PartitionCount - 1];
    }

    //
    // Not doing any custom partitioning, just use the current processor modulo
    // the partition count.
    //
    return &MsQuicLib.Partitions[ProcessorIndex % MsQuicLib.PartitionCount];
}

_IRQL_requires_max_(DISPATCH_LEVEL)
QUIC_INLINE
QUIC_PARTITION*
QuicLibraryGetCurrentPartition(
    void
    )
{
    const uint16_t CurrentProc = (uint16_t)CxPlatProcCurrentNumber();
    return QuicLibraryGetPartitionFromProcessorIndex(CurrentProc);
}

_IRQL_requires_max_(DISPATCH_LEVEL)
QUIC_INLINE
uint16_t
QuicPartitionIdCreate(
    uint16_t BaseIndex
    )
{
    CXPLAT_DBG_ASSERT(BaseIndex < MsQuicLib.PartitionCount);
    //
    // Generate a partition ID which is a combination of random high bits and
    // the actual partitioning index encoded in the low bits.
    //
    // N.B. The following logic can leak the number of partitions if not a power
    // of two. This is because we use a bit mask to split the two parts of the
    // ID.
    //
    uint16_t PartitionId;
    CxPlatRandom(sizeof(PartitionId), &PartitionId);
    return (PartitionId & ~MsQuicLib.PartitionMask) | BaseIndex;
}

_IRQL_requires_max_(DISPATCH_LEVEL)
QUIC_INLINE
uint16_t
QuicPartitionIdGetIndex(
    uint16_t PartitionId
    )
{
    return (PartitionId & MsQuicLib.PartitionMask) % MsQuicLib.PartitionCount;
}

#define QUIC_PERF_SAMPLE_INTERVAL_S    1 // 1 second

_IRQL_requires_max_(DISPATCH_LEVEL)
void
QuicPerfCounterSnapShot(
    _In_ uint64_t TimeDiffUs
    );

_IRQL_requires_max_(DISPATCH_LEVEL)
QUIC_INLINE
void
QuicPerfCounterTrySnapShot(
    _In_ uint64_t TimeNow
    )
{
    uint64_t TimeLast = MsQuicLib.PerfCounterSamplesTime;
    uint64_t TimeDiff = CxPlatTimeDiff64(TimeLast, TimeNow);
    if (TimeDiff < S_TO_US(QUIC_PERF_SAMPLE_INTERVAL_S)) {
        return; // Not time to resample yet.
    }

    if ((int64_t)TimeLast !=
        InterlockedCompareExchange64(
            (int64_t*)&MsQuicLib.PerfCounterSamplesTime,
            (int64_t)TimeNow,
            (int64_t)TimeLast)) {
        return; // Someone else already is updating.
    }

    QuicPerfCounterSnapShot(TimeDiff);
}

//
// Creates a random, new source connection ID, that will be used on the receive
// path.
//
QUIC_INLINE
_Success_(return != NULL)
QUIC_CID_HASH_ENTRY*
QuicCidNewRandomSource(
    _In_opt_ QUIC_CONNECTION* Connection,
    _In_reads_opt_(MsQuicLib.CidServerIdLength)
        const void* ServerID,
    _In_ uint16_t PartitionID,
    _In_ uint8_t PrefixLength,
    _In_reads_(PrefixLength)
        const void* Prefix
    )
{
    CXPLAT_DBG_ASSERT(MsQuicLib.CidTotalLength <= QUIC_MAX_CONNECTION_ID_LENGTH_V1);
    CXPLAT_DBG_ASSERT(MsQuicLib.CidTotalLength == MsQuicLib.CidServerIdLength + QUIC_CID_PID_LENGTH + QUIC_CID_PAYLOAD_LENGTH);
    CXPLAT_DBG_ASSERT(QUIC_CID_PAYLOAD_LENGTH > PrefixLength);

    QUIC_CID_HASH_ENTRY* Entry =
        (QUIC_CID_HASH_ENTRY*)
        CXPLAT_ALLOC_NONPAGED(
            sizeof(QUIC_CID_HASH_ENTRY) +
            MsQuicLib.CidTotalLength,
            QUIC_POOL_CIDHASH);

    if (Entry != NULL) {
        Entry->Connection = Connection;
        CxPlatZeroMemory(&Entry->CID, sizeof(Entry->CID));
        Entry->CID.Length = MsQuicLib.CidTotalLength;

        uint8_t* Data = Entry->CID.Data;
        if (ServerID != NULL) {
            CxPlatCopyMemory(Data, ServerID, MsQuicLib.CidServerIdLength);
        } else {
            CxPlatRandom(MsQuicLib.CidServerIdLength, Data);
        }
        Data += MsQuicLib.CidServerIdLength;

        CXPLAT_STATIC_ASSERT(QUIC_CID_PID_LENGTH == sizeof(PartitionID), "Assumes a 2 byte PID");
        CxPlatCopyMemory(Data, &PartitionID, sizeof(PartitionID));
        Data += sizeof(PartitionID);

        if (PrefixLength) {
            CxPlatCopyMemory(Data, Prefix, PrefixLength);
            Data += PrefixLength;
        }

        CxPlatRandom(QUIC_CID_PAYLOAD_LENGTH - PrefixLength, Data);
    }

    return Entry;
}

//
// Ensures any lazy initialization for the library is complete.
//
_IRQL_requires_max_(PASSIVE_LEVEL)
QUIC_STATUS
QuicLibraryLazyInitialize(
    BOOLEAN AcquireLock
    );

_IRQL_requires_max_(PASSIVE_LEVEL)
void
MsQuicLibraryLazyUninitialize(
    void
    );

_IRQL_requires_max_(PASSIVE_LEVEL)
QUIC_STATUS
QuicLibrarySetGlobalParam(
    _In_ uint32_t Param,
    _In_ uint32_t BufferLength,
    _In_reads_bytes_(BufferLength)
        const void* Buffer
    );

_IRQL_requires_max_(PASSIVE_LEVEL)
QUIC_STATUS
QuicLibraryGetGlobalParam(
    _In_ uint32_t Param,
    _Inout_ uint32_t* BufferLength,
    _Out_writes_bytes_opt_(*BufferLength)
        void* Buffer
    );

_IRQL_requires_max_(PASSIVE_LEVEL)
QUIC_STATUS
QuicLibrarySetParam(
    _In_ HQUIC Handle,
    _In_ uint32_t Param,
    _In_ uint32_t BufferLength,
    _In_reads_bytes_(BufferLength)
        const void* Buffer
    );

_IRQL_requires_max_(PASSIVE_LEVEL)
QUIC_STATUS
QuicLibraryGetParam(
    _In_ HQUIC Handle,
    _In_ uint32_t Param,
    _Inout_ uint32_t* BufferLength,
    _Out_writes_bytes_opt_(*BufferLength)
        void* Buffer
    );

//
// Get the binding for the addresses.
//
_IRQL_requires_max_(PASSIVE_LEVEL)
QUIC_STATUS
QuicLibraryGetBinding(
    _In_ const CXPLAT_UDP_CONFIG* UdpConfig,
    _Outptr_ QUIC_BINDING** NewBinding
    );

//
// Tries to acquire a ref on the binding. Fails if already starting the clean up
// process.
//
_IRQL_requires_max_(DISPATCH_LEVEL)
BOOLEAN
QuicLibraryTryAddRefBinding(
    _In_ QUIC_BINDING* Binding
    );

//
// Releases a reference on the binding and uninitializes it if it's the last
// one. DO NOT call this on a datapath upcall thread, as it will deadlock or
// possibly even crash!
//
_IRQL_requires_max_(PASSIVE_LEVEL)
void
QuicLibraryReleaseBinding(
    _In_ QUIC_BINDING* Binding
    );

//
// Called when a listener is created. Makes sure the library is ready to handle
// incoming client handshakes.
//
_IRQL_requires_max_(PASSIVE_LEVEL)
BOOLEAN
QuicLibraryOnListenerRegistered(
    _In_ QUIC_LISTENER* Listener
    );

//
// Returns the next available worker. Note, the worker may be overloaded.
//
_IRQL_requires_max_(DISPATCH_LEVEL)
QUIC_WORKER*
QuicLibraryGetWorker(
    _In_ const QUIC_RX_PACKET* Packet
    );

//
// Called when a new (server) connection is added in the handshake state.
//
_IRQL_requires_max_(DISPATCH_LEVEL)
void
QuicLibraryOnHandshakeConnectionAdded(
    void
    );

//
// Called when a connection leaves the handshake state.
//
_IRQL_requires_max_(DISPATCH_LEVEL)
void
QuicLibraryOnHandshakeConnectionRemoved(
    void
    );

//
// Generates a stateless reset token for the given connection ID.
//
_IRQL_requires_max_(PASSIVE_LEVEL)
QUIC_STATUS
QuicLibraryGenerateStatelessResetToken(
    _In_ QUIC_PARTITION* Partition,
    _In_reads_(MsQuicLib.CidTotalLength)
        const uint8_t* const CID,
    _Out_writes_all_(QUIC_STATELESS_RESET_TOKEN_LENGTH)
        uint8_t* ResetToken
    );

_IRQL_requires_max_(PASSIVE_LEVEL)
QUIC_STATUS
QuicLibrarySetRetryKeyConfig(
    _In_ const QUIC_STATELESS_RETRY_CONFIG* Config
    );

#if defined(__cplusplus)
}
#endif
