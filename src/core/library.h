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
// Per-processor storage for global library state.
//
typedef struct QUIC_CACHEALIGN QUIC_LIBRARY_PP {

    //
    // Pool for QUIC_CONNECTIONs.
    //
    CXPLAT_POOL ConnectionPool;

    //
    // Pool for QUIC_TRANSPORT_PARAMETERs.
    //
    CXPLAT_POOL TransportParamPool;

    //
    // Pool for QUIC_PACKET_SPACE.
    //
    CXPLAT_POOL PacketSpacePool;

    //
    // Used for generating stateless reset hashes.
    //
    CXPLAT_HASH* ResetTokenHash;
    CXPLAT_LOCK ResetTokenLock;

    uint64_t SendBatchId;
    uint64_t SendPacketId;
    uint64_t ReceivePacketId;

    //
    // Per-processor performance counters.
    //
    int64_t PerfCounters[QUIC_PERF_COUNTER_MAX];

} QUIC_LIBRARY_PP;

//
// Represents the storage for global library state.
//
typedef struct QUIC_LIBRARY {

    //
    // Tracks whether the library loaded (DllMain or DriverEntry invoked on Windows).
    //
    BOOLEAN Loaded : 1;

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
    // Index for the current stateless retry token key.
    //
    BOOLEAN CurrentStatelessRetryKey;

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
    // Number of processors currently being used.
    //
    _Field_range_(>, 0)
    uint16_t ProcessorCount;

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
    // Processor candidates for raw datapath threads.
    //
    uint16_t* DataPathProcList;
    uint32_t DataPathProcListLength;

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
    // Per-processor storage. Count of `ProcessorCount`.
    //
    _Field_size_(ProcessorCount)
    QUIC_LIBRARY_PP* PerProc;

    //
    // Controls access to the stateless retry keys when rotated.
    //
    CXPLAT_DISPATCH_LOCK StatelessRetryKeysLock;

    //
    // Keys used for encryption of stateless retry tokens.
    //
    CXPLAT_KEY* StatelessRetryKeys[2];

    //
    // Timestamp when the current stateless retry key expires.
    //
    int64_t StatelessRetryKeysExpiration[2];

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

} QUIC_LIBRARY;

extern QUIC_LIBRARY MsQuicLib;

#ifdef CxPlatVerifierEnabled
#define QUIC_LIB_VERIFY(Expr) \
    if (MsQuicLib.IsVerifying) { CXPLAT_FRE_ASSERT(Expr); }
#else
#define QUIC_LIB_VERIFY(Expr)
#endif

_IRQL_requires_max_(DISPATCH_LEVEL)
_Ret_range_(0,MsQuicLib.PartitionCount - 1)
inline
uint16_t
QuicLibraryGetCurrentPartition(
    void
    )
{
    return ((uint16_t)CxPlatProcCurrentNumber()) % MsQuicLib.PartitionCount;
}

_IRQL_requires_max_(DISPATCH_LEVEL)
inline
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
inline
uint16_t
QuicPartitionIdGetIndex(
    uint16_t PartitionId
    )
{
    return (PartitionId & MsQuicLib.PartitionMask) % MsQuicLib.PartitionCount;
}

_IRQL_requires_max_(DISPATCH_LEVEL)
inline
uint16_t
QuicPartitionIndexIncrement(
    uint16_t PartitionIndex,
    uint16_t Increment
    )
{
    CXPLAT_DBG_ASSERT(Increment < MsQuicLib.PartitionCount);
    return (PartitionIndex + Increment) % MsQuicLib.PartitionCount;
}

_IRQL_requires_max_(DISPATCH_LEVEL)
inline
uint16_t
QuicPartitionIndexDecrement(
    uint16_t PartitionIndex,
    uint16_t Decrement
    )
{
    CXPLAT_DBG_ASSERT(Decrement < MsQuicLib.PartitionCount);
    if (PartitionIndex >= Decrement) {
        return PartitionIndex - Decrement;
    } else {
        return PartitionIndex + (MsQuicLib.PartitionCount - Decrement);
    }
}

_IRQL_requires_max_(DISPATCH_LEVEL)
inline
void
QuicPerfCounterAdd(
    _In_ QUIC_PERFORMANCE_COUNTERS Type,
    _In_ int64_t Value
    )
{
    CXPLAT_DBG_ASSERT(Type >= 0 && Type < QUIC_PERF_COUNTER_MAX);
    uint32_t ProcIndex = CxPlatProcCurrentNumber();
    CXPLAT_DBG_ASSERT(ProcIndex < (uint32_t)MsQuicLib.PartitionCount);
    InterlockedExchangeAdd64(&(MsQuicLib.PerProc[ProcIndex].PerfCounters[Type]), Value);
}

#define QuicPerfCounterIncrement(Type) QuicPerfCounterAdd(Type, 1)
#define QuicPerfCounterDecrement(Type) QuicPerfCounterAdd(Type, -1)

#define QUIC_PERF_SAMPLE_INTERVAL_S    30 // 30 seconds

_IRQL_requires_max_(DISPATCH_LEVEL)
void
QuicPerfCounterSnapShot(
    _In_ uint64_t TimeDiffUs
    );

_IRQL_requires_max_(DISPATCH_LEVEL)
inline
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
inline
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
    _Out_ QUIC_BINDING** NewBinding
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
    _In_ const _In_ CXPLAT_RECV_DATA* Datagram
    );

//
// Returns the current stateless retry key.
//
_IRQL_requires_max_(DISPATCH_LEVEL)
_Ret_maybenull_
CXPLAT_KEY*
QuicLibraryGetCurrentStatelessRetryKey(
    void
    );

//
// Returns the stateless retry key for that timestamp.
//
_IRQL_requires_max_(DISPATCH_LEVEL)
_Ret_maybenull_
CXPLAT_KEY*
QuicLibraryGetStatelessRetryKeyForTimestamp(
    _In_ int64_t Timestamp
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
    _In_reads_(MsQuicLib.CidTotalLength)
        const uint8_t* const CID,
    _Out_writes_all_(QUIC_STATELESS_RESET_TOKEN_LENGTH)
        uint8_t* ResetToken
    );

#if defined(__cplusplus)
}
#endif
