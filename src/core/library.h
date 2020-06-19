/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.

--*/

//
// The different possible types of handles.
//
typedef enum QUIC_HANDLE_TYPE {

    QUIC_HANDLE_TYPE_REGISTRATION,
    QUIC_HANDLE_TYPE_SESSION,
    QUIC_HANDLE_TYPE_LISTENER,
    QUIC_HANDLE_TYPE_CLIENT,
    QUIC_HANDLE_TYPE_CHILD,
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
    QUIC_POOL ConnectionPool;

    //
    // Pool for QUIC_TRANSPORT_PARAMETERs.
    //
    QUIC_POOL TransportParamPool;

} QUIC_LIBRARY_PP;

//
// Represents the storage for global library state.
//
typedef struct QUIC_LIBRARY {

    //
    // Tracks whether the library loaded (DllMain or DriverEntry invoked on Windows).
    //
    BOOLEAN Loaded : 1;

#ifdef QuicVerifierEnabled
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
    // Indicates encryption is enabled or disabled for new connections.
    // Defaults to FALSE.
    //
    BOOLEAN EncryptionDisabled;

    //
    // Index for the current stateless retry token key.
    //
    BOOLEAN CurrentStatelessRetryKey;

    //
    // Configurable (app & registry) settings.
    //
    QUIC_SETTINGS Settings;

    //
    // Controls access to all non-datapath internal state of the library.
    //
    QUIC_LOCK Lock;

    //
    // Controls access to all datapath internal state of the library.
    //
    QUIC_DISPATCH_LOCK DatapathLock;

    //
    // Total outstanding references on the library.
    //
    uint32_t RefCount;

    //
    // Number of partitions currently being used.
    //
    _Field_range_(>, 0)
    uint8_t PartitionCount;

    //
    // Mask for the worker index in the connection's partition ID.
    //
    uint8_t PartitionMask;

#if DEBUG
    //
    // Number of connections current allocated.
    //
    long ConnectionCount;
#endif

    //
    // Next worker to use in the pool.
    //
    uint8_t NextWorkerIndex;

    //
    // Estimated timer resolution for the platform.
    //
    uint8_t TimerResolutionMs;

    //
    // Length of various parts of locally generated connection IDs.
    //
    _Field_range_(MSQUIC_MIN_CID_SID_LENGTH, MSQUIC_MAX_CID_SID_LENGTH)
    uint8_t CidServerIdLength;
    // uint8_t CidPartitionIdLength; // Currently hard coded (MSQUIC_CID_PID_LENGTH)
    _Field_range_(QUIC_MIN_INITIAL_CONNECTION_ID_LENGTH, MSQUIC_CID_MAX_LENGTH)
    uint8_t CidTotalLength;

    //
    // An identifier used for correlating connection logs and statistics.
    //
    uint64_t ConnectionCorrelationId;

    //
    // The estiamted current total memory usage for handshake connections.
    //
    uint64_t CurrentHandshakeMemoryUsage;

    //
    // Handle to global persistent storage (registry).
    //
    QUIC_STORAGE* Storage;

    //
    // Datapath instance for the library.
    //
    QUIC_DATAPATH* Datapath;

    //
    // List of all registrations in the current process (or kernel).
    //
    QUIC_LIST_ENTRY Registrations;

    //
    // List of all UDP bindings in the current process (or kernel).
    //
    QUIC_LIST_ENTRY Bindings;

    //
    // Contains all (server) connections currently not in an app's registration.
    //
    QUIC_SESSION* UnregisteredSession;

    //
    // Set of workers that manage processing client Initial packets on the
    // server side.
    //
    QUIC_WORKER_POOL* WorkerPool;

    //
    // Per-processor storage. Count of `PartitionCount`.
    //
    _Field_size_(PartitionCount)
    QUIC_LIBRARY_PP* PerProc;

    //
    // Controls access to the stateless retry keys when rotated.
    //
    QUIC_LOCK StatelessRetryKeysLock;

    //
    // Keys used for encryption of stateless retry tokens.
    //
    QUIC_KEY* StatelessRetryKeys[2];

    //
    // Timestamp when the current stateless retry key expires.
    //
    int64_t StatelessRetryKeysExpiration[2];

    //
    // The Toeplitz hash used for hashing received long header packets.
    //
    QUIC_TOEPLITZ_HASH ToeplitzHash;

#if QUIC_TEST_DATAPATH_HOOKS_ENABLED
    //
    // An optional callback to allow test code to modify the data path.
    //
    QUIC_TEST_DATAPATH_HOOKS* TestDatapathHooks;
#endif

} QUIC_LIBRARY;

extern QUIC_LIBRARY MsQuicLib;

#ifdef QuicVerifierEnabled
#define QUIC_LIB_VERIFY(Expr) \
    if (MsQuicLib.IsVerifying) { QUIC_FRE_ASSERT(Expr); }
#else
#define QUIC_LIB_VERIFY(Expr)
#endif

_IRQL_requires_max_(DISPATCH_LEVEL)
_Ret_range_(0,MsQuicLib.PartitionCount - 1)
inline
uint8_t
QuicLibraryGetCurrentPartition(
    void
    )
{
    return ((uint8_t)QuicProcCurrentNumber()) % MsQuicLib.PartitionCount;
}

_IRQL_requires_max_(DISPATCH_LEVEL)
inline
uint8_t
QuicPartitionIdCreate(
    uint8_t BaseIndex
    )
{
    QUIC_DBG_ASSERT(BaseIndex < MsQuicLib.PartitionCount);
    //
    // Generate a partition ID which is a combination of random high bits and
    // the actual partitioning index encoded in the low bits.
    //
    // N.B. The following logic can leak the number of partitions if not a power
    // of two. This is because we use a bit mask to split the two parts of the
    // ID.
    //
    uint8_t PartitionId;
    QuicRandom(sizeof(PartitionId), &PartitionId);
    return (PartitionId & ~MsQuicLib.PartitionMask) | BaseIndex;
}

_IRQL_requires_max_(DISPATCH_LEVEL)
inline
uint8_t
QuicPartitionIdGetIndex(
    uint8_t PartitionId
    )
{
    return (PartitionId & MsQuicLib.PartitionMask) % MsQuicLib.PartitionCount;
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
    _In_ uint8_t PartitionID,
    _In_ uint8_t PrefixLength,
    _In_reads_(PrefixLength)
        const void* Prefix
    )
{
    QUIC_DBG_ASSERT(MsQuicLib.CidTotalLength <= QUIC_MAX_CONNECTION_ID_LENGTH_V1);
    QUIC_DBG_ASSERT(MsQuicLib.CidTotalLength == MsQuicLib.CidServerIdLength + 1 + MSQUIC_CID_PAYLOAD_LENGTH);
    QUIC_DBG_ASSERT(MSQUIC_CID_PAYLOAD_LENGTH > PrefixLength);

    QUIC_CID_HASH_ENTRY* Entry =
        (QUIC_CID_HASH_ENTRY*)
        QUIC_ALLOC_NONPAGED(
            sizeof(QUIC_CID_HASH_ENTRY) +
            MsQuicLib.CidTotalLength);

    if (Entry != NULL) {
        Entry->Connection = Connection;
        QuicZeroMemory(&Entry->CID, sizeof(Entry->CID));
        Entry->CID.Length = MsQuicLib.CidTotalLength;

        uint8_t* Data = Entry->CID.Data;
        if (ServerID != NULL) {
            QuicCopyMemory(Data, ServerID, MsQuicLib.CidServerIdLength);
        } else {
            QuicRandom(MsQuicLib.CidServerIdLength, Data);
        }
        Data += MsQuicLib.CidServerIdLength;

        QUIC_STATIC_ASSERT(MSQUIC_CID_PID_LENGTH == 1, "Assumes a single byte PID");
        *Data = PartitionID;
        Data++;

        QuicCopyMemory(Data, Prefix, PrefixLength);
        Data += PrefixLength;

        QuicRandom(MSQUIC_CID_PAYLOAD_LENGTH - PrefixLength, Data);
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
    _In_ QUIC_PARAM_LEVEL Level,
    _In_ uint32_t Param,
    _In_ uint32_t BufferLength,
    _In_reads_bytes_(BufferLength)
        const void* Buffer
    );

_IRQL_requires_max_(PASSIVE_LEVEL)
QUIC_STATUS
QuicLibraryGetParam(
    _In_ HQUIC Handle,
    _In_ QUIC_PARAM_LEVEL Level,
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
    _In_ QUIC_SESSION* Session,
    _In_ BOOLEAN ShareBinding,
    _In_ BOOLEAN ServerOwned,
    _In_opt_ const QUIC_ADDR * LocalAddress,
    _In_opt_ const QUIC_ADDR * RemoteAddress,
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
    void
    );

//
// Returns the current stateless retry key.
//
_IRQL_requires_max_(PASSIVE_LEVEL)
_Ret_maybenull_
QUIC_KEY*
QuicLibraryGetCurrentStatelessRetryKey(
    void
    );

//
// Returns the stateless retry key for that timestamp.
//
_IRQL_requires_max_(PASSIVE_LEVEL)
_Ret_maybenull_
QUIC_KEY*
QuicLibraryGetStatelessRetryKeyForTimestamp(
    _In_ int64_t Timestamp
    );
