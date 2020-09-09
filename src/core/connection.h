/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.

--*/
#ifdef QUIC_CLOG
#include "connection.h.clog.h"
#endif

typedef struct QUIC_LISTENER QUIC_LISTENER;

//
// Connection close flags
//
#define QUIC_CLOSE_SILENT                   0x00000001U // Don't send connection close or wait for response
#define QUIC_CLOSE_SEND_NOTIFICATION        0x00000002U // Send notification to API client
#define QUIC_CLOSE_APPLICATION              0x00000004U // Application closed the connection.
#define QUIC_CLOSE_REMOTE                   0x00000008U // Connection closed remotely.
#define QUIC_CLOSE_QUIC_STATUS              0x00000010U // QUIC_STATUS used for closing.

#define QUIC_CLOSE_INTERNAL QUIC_CLOSE_SEND_NOTIFICATION
#define QUIC_CLOSE_INTERNAL_SILENT (QUIC_CLOSE_INTERNAL | QUIC_CLOSE_SILENT)

//
// Different possible states/flags of a connection.
// Note - Keep quictypes.h's copy up to date.
//
typedef union QUIC_CONNECTION_STATE {
    uint32_t Flags;
    struct {
        BOOLEAN Allocated       : 1;    // Allocated. Used for Debugging.
        BOOLEAN Initialized     : 1;    // Initialized successfully. Used for Debugging.
        BOOLEAN Started         : 1;    // Handshake started.
        BOOLEAN Connected       : 1;    // Handshake completed.
        BOOLEAN ClosedLocally   : 1;    // Locally closed.
        BOOLEAN ClosedRemotely  : 1;    // Remotely closed.
        BOOLEAN AppClosed       : 1;    // Application (not transport) closed connection.
        BOOLEAN HandleShutdown  : 1;    // Shutdown callback delivered for handle.
        BOOLEAN HandleClosed    : 1;    // Handle closed by application layer.
        BOOLEAN Uninitialized   : 1;    // Uninitialize started/completed.
        BOOLEAN Freed           : 1;    // Freed. Used for Debugging.

        //
        // Indicates whether packet number encryption is enabled or not for the
        // connection.
        //
        BOOLEAN HeaderProtectionEnabled : 1;

        BOOLEAN Disable1RttEncrytion : 1;

        //
        // Indicates whether the current 'owner' of the connection is internal
        // or external. Client connections are always externally owned. Server
        // connections are internally owned until they are indicated to the
        // appliciation, via the listener callback.
        //
        BOOLEAN ExternalOwner : 1;

        //
        // This flag indicates the client has gotten response from the server.
        // The response could either be a Retry or server Initial packet. Once
        // this happens, the client must not accept any received Retry packets.
        //
        BOOLEAN GotFirstServerResponse : 1;

        //
        // This flag indicates the Retry packet was used during the handshake.
        //
        BOOLEAN HandshakeUsedRetryPacket : 1;

        //
        // We have confirmed that the peer has completed the handshake.
        //
        BOOLEAN HandshakeConfirmed : 1;

        //
        // The (server side) connection has been accepted by a listener.
        //
        BOOLEAN ListenerAccepted : 1;

        //
        // Indicates whether the local address has been set. It can be set either
        // via the QUIC_PARAM_CONN_LOCAL_ADDRESS parameter by the application, or
        // via UDP binding creation during the connection start phase.
        //
        BOOLEAN LocalAddressSet : 1;

        //
        // Indicates whether the remote address has been set. It can be set either
        // via the QUIC_PARAM_CONN_REMOTE_ADDRESS parameter by the application,
        // before starting the connection, or via name resolution during the
        // connection start phase.
        //
        BOOLEAN RemoteAddressSet : 1;

        //
        // Indicates the peer transport parameters variable has been set.
        //
        BOOLEAN PeerTransportParameterValid : 1;

        //
        // Indicates the connection needs to queue onto a new worker thread.
        //
        BOOLEAN UpdateWorker : 1;

        //
        // The peer didn't acknowledge the shutdown.
        //
        BOOLEAN ShutdownCompleteTimedOut : 1;

        //
        // The application needs to be notified of a shutdown complete event.
        //
        BOOLEAN SendShutdownCompleteNotif : 1;

        //
        // Indicates whether send requests should be buffered.
        //
        BOOLEAN UseSendBuffer : 1;

        //
        // Indicates whether pacing logic is enabled for sending.
        //
        BOOLEAN UsePacing : 1;

        //
        // Indicates whether this connection shares bindings with others.
        //
        BOOLEAN ShareBinding : 1;

        //
        // Indicates the TestTransportParameter variable has been set by the app.
        //
        BOOLEAN TestTransportParameterSet : 1;

        //
        // Indicates the connection is using the round robin stream scheduling
        // scheme.
        //
        BOOLEAN UseRoundRobinStreamScheduling : 1;

        //
        // Indicates that this connection has resumption enabled and needs to
        // keep the TLS state and transport parameters until it is done sending
        // resumption tickets.
        //
        BOOLEAN ResumptionEnabled : 1;

#ifdef QuicVerifierEnabledByAddr
        //
        // The calling app is being verified (app or driver verifier).
        //
        BOOLEAN IsVerifying : 1;
#endif
    };
} QUIC_CONNECTION_STATE;

//
// Different references on a connection.
//
typedef enum QUIC_CONNECTION_REF {

    QUIC_CONN_REF_HANDLE_OWNER,         // Application or Core.
    QUIC_CONN_REF_LOOKUP_TABLE,         // Per registered CID.
    QUIC_CONN_REF_LOOKUP_RESULT,        // For connections returned from lookups.
    QUIC_CONN_REF_WORKER,               // Worker is (queued for) processing.

    QUIC_CONN_REF_COUNT

} QUIC_CONNECTION_REF;

//
// A single timer entry on the connection.
//
typedef struct QUIC_CONN_TIMER_ENTRY {

    //
    // The type of timer this entry is for.
    //
    QUIC_CONN_TIMER_TYPE Type;

    //
    // The absolute time (in us) for timer expiration.
    //
    uint64_t ExpirationTime;

} QUIC_CONN_TIMER_ENTRY;

//
// Per connection statistics.
//
typedef struct QUIC_CONN_STATS {

    uint64_t CorrelationId;

    uint32_t VersionNegotiation     : 1;
    uint32_t StatelessRetry         : 1;
    uint32_t ResumptionAttempted    : 1;
    uint32_t ResumptionSucceeded    : 1;

    //
    // QUIC protocol version used. Network byte order.
    //
    uint32_t QuicVersion;

    //
    // All timing values are in microseconds.
    //
    struct {
        uint64_t Start;
        uint64_t InitialFlightEnd;      // Processed all peer's Initial packets
        uint64_t HandshakeFlightEnd;    // Processed all peer's Handshake packets
    } Timing;

    struct {
        uint32_t LastQueueTime;         // Time the connection last entered the work queue.
        uint64_t DrainCount;            // Sum of drain calls
        uint64_t OperationCount;        // Sum of operations processed
    } Schedule;

    struct {
        uint32_t ClientFlight1Bytes;    // Sum of TLS payloads
        uint32_t ServerFlight1Bytes;    // Sum of TLS payloads
        uint32_t ClientFlight2Bytes;    // Sum of TLS payloads
    } Handshake;

    struct {
        uint64_t TotalPackets;          // QUIC packets; could be coalesced into fewer UDP datagrams.
        uint64_t RetransmittablePackets;
        uint64_t SuspectedLostPackets;
        uint64_t SpuriousLostPackets;   // Actual lost is (SuspectedLostPackets - SpuriousLostPackets)

        uint64_t TotalBytes;            // Sum of UDP payloads
        uint64_t TotalStreamBytes;      // Sum of stream payloads

        uint32_t CongestionCount;
        uint32_t PersistentCongestionCount;
    } Send;

    struct {
        uint64_t TotalPackets;          // QUIC packets; could be coalesced into fewer UDP datagrams.
        uint64_t ReorderedPackets;      // Means not the expected next packet. Could indicate loss gap too.
        uint64_t DroppedPackets;        // Includes DuplicatePackets.
        uint64_t DuplicatePackets;
        uint64_t DecryptionFailures;    // Count of packets that failed to decrypt.
        uint64_t ValidPackets;          // Count of packets that successfully decrypted or had no encryption.

        uint64_t TotalBytes;            // Sum of UDP payloads
        uint64_t TotalStreamBytes;      // Sum of stream payloads
    } Recv;

    struct {
        uint32_t KeyUpdateCount;        // Count of key updates completed.
    } Misc;

} QUIC_CONN_STATS;

//
// Connection-specific state.
//   N.B. In general, all variables should only be written on the QUIC worker
//        thread.
//
typedef struct QUIC_CONNECTION {

    struct QUIC_HANDLE;

    //
    // Link into the session's list of connections.
    //
    QUIC_LIST_ENTRY SessionLink;

    //
    // Link in the worker's connection queue.
    // N.B. Multi-threaded access, synchronized by worker's connection lock.
    //
    QUIC_LIST_ENTRY WorkerLink;

    //
    // Link in the timer wheel's list.
    //
    QUIC_LIST_ENTRY TimerLink;

    //
    // The worker that is processing this connection.
    //
    QUIC_WORKER* Worker;

    //
    // The top level registration this connection is a part of.
    //
    QUIC_REGISTRATION* Registration;

    //
    // The top level session this connection is a part of.
    //
    QUIC_SESSION* Session;

    //
    // Number of references to the handle.
    //
    long RefCount;

#if DEBUG
    //
    // Detailed ref counts
    //
    short RefTypeCount[QUIC_CONN_REF_COUNT];
#endif

    //
    // The current connnection state/flags.
    //
    QUIC_CONNECTION_STATE State;

    //
    // The current worker thread ID. 0 if not being processed right now.
    //
    QUIC_THREAD_ID WorkerThreadID;

    //
    // The set of ignore flags for server certificate validation to pass to TLS.
    //
    uint32_t ServerCertValidationFlags;

    //
    // The server ID for the connection ID.
    //
    uint8_t ServerID[MSQUIC_MAX_CID_SID_LENGTH];

    //
    // The partition ID for the connection ID.
    //
    uint16_t PartitionID;

    //
    // Number of non-retired desintation CIDs we currently have cached.
    //
    uint8_t DestCidCount;

    //
    // The maximum number of source CIDs to give the peer. This is a minimum of
    // what we're willing to support and what the peer is willing to accept.
    //
    uint8_t SourceCidLimit;

    //
    // Number of paths the connection is currently tracking.
    //
    _Field_range_(0, QUIC_MAX_PATH_COUNT)
    uint8_t PathsCount;

    //
    // The next identifier to use for a new path.
    //
    uint8_t NextPathId;

    //
    // Indicates whether a worker is currently processing a connection.
    // N.B. Multi-threaded access, synchronized by worker's connection lock.
    //
    BOOLEAN WorkerProcessing : 1;
    BOOLEAN HasQueuedWork : 1;

    //
    // Set of current reasons sending more packets is currently blocked.
    //
    uint8_t OutFlowBlockedReasons; // Set of QUIC_FLOW_BLOCKED_* flags

    //
    // Ack Delay Exponent. Used to scale actual wire encoded value by
    // 2 ^ ack_delay_exponent.
    //
    uint8_t AckDelayExponent;

    //
    // Maximum amount of time the connection waits before acknowledging a
    // received packet.
    //
    uint32_t MaxAckDelayMs;

    //
    // The idle timeout period (in milliseconds).
    //
    uint64_t IdleTimeoutMs;

    //
    // The handshake idle timeout period (in milliseconds).
    //
    uint64_t HandshakeIdleTimeoutMs;

    //
    // The number of microseconds that must elapse before the connection will be
    // considered 'ACK idle' and disconnects.
    //
    uint32_t DisconnectTimeoutUs;

    //
    // The interval (in milliseconds) between keep alives sent locally.
    //
    uint32_t KeepAliveIntervalMs;

    //
    // The sequence number to use for the next source CID.
    //
    QUIC_VAR_INT NextSourceCidSequenceNumber;

    //
    // The most recent Retire Prior To field received in a NEW_CONNECTION_ID
    // frame.
    //
    QUIC_VAR_INT RetirePriorTo;

    //
    // Per-path state. The first entry in the list is the active path. All the
    // rest (if any) are other tracked paths, sorted from most to least recently
    // used.
    //
    QUIC_PATH Paths[QUIC_MAX_PATH_COUNT];

    //
    // The list of connection IDs used for receiving.
    //
    QUIC_SINGLE_LIST_ENTRY SourceCids;

    //
    // The list of connection IDs used for sending. Given to us by the peer.
    //
    QUIC_LIST_ENTRY DestCids;

    //
    // The original CID used by the Client in its first Initial packet.
    //
    QUIC_CID* OrigDestCID;

    //
    // Sorted array of all timers for the connection.
    //
    QUIC_CONN_TIMER_ENTRY Timers[QUIC_CONN_TIMER_COUNT];

    //
    // Receive packet queue.
    //
    uint32_t ReceiveQueueCount;
    QUIC_RECV_DATAGRAM* ReceiveQueue;
    QUIC_RECV_DATAGRAM** ReceiveQueueTail;
    QUIC_DISPATCH_LOCK ReceiveQueueLock;

    //
    // The queue of operations to process.
    //
    QUIC_OPERATION_QUEUE OperQ;
    QUIC_OPERATION BackUpOper;
    QUIC_API_CONTEXT BackupApiContext;
    uint16_t BackUpOperUsed;

    //
    // The status code used for indicating transport closed notifications.
    //
    QUIC_STATUS CloseStatus;

    //
    // The locally set error code we use for sending the connection close.
    //
    QUIC_VAR_INT CloseErrorCode;

    //
    // The human readable reason for the connection close. UTF-8
    //
    _Null_terminated_
    char* CloseReasonPhrase;

    //
    // The name of the remote server.
    //
    _Field_z_
    const char* RemoteServerName;

    //
    // The entry into the remote hash lookup table, which is used only during the
    // handshake.
    //
    QUIC_REMOTE_HASH_ENTRY* RemoteHashEntry;

    //
    // Transport parameters received from the peer.
    //
    QUIC_TRANSPORT_PARAMETERS PeerTransportParams;

    //
    // Working space for decoded ACK ranges. All ACK frames that are received
    // are first decoded into this range.
    //
    QUIC_RANGE DecodedAckRanges;

    //
    // All the information and management logic for streams.
    //
    QUIC_STREAM_SET Streams;

    //
    // Congestion control state.
    //
    QUIC_CONGESTION_CONTROL CongestionControl;

    //
    // Manages all the information for outstanding sent packets.
    //
    QUIC_LOSS_DETECTION LossDetection;

    //
    // Per-encryption level packet space information.
    //
    QUIC_PACKET_SPACE* Packets[QUIC_ENCRYPT_LEVEL_COUNT];

    //
    // Manages the stream of cryptographic TLS data sent and received.
    //
    QUIC_CRYPTO Crypto;

    //
    // The send manager for the connection.
    //
    QUIC_SEND Send;
    QUIC_SEND_BUFFER SendBuffer;

    //
    // Manages datagrams for the connection.
    //
    QUIC_DATAGRAM Datagram;

    //
    // The handler for the API client's callbacks.
    //
    QUIC_CONNECTION_CALLBACK_HANDLER ClientCallbackHandler;

    //
    // (Server-only) Transport parameters used during handshake.
    // Only non-null when resumption is enabled.
    //
    QUIC_TRANSPORT_PARAMETERS* HandshakeTP;

    //
    // Statistics
    //
    QUIC_CONN_STATS Stats;

    //
    // Mostly test specific state.
    //
    QUIC_PRIVATE_TRANSPORT_PARAMETER TestTransportParameter;

} QUIC_CONNECTION;

//
// Estimates the memory usage for a connection object in the handshake state.
// TODO - Improve this estimate?
//
#define QUIC_CONN_HANDSHAKE_MEMORY_USAGE \
( \
    sizeof(QUIC_CONNECTION) + \
    QUIC_MAX_TLS_SERVER_SEND_BUFFER + \
    QUIC_DEFAULT_STREAM_RECV_BUFFER_SIZE + \
    16384 /* Guess for TLS overhead */ + \
    1024 /* Extra QUIC stuff */ \
)

#ifdef QuicVerifierEnabledByAddr
#define QUIC_CONN_VERIFY(Connection, Expr) \
    if (Connection->State.IsVerifying) { QUIC_FRE_ASSERT(Expr); }
#elif defined(QuicVerifierEnabled)
#define QUIC_CONN_VERIFY(Connection, Expr) \
    if (MsQuicLib.IsVerifying) { QUIC_FRE_ASSERT(Expr); }
#else
#define QUIC_CONN_VERIFY(Connection, Expr)
#endif

//
// Helper to determine if a connection is server side.
//
inline
BOOLEAN
QuicConnIsServer(
    _In_ const QUIC_CONNECTION * const Connection
    )
{
    return ((QUIC_HANDLE*)Connection)->Type == QUIC_HANDLE_TYPE_CONNECTION_SERVER;
}

//
// Helper for checking if a connection is currently closed.
//
inline
BOOLEAN
QuicConnIsClosed(
    _In_ const QUIC_CONNECTION * const Connection
    )
{
    return Connection->State.ClosedLocally || Connection->State.ClosedRemotely;
}

//
// Returns the earliest expiration time across all timers for the connection.
//
inline
uint64_t
QuicConnGetNextExpirationTime(
    _In_ const QUIC_CONNECTION * const Connection
    )
{
    return Connection->Timers[0].ExpirationTime;
}

//
// Helper to get the owning QUIC_CONNECTION for the stream set module.
//
inline
_Ret_notnull_
QUIC_CONNECTION*
QuicStreamSetGetConnection(
    _In_ QUIC_STREAM_SET* StreamSet
    )
{
    return QUIC_CONTAINING_RECORD(StreamSet, QUIC_CONNECTION, Streams);
}

//
// Helper to get the owning QUIC_CONNECTION for the crypto module.
//
inline
_Ret_notnull_
QUIC_CONNECTION*
QuicCryptoGetConnection(
    _In_ QUIC_CRYPTO* Crypto
    )
{
    return QUIC_CONTAINING_RECORD(Crypto, QUIC_CONNECTION, Crypto);
}

//
// Helper to get the owning QUIC_CONNECTION for the send module.
//
inline
_Ret_notnull_
QUIC_CONNECTION*
QuicSendGetConnection(
    _In_ QUIC_SEND* Send
    )
{
    return QUIC_CONTAINING_RECORD(Send, QUIC_CONNECTION, Send);
}

//
// Helper to get the owning QUIC_CONNECTION for the congestion control module.
//
inline
_Ret_notnull_
QUIC_CONNECTION*
QuicCongestionControlGetConnection(
    _In_ QUIC_CONGESTION_CONTROL* Cc
    )
{
    return QUIC_CONTAINING_RECORD(Cc, QUIC_CONNECTION, CongestionControl);
}

//
// Helper to get the QUIC_PACKET_SPACE for a loss detection.
//
inline
_Ret_notnull_
QUIC_CONNECTION*
QuicLossDetectionGetConnection(
    _In_ QUIC_LOSS_DETECTION* LossDetection
    )
{
    return QUIC_CONTAINING_RECORD(LossDetection, QUIC_CONNECTION, LossDetection);
}

//
// Helper to get the owning QUIC_CONNECTION for datagram.
//
inline
_Ret_notnull_
QUIC_CONNECTION*
QuicDatagramGetConnection(
    _In_ const QUIC_DATAGRAM* const Datagram
    )
{
    return QUIC_CONTAINING_RECORD(Datagram, QUIC_CONNECTION, Datagram);
}

inline
void
QuicConnLogOutFlowStats(
    _In_ const QUIC_CONNECTION* const Connection
    )
{
    if (!QuicTraceEventEnabled(ConnOutFlowStats)) {
        return;
    }

    const QUIC_PATH* Path = &Connection->Paths[0];
    UNREFERENCED_PARAMETER(Path);

    QuicTraceEvent(
        ConnOutFlowStats,
        "[conn][%p] OUT: BytesSent=%llu InFlight=%u InFlightMax=%u CWnd=%u SSThresh=%u ConnFC=%llu ISB=%llu PostedBytes=%llu SRtt=%u",
        Connection,
        Connection->Stats.Send.TotalBytes,
        Connection->CongestionControl.BytesInFlight,
        Connection->CongestionControl.BytesInFlightMax,
        Connection->CongestionControl.CongestionWindow,
        Connection->CongestionControl.SlowStartThreshold,
        Connection->Send.PeerMaxData - Connection->Send.OrderedStreamBytesSent,
        Connection->SendBuffer.IdealBytes,
        Connection->SendBuffer.PostedBytes,
        Path->GotFirstRttSample ? Path->SmoothedRtt : 0);

    uint64_t FcAvailable, SendWindow;
    QuicStreamSetGetFlowControlSummary(
        &Connection->Streams,
        &FcAvailable,
        &SendWindow);

    QuicTraceEvent(
        ConnOutFlowStreamStats,
        "[conn][%p] OUT: StreamFC=%llu StreamSendWindow=%llu",
        Connection,
        FcAvailable,
        SendWindow);
}

inline
void
QuicConnLogInFlowStats(
    _In_ const QUIC_CONNECTION* const Connection
    )
{
    UNREFERENCED_PARAMETER(Connection);
    QuicTraceEvent(
        ConnInFlowStats,
        "[conn][%p] IN: BytesRecv=%llu",
        Connection,
        Connection->Stats.Recv.TotalBytes);
}

inline
void
QuicConnLogStatistics(
    _In_ const QUIC_CONNECTION* const Connection
    )
{
    const QUIC_PATH* Path = &Connection->Paths[0];
    UNREFERENCED_PARAMETER(Path);

    QuicTraceEvent(
        ConnStats,
        "[conn][%p] STATS: SRtt=%u CongestionCount=%u PersistentCongestionCount=%u SendTotalBytes=%llu RecvTotalBytes=%llu",
        Connection,
        Path->SmoothedRtt,
        Connection->Stats.Send.CongestionCount,
        Connection->Stats.Send.PersistentCongestionCount,
        Connection->Stats.Send.TotalBytes,
        Connection->Stats.Recv.TotalBytes);

    QuicTraceEvent(
        ConnPacketStats,
        "[conn][%p] STATS: SendTotalPackets=%llu SendSuspectedLostPackets=%llu SendSpuriousLostPackets=%llu RecvTotalPackets=%llu RecvReorderedPackets=%llu RecvDroppedPackets=%llu RecvDuplicatePackets=%llu RecvDecryptionFailures=%llu",
        Connection,
        Connection->Stats.Send.TotalPackets,
        Connection->Stats.Send.SuspectedLostPackets,
        Connection->Stats.Send.SpuriousLostPackets,
        Connection->Stats.Recv.TotalPackets,
        Connection->Stats.Recv.ReorderedPackets,
        Connection->Stats.Recv.DroppedPackets,
        Connection->Stats.Recv.DuplicatePackets,
        Connection->Stats.Recv.DecryptionFailures);
}

inline
BOOLEAN
QuicConnAddOutFlowBlockedReason(
    _In_ QUIC_CONNECTION* Connection,
    _In_ QUIC_FLOW_BLOCK_REASON Reason
    )
{
    if (!(Connection->OutFlowBlockedReasons & Reason)) {
        Connection->OutFlowBlockedReasons |= Reason;
        QuicTraceEvent(
            ConnOutFlowBlocked,
            "[conn][%p] Send Blocked Flags: %hhu",
            Connection,
            Connection->OutFlowBlockedReasons);
        return TRUE;
    }
    return FALSE;
}

inline
BOOLEAN
QuicConnRemoveOutFlowBlockedReason(
    _In_ QUIC_CONNECTION* Connection,
    _In_ QUIC_FLOW_BLOCK_REASON Reason
    )
{
    if ((Connection->OutFlowBlockedReasons & Reason)) {
        Connection->OutFlowBlockedReasons &= ~Reason;
        QuicTraceEvent(
            ConnOutFlowBlocked,
            "[conn][%p] Send Blocked Flags: %hhu",
            Connection,
            Connection->OutFlowBlockedReasons);
        return TRUE;
    }
    return FALSE;
}

//
// Allocates and initializes a connection object. In the client scenario no
// initial datagram exists already, so Datagram is NULL. In the server scenario
// a datagram is the cause of the creation, and is passed in.
//
_IRQL_requires_max_(DISPATCH_LEVEL)
__drv_allocatesMem(Mem)
_Must_inspect_result_
_Success_(return != NULL)
QUIC_CONNECTION*
QuicConnAlloc(
    _In_ QUIC_SESSION* Session,
    _In_opt_ const QUIC_RECV_DATAGRAM* const Datagram
    );

//
// Called to free the memory for a connection.
//
_IRQL_requires_max_(DISPATCH_LEVEL)
void
QuicConnFree(
    _In_ __drv_freesMem(Mem) QUIC_CONNECTION* Connection
    );

//
// Releases the handle usage of the app.
//
_IRQL_requires_max_(DISPATCH_LEVEL)
void
QuicConnCloseHandle(
    _In_ QUIC_CONNECTION* Connection
    );

_IRQL_requires_max_(PASSIVE_LEVEL)
void
QuicConnOnShutdownComplete(
    _In_ QUIC_CONNECTION* Connection
    );

#if DEBUG
_IRQL_requires_max_(DISPATCH_LEVEL)
inline
void
QuicConnValidate(
    _In_ QUIC_CONNECTION* Connection
    )
{
    QUIC_FRE_ASSERT(!Connection->State.Freed);
}
#else
#define QuicConnValidate(Connection)
#endif

//
// Adds a reference to the Connection.
//
_IRQL_requires_max_(DISPATCH_LEVEL)
inline
void
QuicConnAddRef(
    _In_ QUIC_CONNECTION* Connection,
    _In_ QUIC_CONNECTION_REF Ref
    )
{
    QuicConnValidate(Connection);

#if DEBUG
    InterlockedIncrement16((volatile short*)&Connection->RefTypeCount[Ref]);
#else
    UNREFERENCED_PARAMETER(Ref);
#endif

    InterlockedIncrement((volatile long*)&Connection->RefCount);
}

//
// Releases a reference to the Connection and cleans it up if it's the last
// reference.
//
#pragma warning(push)
#pragma warning(disable:6014) // SAL doesn't understand ref counts
_IRQL_requires_max_(DISPATCH_LEVEL)
inline
void
QuicConnRelease(
    _In_ __drv_freesMem(Mem) QUIC_CONNECTION* Connection,
    _In_ QUIC_CONNECTION_REF Ref
    )
{
    QuicConnValidate(Connection);

#if DEBUG
    QUIC_TEL_ASSERT(Connection->RefTypeCount[Ref] > 0);
    uint16_t result = (uint16_t)InterlockedDecrement16((volatile short*)&Connection->RefTypeCount[Ref]);
    QUIC_TEL_ASSERT(result != 0xFFFF);
#else
    UNREFERENCED_PARAMETER(Ref);
#endif

    QUIC_DBG_ASSERT(Connection->RefCount > 0);
    if (InterlockedDecrement((volatile long*)&Connection->RefCount) == 0) {
#if DEBUG
        for (uint32_t i = 0; i < QUIC_CONN_REF_COUNT; i++) {
            QUIC_TEL_ASSERT(Connection->RefTypeCount[i] == 0);
        }
#endif
        if (Ref == QUIC_CONN_REF_LOOKUP_RESULT) {
            //
            // Lookup results cannot be the last ref, as they can result in the
            // datapath binding being deleted on a callback. Instead, queue the
            // connection to be released by the worker.
            //
            QUIC_DBG_ASSERT(Connection->Worker != NULL);
            QuicWorkerQueueConnection(Connection->Worker, Connection);
        } else {
            QuicConnFree(Connection);
        }
    }
}
#pragma warning(pop)

//
// Tracing rundown for the connection.
//
_IRQL_requires_max_(DISPATCH_LEVEL)
void
QuicConnQueueTraceRundown(
    _In_ QUIC_CONNECTION* Connection
    );

//
// Indicates an event to the application layer.
//
_IRQL_requires_max_(PASSIVE_LEVEL)
QUIC_STATUS
QuicConnIndicateEvent(
    _In_ QUIC_CONNECTION* Connection,
    _Inout_ QUIC_CONNECTION_EVENT* Event
    );

//
// Allows the connection to drain some operations that it currently has
// queued up. Returns TRUE if there are still work to do after the function
// returns.
//
_IRQL_requires_max_(PASSIVE_LEVEL)
BOOLEAN
QuicConnDrainOperations(
    _In_ QUIC_CONNECTION* Connection
    );

//
// Applies the settings from the session.
//
_IRQL_requires_max_(PASSIVE_LEVEL)
void
QuicConnApplySettings(
    _In_ QUIC_CONNECTION* Connection,
    _In_ const QUIC_SETTINGS* Settings
    );

//
// Queues a new operation on the connection and queues the connection on a
// worker if necessary.
//
_IRQL_requires_max_(DISPATCH_LEVEL)
void
QuicConnQueueOper(
    _In_ QUIC_CONNECTION* Connection,
    _In_ QUIC_OPERATION* Oper
    );

_IRQL_requires_max_(DISPATCH_LEVEL)
void
QuicConnQueueHighestPriorityOper(
    _In_ QUIC_CONNECTION* Connection,
    _In_ QUIC_OPERATION* Oper
    );

//
// Generates a new source connection ID.
//
_IRQL_requires_max_(PASSIVE_LEVEL)
QUIC_CID_HASH_ENTRY*
QuicConnGenerateNewSourceCid(
    _In_ QUIC_CONNECTION* Connection,
    _In_ BOOLEAN IsInitial
    );

//
// Generates any necessary source CIDs.
//
_IRQL_requires_max_(PASSIVE_LEVEL)
void
QuicConnGenerateNewSourceCids(
    _In_ QUIC_CONNECTION* Connection,
    _In_ BOOLEAN ReplaceExistingCids
    );

//
// Retires the currently used destination connection ID.
//
_IRQL_requires_max_(PASSIVE_LEVEL)
BOOLEAN
QuicConnRetireCurrentDestCid(
    _In_ QUIC_CONNECTION* Connection,
    _In_ QUIC_PATH* Path
    );

//
// Look up a source CID by sequence number.
//
_IRQL_requires_max_(DISPATCH_LEVEL)
_Success_(return != NULL)
inline
QUIC_CID_HASH_ENTRY*
QuicConnGetSourceCidFromSeq(
    _In_ QUIC_CONNECTION* Connection,
    _In_ QUIC_VAR_INT SequenceNumber,
    _In_ BOOLEAN RemoveFromList,
    _Out_ BOOLEAN* IsLastCid
    )
{
    for (QUIC_SINGLE_LIST_ENTRY** Entry = &Connection->SourceCids.Next;
            *Entry != NULL;
            Entry = &(*Entry)->Next) {
        QUIC_CID_HASH_ENTRY* SourceCid =
            QUIC_CONTAINING_RECORD(
                *Entry,
                QUIC_CID_HASH_ENTRY,
                Link);
        if (SourceCid->CID.SequenceNumber == SequenceNumber) {
            if (RemoveFromList) {
                QuicBindingRemoveSourceConnectionID(
                    Connection->Paths[0].Binding,
                    SourceCid);
                QuicTraceEvent(
                    ConnSourceCidRemoved,
                    "[conn][%p] (SeqNum=%llu) Removed Source CID: %!CID!",
                    Connection,
                    SourceCid->CID.SequenceNumber,
                    CLOG_BYTEARRAY(SourceCid->CID.Length, SourceCid->CID.Data));
                *Entry = (*Entry)->Next;
            }
            *IsLastCid = Connection->SourceCids.Next == NULL;
            return SourceCid;
        }
    }
    return NULL;
}

//
// Look up a source CID by data buffer.
//
_IRQL_requires_max_(DISPATCH_LEVEL)
inline
QUIC_CID_HASH_ENTRY*
QuicConnGetSourceCidFromBuf(
    _In_ QUIC_CONNECTION* Connection,
    _In_ uint8_t CidLength,
    _In_reads_(CidLength)
        const uint8_t* CidBuffer
    )
{
    for (QUIC_SINGLE_LIST_ENTRY* Entry = Connection->SourceCids.Next;
            Entry != NULL;
            Entry = Entry->Next) {
        QUIC_CID_HASH_ENTRY* SourceCid =
            QUIC_CONTAINING_RECORD(
                Entry,
                QUIC_CID_HASH_ENTRY,
                Link);
        if (CidLength == SourceCid->CID.Length &&
            memcmp(CidBuffer, SourceCid->CID.Data, CidLength) == 0) {
            return SourceCid;
        }
    }
    return NULL;
}

//
// Look up a source CID by sequence number.
//
_IRQL_requires_max_(DISPATCH_LEVEL)
inline
QUIC_CID_QUIC_LIST_ENTRY*
QuicConnGetDestCidFromSeq(
    _In_ QUIC_CONNECTION* Connection,
    _In_ QUIC_VAR_INT SequenceNumber,
    _In_ BOOLEAN RemoveFromList
    )
{
    for (QUIC_LIST_ENTRY* Entry = Connection->DestCids.Flink;
            Entry != &Connection->DestCids;
            Entry = Entry->Flink) {
        QUIC_CID_QUIC_LIST_ENTRY* DestCid =
            QUIC_CONTAINING_RECORD(
                Entry,
                QUIC_CID_QUIC_LIST_ENTRY,
                Link);
        if (DestCid->CID.SequenceNumber == SequenceNumber) {
            if (RemoveFromList) {
                QuicListEntryRemove(Entry);
            }
            return DestCid;
        }
    }
    return NULL;
}

//
// Adds a sample (in microsec) to the connection's RTT estimator.
//
_IRQL_requires_max_(PASSIVE_LEVEL)
void
QuicConnUpdateRtt(
    _In_ QUIC_CONNECTION* Connection,
    _In_ QUIC_PATH* Path,
    _In_ uint32_t LatestRtt
    );

//
// Sets a new timer delay in milliseconds.
//
_IRQL_requires_max_(PASSIVE_LEVEL)
void
QuicConnTimerSet(
    _Inout_ QUIC_CONNECTION* Connection,
    _In_ QUIC_CONN_TIMER_TYPE Type,
    _In_ uint64_t DelayMs
    );

//
// Cancels a timer.
//
_IRQL_requires_max_(PASSIVE_LEVEL)
void
QuicConnTimerCancel(
    _Inout_ QUIC_CONNECTION* Connection,
    _In_ QUIC_CONN_TIMER_TYPE Type
    );

//
// Called when the next timer(s) expire.
//
_IRQL_requires_max_(PASSIVE_LEVEL)
void
QuicConnTimerExpired(
    _Inout_ QUIC_CONNECTION* Connection,
    _In_ uint64_t TimeNow
    );

//
// Called when the QUIC version is set.
//
_IRQL_requires_max_(PASSIVE_LEVEL)
void
QuicConnOnQuicVersionSet(
    _In_ QUIC_CONNECTION* Connection
    );

//
// Called when the local address is changed.
//
_IRQL_requires_max_(PASSIVE_LEVEL)
void
QuicConnOnLocalAddressChanged(
    _In_ QUIC_CONNECTION* Connection
    );

//
// Starts the connection.
//
_IRQL_requires_max_(PASSIVE_LEVEL)
QUIC_STATUS
QuicConnStart(
    _In_ QUIC_CONNECTION* Connection,
    _In_ QUIC_ADDRESS_FAMILY Family,
    _In_opt_z_ const char* ServerName,
    _In_ uint16_t ServerPort // Host byte order
    );

//
// Restarts the connection with the current configuration.
//
_IRQL_requires_max_(PASSIVE_LEVEL)
void
QuicConnRestart(
    _In_ QUIC_CONNECTION* Connection,
    _In_ BOOLEAN CompleteReset
    );

//
// Process peer's transport parameters and updates connection state
// accordingly.
//
_IRQL_requires_max_(PASSIVE_LEVEL)
void
QuicConnProcessPeerTransportParameters(
    _In_ QUIC_CONNECTION* Connection,
    _In_ BOOLEAN FromCache
    );

//
// Configures the security config.
//
_IRQL_requires_max_(PASSIVE_LEVEL)
QUIC_STATUS
QuicConnHandshakeConfigure(
    _In_ QUIC_CONNECTION* Connection,
    _In_opt_ QUIC_SEC_CONFIG* SecConfig
    );

//
// Check if the resumption state is ready to be cleaned up and free it.
//
// Called when the server has sent everything it will ever send and it has all
// been acknowledged.
//
_IRQL_requires_max_(PASSIVE_LEVEL)
void
QuicConnCleanupServerResumptionState(
    _In_ QUIC_CONNECTION* Connection
    );

//
// Discard any 0-RTT deferred datagrams.
//
_IRQL_requires_max_(PASSIVE_LEVEL)
void
QuicConnDiscardDeferred0Rtt(
    _In_ QUIC_CONNECTION* Connection
    );

//
// Processes deferred datagrams for newly derived read keys.
//
_IRQL_requires_max_(PASSIVE_LEVEL)
void
QuicConnFlushDeferred(
    _In_ QUIC_CONNECTION* Connection
    );

//
// Starts the (async) process of closing the connection locally.
//
_IRQL_requires_max_(PASSIVE_LEVEL)
void
QuicConnCloseLocally(
    _In_ QUIC_CONNECTION* Connection,
    _In_ uint32_t Flags,
    _In_ uint64_t ErrorCode,
    _In_opt_z_ const char* ErrorMsg
    );

//
// Close the connection for a transport protocol error.
//
_IRQL_requires_max_(PASSIVE_LEVEL)
inline
void
QuicConnTransportError(
    _In_ QUIC_CONNECTION* Connection,
    _In_ uint64_t ErrorCode
    )
{
    QuicConnCloseLocally(Connection, QUIC_CLOSE_INTERNAL, ErrorCode, NULL);
}

//
// Helper function for internal code to immediately trigger a connection
// close in response to a fatal error.
//
_IRQL_requires_max_(PASSIVE_LEVEL)
inline
void
QuicConnFatalError(
    _In_ QUIC_CONNECTION* Connection,
    _In_ QUIC_STATUS Status,
    _In_opt_z_ const char* ErrorMsg
    )
{
    QuicConnCloseLocally(
        Connection,
        QUIC_CLOSE_INTERNAL | QUIC_CLOSE_QUIC_STATUS,
        (uint64_t)Status,
        ErrorMsg);
}

//
// Helper function to immediately, silently close the connection completely
// down, independent of the current state.
//
_IRQL_requires_max_(PASSIVE_LEVEL)
inline
void
QuicConnSilentlyAbort(
    _In_ QUIC_CONNECTION* Connection
    )
{
    QuicConnCloseLocally(
        Connection,
        QUIC_CLOSE_INTERNAL | QUIC_CLOSE_QUIC_STATUS | QUIC_CLOSE_SILENT,
        (uint64_t)QUIC_STATUS_ABORTED,
        NULL);
}

//
// Called in response to sending or receiving a new packet.
//
_IRQL_requires_max_(PASSIVE_LEVEL)
void
QuicConnResetIdleTimeout(
    _In_ QUIC_CONNECTION* Connection
    );

//
// Queues a received UDP datagram chain to a connection for processing.
//
_IRQL_requires_max_(DISPATCH_LEVEL)
void
QuicConnQueueRecvDatagrams(
    _In_ QUIC_CONNECTION* Connection,
    _In_ QUIC_RECV_DATAGRAM* DatagramChain,
    _In_ uint32_t DatagramChainLength
    );

//
// Queues an unreachable event to a connection for processing.
//
_IRQL_requires_max_(DISPATCH_LEVEL)
void
QuicConnQueueUnreachable(
    _In_ QUIC_CONNECTION* Connection,
    _In_ const QUIC_ADDR* RemoteAddress
    );

//
// Sets a connection parameter.
//
_IRQL_requires_max_(PASSIVE_LEVEL)
QUIC_STATUS
QuicConnParamSet(
    _In_ QUIC_CONNECTION* Connection,
    _In_ uint32_t Param,
    _In_ uint32_t BufferLength,
    _In_reads_bytes_(BufferLength)
        const void* Buffer
    );

//
// Gets a connection parameter.
//
_IRQL_requires_max_(PASSIVE_LEVEL)
QUIC_STATUS
QuicConnParamGet(
    _In_ QUIC_CONNECTION* Connection,
    _In_ uint32_t Param,
    _Inout_ uint32_t* BufferLength,
    _Out_writes_bytes_opt_(*BufferLength)
        void* Buffer
    );
