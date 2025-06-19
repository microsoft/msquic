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
    uint64_t Flags;
    struct {
        BOOLEAN Allocated       : 1;    // Allocated. Used for Debugging.
        BOOLEAN Initialized     : 1;    // Initialized successfully. Used for Debugging.
        BOOLEAN Started         : 1;    // Handshake started.
        BOOLEAN Connected       : 1;    // Handshake completed.
        BOOLEAN ClosedLocally   : 1;    // Locally closed.
        BOOLEAN ClosedRemotely  : 1;    // Remotely closed.
        BOOLEAN AppClosed       : 1;    // Application (not transport) closed connection.
        BOOLEAN ShutdownComplete : 1;   // Shutdown callback delivered for handle.
        BOOLEAN HandleClosed    : 1;    // Handle closed by application layer.
        BOOLEAN Freed           : 1;    // Freed. Used for Debugging.

        //
        // Indicates whether packet number encryption is enabled or not for the
        // connection.
        //
        BOOLEAN HeaderProtectionEnabled : 1; // TODO - Remove since it's not used

        //
        // Indicates that 1-RTT encryption has been configured/negotiated to be
        // disabled.
        //
        BOOLEAN Disable1RttEncrytion : 1;

        //
        // Indicates whether the current 'owner' of the connection is internal
        // or external. Client connections are always externally owned. Server
        // connections are internally owned until they are indicated to the
        // appliciation, via the listener callback.
        //
        BOOLEAN ExternalOwner : 1;

        //
        // Indicate the connection is currently in the registration's list of
        // connections and needs to be removed.
        //
        BOOLEAN Registered : 1;

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
        // The connection is shutdown and the completion for it needs to be run.
        //
        BOOLEAN ProcessShutdownComplete : 1;

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

        //
        // When true, this indicates that the connection is currently executing
        // an API call inline (from a reentrant call on a callback).
        //
        BOOLEAN InlineApiExecution : 1;

        //
        // True when a server attempts Compatible Version Negotiation
        BOOLEAN CompatibleVerNegotiationAttempted : 1;

        //
        // True once a client connection has completed a compatible version
        // negotiation, and false otherwise. Used to prevent packets with invalid
        // version fields from being accepted.
        //
        BOOLEAN CompatibleVerNegotiationCompleted : 1;

        //
        // When true, this indicates the app has set the local interface index.
        //
        BOOLEAN LocalInterfaceSet : 1;

        //
        // This value of the fixed bit on send packets.
        //
        BOOLEAN FixedBit : 1;

        //
        // Indicates that the peer accepts RELIABLE_RESET kind of frames, in addition to RESET_STREAM frames.
        //
        BOOLEAN ReliableResetStreamNegotiated : 1;

        //
        // Sending timestamps has been negotiated.
        //
        BOOLEAN TimestampSendNegotiated : 1;

        //
        // Receiving timestamps has been negotiated.
        //
        BOOLEAN TimestampRecvNegotiated : 1;

        //
        // Indicates we received APPLICATION_ERROR transport error and are checking also
        // later packets in case they contain CONNECTION_CLOSE frame with application-layer error.
        //
        BOOLEAN DelayedApplicationError : 1;

#ifdef CxPlatVerifierEnabledByAddr
        //
        // The calling app is being verified (app or driver verifier).
        //
        BOOLEAN IsVerifying : 1;
#endif

#if QUIC_TEST_DISABLE_VNE_TP_GENERATION
        //
        // Whether to disable automatic generation of VNE transport parameter.
        // Only used for testing, and thus only enabled for debug builds.
        //
        BOOLEAN DisableVneTp : 1;
#endif
    };
} QUIC_CONNECTION_STATE;

CXPLAT_STATIC_ASSERT(sizeof(QUIC_CONNECTION_STATE) == sizeof(uint64_t), "Ensure correct size/type");

//
// Different references on a connection.
//
typedef enum QUIC_CONNECTION_REF {

    QUIC_CONN_REF_HANDLE_OWNER,         // Application or Core.
    QUIC_CONN_REF_LOOKUP_TABLE,         // Per registered CID.
    QUIC_CONN_REF_LOOKUP_RESULT,        // For connections returned from lookups.
    QUIC_CONN_REF_WORKER,               // Worker is (queued for) processing.
    QUIC_CONN_REF_TIMER_WHEEL,          // The timer wheel is tracking the connection.
    QUIC_CONN_REF_ROUTE,                // Route resolution is undergoing.
    QUIC_CONN_REF_STREAM,               // A stream depends on the connection.

    QUIC_CONN_REF_COUNT

} QUIC_CONNECTION_REF;

//
// Per connection statistics.
//
typedef struct QUIC_CONN_STATS {

    uint64_t CorrelationId;

    uint32_t VersionNegotiation     : 1;
    uint32_t StatelessRetry         : 1;
    uint32_t ResumptionAttempted    : 1;
    uint32_t ResumptionSucceeded    : 1;
    uint32_t GreaseBitNegotiated    : 1;
    uint32_t EncryptionOffloaded    : 1;

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
        int64_t PhaseShift;             // Time between local and peer epochs
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
        uint8_t HandshakeHopLimitTTL;   // TTL value in the initial packet of the handshake.
    } Handshake;

    struct {
        uint64_t TotalPackets;          // QUIC packets; could be coalesced into fewer UDP datagrams.
        uint64_t RetransmittablePackets;
        uint64_t SuspectedLostPackets;
        uint64_t SpuriousLostPackets;   // Actual lost is (SuspectedLostPackets - SpuriousLostPackets)

        uint64_t TotalBytes;            // Sum of UDP payloads
        uint64_t TotalStreamBytes;      // Sum of stream payloads

        uint32_t CongestionCount;
        uint32_t EcnCongestionCount;
        uint32_t PersistentCongestionCount;
    } Send;

    struct {
        uint64_t TotalPackets;          // QUIC packets; could be coalesced into fewer UDP datagrams.
        uint64_t ReorderedPackets;      // Packets where packet number is less than highest seen.
        uint64_t DroppedPackets;        // Includes DuplicatePackets.
        uint64_t DuplicatePackets;
        uint64_t DecryptionFailures;    // Count of packets that failed to decrypt.
        uint64_t ValidPackets;          // Count of packets that successfully decrypted or had no encryption.
        uint64_t ValidAckFrames;        // Count of receive ACK frames.

        uint64_t TotalBytes;            // Sum of UDP payloads
        uint64_t TotalStreamBytes;      // Sum of stream payloads
    } Recv;

    struct {
        uint32_t KeyUpdateCount;        // Count of key updates completed.
        uint32_t DestCidUpdateCount;    // Number of times the destination CID changed.
    } Misc;

} QUIC_CONN_STATS;

//
// Connection-specific state.
//   N.B. In general, all variables should only be written on the QUIC worker
//        thread.
//
typedef struct QUIC_CONNECTION {

#ifdef __cplusplus
    struct QUIC_HANDLE _;
#else
    struct QUIC_HANDLE;
#endif

    //
    // Link into the registrations's list of connections.
    //
    CXPLAT_LIST_ENTRY RegistrationLink;

    //
    // Link in the worker's connection queue.
    // N.B. Multi-threaded access, synchronized by worker's connection lock.
    //
    CXPLAT_LIST_ENTRY WorkerLink;

    //
    // Link in the timer wheel's list.
    //
    CXPLAT_LIST_ENTRY TimerLink;

    //
    // The worker that is processing this connection.
    //
    QUIC_WORKER* Worker;

    //
    // The partition this connection is currently assigned to. It is changed at
    // the same time as the worker, but doesn't always need to stay in sync with
    // the worker.
    //
    QUIC_PARTITION* Partition;

    //
    // The top level registration this connection is a part of.
    //
    QUIC_REGISTRATION* Registration;

    //
    // The configuration for this connection.
    //
    QUIC_CONFIGURATION* Configuration;

    //
    // The settings for this connection. Some values may be inherited from the
    // global settings, the configuration setting or explicitly set by the app.
    //
    QUIC_SETTINGS_INTERNAL Settings;

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
    CXPLAT_THREAD_ID WorkerThreadID;

    //
    // The server ID for the connection ID.
    //
    uint8_t ServerID[QUIC_MAX_CID_SID_LENGTH];

    //
    // The partition ID for the connection ID.
    //
    uint16_t PartitionID;

    //
    // Number of non-retired desintation CIDs we currently have cached.
    //
    uint8_t DestCidCount;

    //
    // Number of retired desintation CIDs we currently have cached.
    //
    uint8_t RetiredDestCidCount;

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
    BOOLEAN HasPriorityWork : 1;

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
    // The number of packets that must be received before eliciting an immediate
    // acknowledgment. May be updated by the peer via the ACK_FREQUENCY frame.
    //
    uint8_t PacketTolerance;

    //
    // The number of packets we want the peer to wait before sending an
    // immediate acknowledgment. Requires the ACK_FREQUENCY extension/frame to
    // be able to send to the peer.
    //
    uint8_t PeerPacketTolerance;

    //
    // The maximum number of packets that can be out of order before an immediate
    // acknowledgment (ACK) is triggered. If no specific instructions (ACK_FREQUENCY
    // frames) are received from the peer, the receiver will immediately acknowledge
    // any out-of-order packets, which means the default value is 1. A value of 0
    // means out-of-order packets do not trigger an immediate ACK.
    //
    uint8_t ReorderingThreshold;

    //
    // The maximum number of packets that the peer can be out of order before an immediate
    // acknowledgment (ACK) is triggered.
    //
    uint8_t PeerReorderingThreshold;

    //
    // DSCP value to set on all sends from this connection.
    // Default value of 0.
    //
    uint8_t DSCP;

    //
    // The ACK frequency sequence number we are currently using to send.
    //
    uint64_t SendAckFreqSeqNum;

    //
    // The next ACK frequency sequence number we expect to receive.
    //
    uint64_t NextRecvAckFreqSeqNum;

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
    CXPLAT_SLIST_ENTRY SourceCids;

    //
    // The list of connection IDs used for sending. Given to us by the peer.
    //
    CXPLAT_LIST_ENTRY DestCids;

    //
    // The original CID used by the Client in its first Initial packet.
    //
    QUIC_CID* OrigDestCID;

    //
    // An app configured prefix for all connection IDs. The first byte indicates
    // the length of the ID, the second byte the offset of the ID in the CID and
    // the rest payload of the identifier.
    //
    uint8_t CibirId[2 + QUIC_MAX_CIBIR_LENGTH];

    //
    // Expiration time (absolute time in us) for each timer type. We use UINT64_MAX as a sentinel
    // to indicate that the timer is not set.
    //
    uint64_t ExpirationTimes[QUIC_CONN_TIMER_COUNT];

    //
    // Earliest expiration time of all timers types.
    //
    uint64_t EarliestExpirationTime;

    //
    // Timestamp (us) of when we last queued up a connection close (or
    // application close) response to be sent.
    //
    uint64_t LastCloseResponseTimeUs;

    //
    // Receive packet queue.
    //
    uint32_t ReceiveQueueCount;
    uint32_t ReceiveQueueByteCount;
    QUIC_RX_PACKET* ReceiveQueue;
    QUIC_RX_PACKET** ReceiveQueueTail;
    CXPLAT_DISPATCH_LOCK ReceiveQueueLock;

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

    //
    // Struct to log TLS traffic secrets. The app will have to read and
    // format the struct once the connection is connected.
    //
    QUIC_TLS_SECRETS* TlsSecrets;

    //
    // Previously-attempted QUIC version, after Incompatible Version Negotiation.
    //
    uint32_t PreviousQuicVersion;

    //
    // Initially-attempted QUIC version.
    // Only populated during compatible version negotiation.
    //
    uint32_t OriginalQuicVersion;

    //
    // The size of the keep alive padding.
    //
    uint16_t KeepAlivePadding;

    //
    // Connection blocked timings.
    //
    struct {
        QUIC_FLOW_BLOCKED_TIMING_TRACKER Scheduling;
        QUIC_FLOW_BLOCKED_TIMING_TRACKER Pacing;
        QUIC_FLOW_BLOCKED_TIMING_TRACKER AmplificationProt;
        QUIC_FLOW_BLOCKED_TIMING_TRACKER CongestionControl;
        QUIC_FLOW_BLOCKED_TIMING_TRACKER FlowControl;
    } BlockedTimings;

} QUIC_CONNECTION;

typedef struct QUIC_SERIALIZED_RESUMPTION_STATE {

    uint32_t QuicVersion;
    QUIC_TRANSPORT_PARAMETERS TransportParameters;
    uint16_t ServerNameLength;
    uint8_t Buffer[0]; // ServerName and TLS Session/Ticket

} QUIC_SERIALIZED_RESUMPTION_STATE;

//
// Estimates the memory usage for a connection object in the handshake state.
//
#define QUIC_CONN_HANDSHAKE_MEMORY_USAGE \
( \
    sizeof(QUIC_CONNECTION) + \
    QUIC_MAX_TLS_SERVER_SEND_BUFFER + \
    QUIC_DEFAULT_STREAM_RECV_BUFFER_SIZE + \
    16384 /* Guess for TLS overhead */ + \
    1024 /* Extra QUIC stuff */ \
)

#if DEBUG // Enable all verifier checks in debug builds
#define QUIC_CONN_VERIFY(Connection, Expr) CXPLAT_FRE_ASSERT(Expr)
#elif defined(CxPlatVerifierEnabledByAddr)
#define QUIC_CONN_VERIFY(Connection, Expr) \
    if (Connection->State.IsVerifying) { CXPLAT_FRE_ASSERT(Expr); }
#elif defined(CxPlatVerifierEnabled)
#define QUIC_CONN_VERIFY(Connection, Expr) \
    if (MsQuicLib.IsVerifying) { CXPLAT_FRE_ASSERT(Expr); }
#else
#define QUIC_CONN_VERIFY(Connection, Expr)
#endif

#define QuicConnAllocOperation(Connection, Type) \
    QuicOperationAlloc((Connection)->Partition, (Type))

//
// Helper to determine if a connection is server side.
//
QUIC_INLINE
BOOLEAN
QuicConnIsServer(
    _In_ const QUIC_CONNECTION * const Connection
    )
{
    return ((QUIC_HANDLE*)Connection)->Type == QUIC_HANDLE_TYPE_CONNECTION_SERVER;
}

//
// Helper to determine if a connection is client side.
//
QUIC_INLINE
BOOLEAN
QuicConnIsClient(
    _In_ const QUIC_CONNECTION * const Connection
    )
{
    return ((QUIC_HANDLE*)Connection)->Type == QUIC_HANDLE_TYPE_CONNECTION_CLIENT;
}

//
// Helper for checking if a connection is currently closed.
//
QUIC_INLINE
BOOLEAN
QuicConnIsClosed(
    _In_ const QUIC_CONNECTION * const Connection
    )
{
    return Connection->State.ClosedLocally || Connection->State.ClosedRemotely;
}

//
// Helper to get the owning QUIC_CONNECTION for the stream set module.
//
QUIC_INLINE
_Ret_notnull_
QUIC_CONNECTION*
QuicStreamSetGetConnection(
    _In_ QUIC_STREAM_SET* StreamSet
    )
{
    return CXPLAT_CONTAINING_RECORD(StreamSet, QUIC_CONNECTION, Streams);
}

//
// Helper to get the owning QUIC_CONNECTION for the crypto module.
//
QUIC_INLINE
_Ret_notnull_
QUIC_CONNECTION*
QuicCryptoGetConnection(
    _In_ QUIC_CRYPTO* Crypto
    )
{
    return CXPLAT_CONTAINING_RECORD(Crypto, QUIC_CONNECTION, Crypto);
}

//
// Helper to get the owning QUIC_CONNECTION for the send module.
//
QUIC_INLINE
_Ret_notnull_
QUIC_CONNECTION*
QuicSendGetConnection(
    _In_ QUIC_SEND* Send
    )
{
    return CXPLAT_CONTAINING_RECORD(Send, QUIC_CONNECTION, Send);
}

//
// Helper to get the owning QUIC_CONNECTION for the congestion control module.
//
QUIC_INLINE
_Ret_notnull_
QUIC_CONNECTION*
QuicCongestionControlGetConnection(
    _In_ const QUIC_CONGESTION_CONTROL* Cc
    )
{
    return CXPLAT_CONTAINING_RECORD(Cc, QUIC_CONNECTION, CongestionControl);
}

//
// Helper to get the QUIC_PACKET_SPACE for a loss detection.
//
QUIC_INLINE
_Ret_notnull_
QUIC_CONNECTION*
QuicLossDetectionGetConnection(
    _In_ QUIC_LOSS_DETECTION* LossDetection
    )
{
    return CXPLAT_CONTAINING_RECORD(LossDetection, QUIC_CONNECTION, LossDetection);
}

//
// Helper to get the owning QUIC_CONNECTION for datagram.
//
QUIC_INLINE
_Ret_notnull_
QUIC_CONNECTION*
QuicDatagramGetConnection(
    _In_ const QUIC_DATAGRAM* const Datagram
    )
{
    return CXPLAT_CONTAINING_RECORD(Datagram, QUIC_CONNECTION, Datagram);
}

QUIC_INLINE
void
QuicConnLogOutFlowStats(
    _In_ const QUIC_CONNECTION* const Connection
    )
{
    if (!QuicTraceEventEnabled(ConnOutFlowStats)) {
        return;
    }

    QuicCongestionControlLogOutFlowStatus(&Connection->CongestionControl);

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

QUIC_INLINE
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

QUIC_INLINE
void
QuicConnLogStatistics(
    _In_ const QUIC_CONNECTION* const Connection
    )
{
    const QUIC_PATH* Path = &Connection->Paths[0];
    UNREFERENCED_PARAMETER(Path);

    QuicTraceEvent(
        ConnStatsV3,
        "[conn][%p] STATS: SRtt=%llu CongestionCount=%u PersistentCongestionCount=%u SendTotalBytes=%llu RecvTotalBytes=%llu CongestionWindow=%u Cc=%s EcnCongestionCount=%u",
        Connection,
        Path->SmoothedRtt,
        Connection->Stats.Send.CongestionCount,
        Connection->Stats.Send.PersistentCongestionCount,
        Connection->Stats.Send.TotalBytes,
        Connection->Stats.Recv.TotalBytes,
        QuicCongestionControlGetCongestionWindow(&Connection->CongestionControl),
        Connection->CongestionControl.Name,
        Connection->Stats.Send.EcnCongestionCount);

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

QUIC_INLINE
BOOLEAN
QuicConnAddOutFlowBlockedReason(
    _In_ QUIC_CONNECTION* Connection,
    _In_ QUIC_FLOW_BLOCK_REASON Reason
    )
{
    CXPLAT_DBG_ASSERTMSG(
        (Reason & (Reason - 1)) == 0,
        "More than one reason is not allowed");
    if (!(Connection->OutFlowBlockedReasons & Reason)) {
        uint64_t Now = CxPlatTimeUs64();
        if (Reason & QUIC_FLOW_BLOCKED_PACING) {
            Connection->BlockedTimings.Pacing.LastStartTimeUs = Now;
        }
        if (Reason & QUIC_FLOW_BLOCKED_SCHEDULING) {
            Connection->BlockedTimings.Scheduling.LastStartTimeUs = Now;
        }
        if (Reason & QUIC_FLOW_BLOCKED_AMPLIFICATION_PROT) {
            Connection->BlockedTimings.AmplificationProt.LastStartTimeUs = Now;
        }
        if (Reason & QUIC_FLOW_BLOCKED_CONGESTION_CONTROL) {
            Connection->BlockedTimings.CongestionControl.LastStartTimeUs = Now;
        }
        if (Reason & QUIC_FLOW_BLOCKED_CONN_FLOW_CONTROL) {
            Connection->BlockedTimings.FlowControl.LastStartTimeUs = Now;
        }

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

QUIC_INLINE
BOOLEAN
QuicConnRemoveOutFlowBlockedReason(
    _In_ QUIC_CONNECTION* Connection,
    _In_ QUIC_FLOW_BLOCK_REASON Reason
    )
{
    if ((Connection->OutFlowBlockedReasons & Reason)) {
        uint64_t Now = CxPlatTimeUs64();
        if ((Connection->OutFlowBlockedReasons & QUIC_FLOW_BLOCKED_PACING) &&
            (Reason & QUIC_FLOW_BLOCKED_PACING)) {
            Connection->BlockedTimings.Pacing.CumulativeTimeUs +=
                CxPlatTimeDiff64(Connection->BlockedTimings.Pacing.LastStartTimeUs, Now);
            Connection->BlockedTimings.Pacing.LastStartTimeUs = 0;
        }
        if ((Connection->OutFlowBlockedReasons & QUIC_FLOW_BLOCKED_SCHEDULING) &&
            (Reason & QUIC_FLOW_BLOCKED_SCHEDULING)) {
            Connection->BlockedTimings.Scheduling.CumulativeTimeUs +=
                CxPlatTimeDiff64(Connection->BlockedTimings.Scheduling.LastStartTimeUs, Now);
            Connection->BlockedTimings.Scheduling.LastStartTimeUs = 0;
        }
        if ((Connection->OutFlowBlockedReasons & QUIC_FLOW_BLOCKED_AMPLIFICATION_PROT) &&
            (Reason & QUIC_FLOW_BLOCKED_AMPLIFICATION_PROT)) {
            Connection->BlockedTimings.AmplificationProt.CumulativeTimeUs +=
                CxPlatTimeDiff64(Connection->BlockedTimings.AmplificationProt.LastStartTimeUs, Now);
            Connection->BlockedTimings.AmplificationProt.LastStartTimeUs = 0;
        }
        if ((Connection->OutFlowBlockedReasons & QUIC_FLOW_BLOCKED_CONGESTION_CONTROL) &&
            (Reason & QUIC_FLOW_BLOCKED_CONGESTION_CONTROL)) {
            Connection->BlockedTimings.CongestionControl.CumulativeTimeUs +=
                CxPlatTimeDiff64(Connection->BlockedTimings.CongestionControl.LastStartTimeUs, Now);
            Connection->BlockedTimings.CongestionControl.LastStartTimeUs = 0;
        }
        if ((Connection->OutFlowBlockedReasons & QUIC_FLOW_BLOCKED_CONN_FLOW_CONTROL) &&
            (Reason & QUIC_FLOW_BLOCKED_CONN_FLOW_CONTROL)) {
            Connection->BlockedTimings.FlowControl.CumulativeTimeUs +=
                CxPlatTimeDiff64(Connection->BlockedTimings.FlowControl.LastStartTimeUs, Now);
            Connection->BlockedTimings.FlowControl.LastStartTimeUs = 0;
        }

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
_Must_inspect_result_
_Success_(return == QUIC_STATUS_SUCCESS)
QUIC_STATUS
QuicConnAlloc(
    _In_ QUIC_REGISTRATION* Registration,
    _In_ QUIC_PARTITION* Partition,
    _In_opt_ QUIC_WORKER* Worker,
    _In_opt_ const QUIC_RX_PACKET* Packet,
    _Outptr_ _At_(*NewConnection, __drv_allocatesMem(Mem))
        QUIC_CONNECTION** NewConnection
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
QUIC_INLINE
void
QuicConnValidate(
    _In_ QUIC_CONNECTION* Connection
    )
{
    CXPLAT_FRE_ASSERT(!Connection->State.Freed);
}
#else
#define QuicConnValidate(Connection)
#endif

//
// Adds a reference to the Connection.
//
_IRQL_requires_max_(DISPATCH_LEVEL)
QUIC_INLINE
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
QUIC_INLINE
void
QuicConnRelease(
    _In_ __drv_freesMem(Mem) QUIC_CONNECTION* Connection,
    _In_ QUIC_CONNECTION_REF Ref
    )
{
    QuicConnValidate(Connection);

#if DEBUG
    CXPLAT_TEL_ASSERT(Connection->RefTypeCount[Ref] > 0);
    uint16_t result = (uint16_t)InterlockedDecrement16((volatile short*)&Connection->RefTypeCount[Ref]);
    CXPLAT_TEL_ASSERT(result != 0xFFFF);
#else
    UNREFERENCED_PARAMETER(Ref);
#endif

    CXPLAT_DBG_ASSERT(Connection->RefCount > 0);
    if (InterlockedDecrement((volatile long*)&Connection->RefCount) == 0) {
#if DEBUG
        for (uint32_t i = 0; i < QUIC_CONN_REF_COUNT; i++) {
            CXPLAT_TEL_ASSERT(Connection->RefTypeCount[i] == 0);
        }
#endif
        if (Ref == QUIC_CONN_REF_LOOKUP_RESULT) {
            //
            // Lookup results cannot be the last ref, as they can result in the
            // datapath binding being deleted on a callback. Instead, queue the
            // connection to be released by the worker.
            //
            CXPLAT_DBG_ASSERT(Connection->Worker != NULL);
            QuicWorkerQueueConnection(Connection->Worker, Connection);
        } else {
            QuicConnFree(Connection);
        }
    }
}
#pragma warning(pop)

//
// Registers the connection with a registration.
//
_IRQL_requires_max_(DISPATCH_LEVEL)
_Must_inspect_result_
BOOLEAN
QuicConnRegister(
    _Inout_ QUIC_CONNECTION* Connection,
    _Inout_ QUIC_REGISTRATION* Registration
    );

//
// Unregisters the connection from the registration.
//
_IRQL_requires_max_(DISPATCH_LEVEL)
void
QuicConnUnregister(
    _Inout_ QUIC_CONNECTION* Connection
    );

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
    _In_ QUIC_CONNECTION* Connection,
    _Inout_ BOOLEAN* StillHasPriorityWork
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
QuicConnQueuePriorityOper(
    _In_ QUIC_CONNECTION* Connection,
    _In_ QUIC_OPERATION* Oper
    );

_IRQL_requires_max_(DISPATCH_LEVEL)
void
QuicConnQueueHighestPriorityOper(
    _In_ QUIC_CONNECTION* Connection,
    _In_ QUIC_OPERATION* Oper
    );

typedef enum QUIC_CONN_START_FLAGS {
    QUIC_CONN_START_FLAG_NONE =              0x00000000U,
    QUIC_CONN_START_FLAG_FAIL_SILENTLY =     0x00000001U // Don't send notification to API client
} QUIC_CONN_START_FLAGS;

//
// Starts the connection. Shouldn't be called directly in most instances.
//
_IRQL_requires_max_(PASSIVE_LEVEL)
QUIC_STATUS
QuicConnStart(
    _In_ QUIC_CONNECTION* Connection,
    _In_ QUIC_CONFIGURATION* Configuration,
    _In_ QUIC_ADDRESS_FAMILY Family,
    _In_opt_z_ const char* ServerName,
    _In_ uint16_t ServerPort, // Host byte order
    _In_ QUIC_CONN_START_FLAGS StartFlags
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
QUIC_INLINE
QUIC_CID_HASH_ENTRY*
QuicConnGetSourceCidFromSeq(
    _In_ QUIC_CONNECTION* Connection,
    _In_ QUIC_VAR_INT SequenceNumber,
    _In_ BOOLEAN RemoveFromList,
    _Out_ BOOLEAN* IsLastCid
    )
{
    for (CXPLAT_SLIST_ENTRY** Entry = &Connection->SourceCids.Next;
            *Entry != NULL;
            Entry = &(*Entry)->Next) {
        QUIC_CID_HASH_ENTRY* SourceCid =
            CXPLAT_CONTAINING_RECORD(
                *Entry,
                QUIC_CID_HASH_ENTRY,
                Link);
        if (SourceCid->CID.SequenceNumber == SequenceNumber) {
            if (RemoveFromList) {
                QuicBindingRemoveSourceConnectionID(
                    Connection->Paths[0].Binding,
                    SourceCid,
                    Entry);
                QuicTraceEvent(
                    ConnSourceCidRemoved,
                    "[conn][%p] (SeqNum=%llu) Removed Source CID: %!CID!",
                    Connection,
                    SourceCid->CID.SequenceNumber,
                    CASTED_CLOG_BYTEARRAY(SourceCid->CID.Length, SourceCid->CID.Data));
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
QUIC_INLINE
QUIC_CID_HASH_ENTRY*
QuicConnGetSourceCidFromBuf(
    _In_ QUIC_CONNECTION* Connection,
    _In_ uint8_t CidLength,
    _In_reads_(CidLength)
        const uint8_t* CidBuffer
    )
{
    for (CXPLAT_SLIST_ENTRY* Entry = Connection->SourceCids.Next;
            Entry != NULL;
            Entry = Entry->Next) {
        QUIC_CID_HASH_ENTRY* SourceCid =
            CXPLAT_CONTAINING_RECORD(
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
QUIC_INLINE
QUIC_CID_LIST_ENTRY*
QuicConnGetDestCidFromSeq(
    _In_ QUIC_CONNECTION* Connection,
    _In_ QUIC_VAR_INT SequenceNumber,
    _In_ BOOLEAN RemoveFromList
    )
{
    for (CXPLAT_LIST_ENTRY* Entry = Connection->DestCids.Flink;
            Entry != &Connection->DestCids;
            Entry = Entry->Flink) {
        QUIC_CID_LIST_ENTRY* DestCid =
            CXPLAT_CONTAINING_RECORD(
                Entry,
                QUIC_CID_LIST_ENTRY,
                Link);
        if (DestCid->CID.SequenceNumber == SequenceNumber) {
            if (RemoveFromList) {
                CxPlatListEntryRemove(Entry);
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
    _In_ uint64_t LatestRtt,
    _In_ uint64_t OurSendTimestamp,
    _In_ uint64_t PeerSendTimestamp
    );

//
// Sets a new timer delay in microseconds.
//
_IRQL_requires_max_(PASSIVE_LEVEL)
void
QuicConnTimerSetEx(
    _Inout_ QUIC_CONNECTION* Connection,
    _In_ QUIC_CONN_TIMER_TYPE Type,
    _In_ uint64_t DelayUs,
    _In_ uint64_t TimeNow
    );

_IRQL_requires_max_(PASSIVE_LEVEL)
QUIC_INLINE
void
QuicConnTimerSet(
    _Inout_ QUIC_CONNECTION* Connection,
    _In_ QUIC_CONN_TIMER_TYPE Type,
    _In_ uint64_t DelayUs
    )
{
    const uint64_t TimeNow = CxPlatTimeUs64();
    QuicConnTimerSetEx(Connection, Type, DelayUs, TimeNow);
}

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

_IRQL_requires_max_(PASSIVE_LEVEL)
QUIC_INLINE
uint64_t
QuicConnGetAckDelay(
    _In_ const QUIC_CONNECTION* Connection
    )
{
    if (Connection->Settings.MaxAckDelayMs &&
        (MsQuicLib.ExecutionConfig == NULL ||
         Connection->Settings.MaxAckDelayMs > US_TO_MS(MsQuicLib.ExecutionConfig->PollingIdleTimeoutUs))) {
        //
        // If we are using delayed ACKs, and the ACK delay is greater than the
        // polling timeout, then we need to account for delay resulting from
        // from the timer resolution.
        //
        return (uint64_t)Connection->Settings.MaxAckDelayMs + (uint64_t)MsQuicLib.TimerResolutionMs;
    }
    return (uint64_t)Connection->Settings.MaxAckDelayMs;
}

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

_IRQL_requires_max_(PASSIVE_LEVEL)
QUIC_STATUS
QuicConnGenerateLocalTransportParameters(
    _In_ QUIC_CONNECTION* Connection,
    _Out_ QUIC_TRANSPORT_PARAMETERS* LocalTP
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
QUIC_STATUS
QuicConnProcessPeerTransportParameters(
    _In_ QUIC_CONNECTION* Connection,
    _In_ BOOLEAN FromResumptionTicket
    );

//
// Sets the configuration handle.
//
_IRQL_requires_max_(PASSIVE_LEVEL)
QUIC_STATUS
QuicConnSetConfiguration(
    _In_ QUIC_CONNECTION* Connection,
    _In_ QUIC_CONFIGURATION* Configuration
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
QUIC_INLINE
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
QUIC_INLINE
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
QUIC_INLINE
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
// Queues a received packet chain to a connection for processing.
//
_IRQL_requires_max_(DISPATCH_LEVEL)
void
QuicConnQueueRecvPackets(
    _In_ QUIC_CONNECTION* Connection,
    _In_ QUIC_RX_PACKET* Packets,
    _In_ uint32_t PacketChainLength,
    _In_ uint32_t PacketChainByteLength
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
// Queues a route completion event to a connection for processing.
//
_IRQL_requires_max_(DISPATCH_LEVEL)
_Function_class_(CXPLAT_ROUTE_RESOLUTION_CALLBACK)
void
QuicConnQueueRouteCompletion(
    _Inout_ void* Context,
    _When_(Succeeded == FALSE, _Reserved_)
    _When_(Succeeded == TRUE, _In_reads_bytes_(6))
        const uint8_t* PhysicalAddress,
    _In_ uint8_t PathId,
    _In_ BOOLEAN Succeeded
    );

//
// Queues up an update to the packet tolerance we want the peer to use.
//
_IRQL_requires_max_(PASSIVE_LEVEL)
void
QuicConnUpdatePeerPacketTolerance(
    _In_ QUIC_CONNECTION* Connection,
    _In_ uint8_t NewPacketTolerance
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

//
// Get the max MTU for a specific path.
//
_IRQL_requires_max_(DISPATCH_LEVEL)
QUIC_INLINE
uint16_t
QuicConnGetMaxMtuForPath(
    _In_ QUIC_CONNECTION* Connection,
    _In_ QUIC_PATH* Path
    )
{
    //
    // We can't currently cache the full value because this is called before
    // handshake complete in QuicPacketBuilderFinalize. So cache the values
    // we can.
    //
    uint16_t LocalMtu = Path->LocalMtu;
    if (LocalMtu == 0) {
        LocalMtu = CxPlatSocketGetLocalMtu(Path->Binding->Socket, &Path->Route);
        Path->LocalMtu = LocalMtu;
    }
    uint16_t RemoteMtu = 0xFFFF;
    if ((Connection->PeerTransportParams.Flags & QUIC_TP_FLAG_MAX_UDP_PAYLOAD_SIZE)) {
        RemoteMtu =
            PacketSizeFromUdpPayloadSize(
                QuicAddrGetFamily(&Path->Route.RemoteAddress),
                (uint16_t)Connection->PeerTransportParams.MaxUdpPayloadSize);
    }
    uint16_t SettingsMtu = Connection->Settings.MaximumMtu;
    return CXPLAT_MIN(CXPLAT_MIN(LocalMtu, RemoteMtu), SettingsMtu);
}

//
// Check to see if enough time has passed while in Search Complete to retry MTU
// discovery.
//
_IRQL_requires_max_(PASSIVE_LEVEL)
QUIC_INLINE
void
QuicMtuDiscoveryCheckSearchCompleteTimeout(
    _In_ QUIC_CONNECTION* Connection,
    _In_ uint64_t TimeNow
    )
{
    uint64_t TimeoutTime = Connection->Settings.MtuDiscoverySearchCompleteTimeoutUs;
    for (uint8_t i = 0; i < Connection->PathsCount; i++) {
        //
        // Only trigger a new send if we're in Search Complete and enough time has
        // passed.
        //
        QUIC_PATH* Path = &Connection->Paths[i];
        if (!Path->IsActive || !Path->MtuDiscovery.IsSearchComplete) {
            continue;
        }
        if (CxPlatTimeDiff64(
                Path->MtuDiscovery.SearchCompleteEnterTimeUs,
                TimeNow) >= TimeoutTime) {
            QuicMtuDiscoveryMoveToSearching(&Path->MtuDiscovery, Connection);
        }
    }
}
