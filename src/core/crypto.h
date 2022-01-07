/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.

Abstract:

    Definitions for the Crypto interface, which manages the send and receive
    queues for TLS data.

--*/

#if defined(__cplusplus)
extern "C" {
#endif

//
// Set of callbacks for TLS.
//
extern CXPLAT_TLS_CALLBACKS QuicTlsCallbacks;

//
// Stream of TLS data.
//
typedef struct QUIC_CRYPTO {

    //
    // Indicates the crypto object has been initialized.
    //
    BOOLEAN Initialized : 1;

    //
    // Indicates the send state is in recovery.
    //
    BOOLEAN InRecovery : 1;

    //
    // Indicates custom cert validation (by the app) is outstanding.
    //
    BOOLEAN CertValidationPending : 1;

    //
    // The TLS context for processing handshake messages.
    //
    CXPLAT_TLS* TLS;

    //
    // Send State
    //

    CXPLAT_TLS_PROCESS_STATE TlsState;

    //
    // Result flags from the last Tls process call.
    //
    CXPLAT_TLS_RESULT_FLAGS ResultFlags;

    //
    // The length of bytes that have been sent at least once.
    //
    uint32_t MaxSentLength;

    //
    // The smallest offset for unacknowledged send data. This variable is
    // similar to RFC793 SND.UNA.
    //
    uint32_t UnAckedOffset;

    //
    // The next offset we will start sending at.
    //
    uint32_t NextSendOffset;

    //
    // Recovery window
    //
    uint32_t RecoveryNextOffset;
    uint32_t RecoveryEndOffset;
    #define RECOV_WINDOW_OPEN(S) ((S)->RecoveryNextOffset < (S)->RecoveryEndOffset)

    //
    // The ACK ranges greater than 'UnAckedOffset', with holes between them.
    //
    QUIC_RANGE SparseAckRanges;

    //
    // Recv State
    //

    //
    // The total amount of data consumed by TLS.
    //
    uint32_t RecvTotalConsumed;

    //
    // The offset the current receive encryption level starts.
    //
    uint32_t RecvEncryptLevelStartOffset;

    //
    // The structure for tracking received buffers.
    //
    QUIC_RECV_BUFFER RecvBuffer;

    //
    // Resumption ticket to send to server.
    //
    uint8_t* ResumptionTicket;
    uint32_t ResumptionTicketLength;

} QUIC_CRYPTO;

inline
BOOLEAN
QuicCryptoHasPendingCryptoFrame(
    _In_ QUIC_CRYPTO* Crypto
    )
{
    return
        RECOV_WINDOW_OPEN(Crypto) ||
        (Crypto->NextSendOffset < Crypto->TlsState.BufferTotalLength);
}

_IRQL_requires_max_(PASSIVE_LEVEL)
QUIC_STATUS
QuicCryptoInitialize(
    _Inout_ QUIC_CRYPTO* Crypto
    );

_IRQL_requires_max_(PASSIVE_LEVEL)
void
QuicCryptoUninitialize(
    _In_ QUIC_CRYPTO* Crypto
    );

//
// Initializes the TLS state.
//
_IRQL_requires_max_(PASSIVE_LEVEL)
QUIC_STATUS
QuicCryptoInitializeTls(
    _Inout_ QUIC_CRYPTO* Crypto,
    _In_ CXPLAT_SEC_CONFIG* SecConfig,
    _In_ const QUIC_TRANSPORT_PARAMETERS* Params
    );

//
// Update the initial keys when the QUIC version changes.
//
QUIC_STATUS
QuicCryptoOnVersionChange(
    _In_ QUIC_CRYPTO* Crypto
    );

//
// Indicate the connection is starting over and the initial data needs to be
// resent.
//
_IRQL_requires_max_(PASSIVE_LEVEL)
void
QuicCryptoReset(
    _In_ QUIC_CRYPTO* Crypto
    );

//
// Indicates both peers know the handshake completed successfully.
//
_IRQL_requires_max_(PASSIVE_LEVEL)
void
QuicCryptoHandshakeConfirmed(
    _In_ QUIC_CRYPTO* Crypto
    );

//
// Cleans up the indicated key type so that it cannot be used for encryption or
// decryption of packets any more. Returns TRUE if keys were actually discarded
// or FALSE if keys had previously been discarded already.
//
_IRQL_requires_max_(PASSIVE_LEVEL)
BOOLEAN
QuicCryptoDiscardKeys(
    _In_ QUIC_CRYPTO* Crypto,
    _In_ QUIC_PACKET_KEY_TYPE KeyType
    );

//
// Returns the next encryption level with data ready to be sent.
//
_IRQL_requires_max_(PASSIVE_LEVEL)
QUIC_ENCRYPT_LEVEL
QuicCryptoGetNextEncryptLevel(
    _In_ QUIC_CRYPTO* Crypto
    );

//
// Called to write any frames it needs to the packet buffer. Returns TRUE if
// frames were written; FALSE if it ran out of space to write anything.
//
_IRQL_requires_max_(PASSIVE_LEVEL)
BOOLEAN
QuicCryptoWriteFrames(
    _In_ QUIC_CRYPTO* Crypto,
    _Inout_ QUIC_PACKET_BUILDER* Builder
    );

//
// Called when a crypto frame is inferred to be lost. Returns TRUE if data is
// queued to be sent.
//
_IRQL_requires_max_(PASSIVE_LEVEL)
BOOLEAN
QuicCryptoOnLoss(
    _In_ QUIC_CRYPTO* Crypto,
    _In_ QUIC_SENT_FRAME_METADATA* FrameMetadata
    );

//
// Called when an ACK is received for a crypto frame.
//
_IRQL_requires_max_(PASSIVE_LEVEL)
void
QuicCryptoOnAck(
    _In_ QUIC_CRYPTO* Crypto,
    _In_ QUIC_SENT_FRAME_METADATA* FrameMetadata
    );

//
// Processes a received crypto frame.
//
_IRQL_requires_max_(PASSIVE_LEVEL)
QUIC_STATUS
QuicCryptoProcessFrame(
    _In_ QUIC_CRYPTO* Crypto,
    _In_ QUIC_PACKET_KEY_TYPE KeyType,
    _In_ const QUIC_CRYPTO_EX* const Frame
    );

//
// Passes any data queued up to TLS for processing.
//
_IRQL_requires_max_(PASSIVE_LEVEL)
QUIC_STATUS
QuicCryptoProcessData(
    _In_ QUIC_CRYPTO* Crypto,
    _In_ BOOLEAN IsClientInitial
    );

//
// Processes app-provided data for TLS (i.e. resumption ticket data).
//
_IRQL_requires_max_(PASSIVE_LEVEL)
QUIC_STATUS
QuicCryptoProcessAppData(
    _In_ QUIC_CRYPTO* Crypto,
    _In_ uint32_t DataLength,
    _In_reads_bytes_(DataLength)
        const uint8_t* AppData
    );

//
// Invoked when the app has completed its custom certificate validation.
//
_IRQL_requires_max_(PASSIVE_LEVEL)
void
QuicCryptoCustomCertValidationComplete(
    _In_ QUIC_CRYPTO* Crypto,
    _In_ BOOLEAN Result
    );

//
// Helper function to determine how much complete TLS data is contained in the
// buffer, and should be passed to TLS.
//
_IRQL_requires_max_(DISPATCH_LEVEL)
uint32_t
QuicCryptoTlsGetCompleteTlsMessagesLength(
    _In_reads_(BufferLength)
        const uint8_t* Buffer,
    _In_ uint32_t BufferLength
    );

//
// Reads, validates and decodes all information needed for preprocessing the
// initial CRYPTO data from a client. Return QUIC_STATUS_PENDING if not all the
// data necessary to decode is available.
//
_IRQL_requires_max_(PASSIVE_LEVEL)
QUIC_STATUS
QuicCryptoTlsReadInitial(
    _In_ QUIC_CONNECTION* Connection,
    _In_reads_(BufferLength)
        const uint8_t* Buffer,
    _In_ uint32_t BufferLength,
    _Inout_ QUIC_NEW_CONNECTION_INFO* Info,
    _Inout_opt_ QUIC_TLS_SECRETS* TlsSecrets
    );

//
// Generates new 1-RTT read and write keys, unless they already exist.
//
_IRQL_requires_max_(PASSIVE_LEVEL)
QUIC_STATUS
QuicCryptoGenerateNewKeys(
    _In_ QUIC_CONNECTION* Connection
    );

//
// Shift 1-RTT keys, freeing the old keys and replacing them with the current
// keys, replacing the current keys with the new keys; update the start packet
// number; and invert the key phase bit.
// If the shift is locally-initiated, then set the flag to await confirmation
// of the key update from the peer.
//
_IRQL_requires_max_(PASSIVE_LEVEL)
void
QuicCryptoUpdateKeyPhase (
    _In_ QUIC_CONNECTION* Connection,
    _In_ BOOLEAN LocalUpdate
    );

//
// Encode all state the server needs to resume the connection into a ticket
// ready to be passed to TLS.
// The buffer returned in Ticket needs to be freed with CXPLAT_FREE().
// Note: Connection is only used for logging and may be NULL for testing.
//
QUIC_STATUS
QuicCryptoEncodeServerTicket(
    _In_opt_ QUIC_CONNECTION* Connection,
    _In_ uint32_t QuicVersion,
    _In_ uint32_t AppDataLength,
    _In_reads_bytes_opt_(AppDataLength)
        const uint8_t* const AppResumptionData,
    _In_ const QUIC_TRANSPORT_PARAMETERS* HandshakeTP,
    _In_ uint8_t AlpnLength,
    _In_reads_bytes_(AlpnLength)
        const uint8_t* const NegotiatedAlpn,
    _Outptr_result_buffer_(*TicketLength)
        uint8_t** Ticket,
    _Out_ uint32_t* TicketLength
    );

//
// Decode a previously-generated resumption ticket and extract all data needed
// to resume the connection.
// AppData contains a pointer to the offset within Ticket, so do not free it.
// AppData contain NULL if the server application didn't pass any resumption
// data.
// Note: Connection is only used for logging and may be NULL for testing.
//
QUIC_STATUS
QuicCryptoDecodeServerTicket(
    _In_ QUIC_CONNECTION* Connection,
    _In_ uint16_t TicketLength,
    _In_reads_bytes_(TicketLength)
        const uint8_t* Ticket,
    _In_ const uint8_t* AlpnList,
    _In_ uint16_t AlpnListLength,
    _Out_ QUIC_TRANSPORT_PARAMETERS* DecodedTP,
    _Outptr_result_buffer_maybenull_(*AppDataLength)
        const uint8_t** AppData,
    _Out_ uint32_t* AppDataLength
    );

//
// Encodes necessary data into the client ticket to enable connection resumption.
// The pointer held by ClientTicket needs to be freed by CXPLAT_FREE().
// Note: Connection is only used for logging and may be NULL for testing.
//
QUIC_STATUS
QuicCryptoEncodeClientTicket(
    _In_opt_ QUIC_CONNECTION* Connection,
    _In_ uint32_t TicketLength,
    _In_reads_bytes_(TicketLength)
        const uint8_t* Ticket,
    _In_ const QUIC_TRANSPORT_PARAMETERS* ServerTP,
    _In_ uint32_t QuicVersion,
    _Outptr_result_buffer_(*ClientTicketLength)
        const uint8_t** ClientTicket,
    _Out_ uint32_t* ClientTicketLength
    );

//
// Decodes and returns data necessary to resume a connection from a client ticket.
// The buffer held in ServerTicket must be freed with CXPLAT_FREE().
// Note: Connection is only used for logging and my be NULL for testing.
//
QUIC_STATUS
QuicCryptoDecodeClientTicket(
    _In_opt_ QUIC_CONNECTION* Connection,
    _In_ uint16_t ClientTicketLength,
    _In_reads_bytes_(ClientTicketLength)
        const uint8_t* ClientTicket,
    _Out_ QUIC_TRANSPORT_PARAMETERS* DecodedTP,
    _Outptr_result_buffer_maybenull_(*ServerTicketLength)
        uint8_t** ServerTicket,
    _Out_ uint32_t* ServerTicketLength,
    _Out_ uint32_t* QuicVersion
    );

#if defined(__cplusplus)
}
#endif
