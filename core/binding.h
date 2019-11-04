/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.

--*/

typedef struct _QUIC_PARTITIONED_HASHTABLE QUIC_PARTITIONED_HASHTABLE;
typedef struct _QUIC_STATELESS_CONTEXT QUIC_STATELESS_CONTEXT;

//
// Structure that MsQuic servers use for encoding data for stateless retries.
//
typedef struct _QUIC_RETRY_TOKEN_CONTENTS {
    QUIC_ADDR RemoteAddress;
    uint8_t OrigConnId[QUIC_MAX_CONNECTION_ID_LENGTH_V1];
    uint8_t OrigConnIdLength;
    uint8_t EncryptionTag[QUIC_ENCRYPTION_OVERHEAD];
} QUIC_RETRY_TOKEN_CONTENTS;

QUIC_STATIC_ASSERT(
    MSQUIC_CONNECTION_ID_LENGTH <= QUIC_IV_LENGTH,
    "CIDs are expected to be shorted than IV");

//
// The per recv buffer context type.
//
typedef struct _QUIC_RECV_PACKET {

    //
    // The bytes that represent the fully decoded packet number.
    //
    uint64_t PacketNumber;

    //
    // The current packet buffer.
    //
    union {
        _Field_size_(BufferLength)
        const uint8_t* Buffer;
        const struct _QUIC_HEADER_INVARIANT* Invariant;
        const struct _QUIC_VERSION_NEGOTIATION_PACKET* VerNeg;
        const struct _QUIC_LONG_HEADER_D23* LH;
        const struct _QUIC_RETRY_D23* Retry;
        const struct _QUIC_SHORT_HEADER_D23* SH;
    };

    //
    // Destination connection ID.
    //
    const uint8_t* DestCID;

    //
    // Sources connection ID. Only valid for long header packets.
    //
    const uint8_t* SourceCID;

    //
    // Length of the Buffer array.
    //
    uint16_t BufferLength;

    //
    // Length of the current packet header.
    //
    uint16_t HeaderLength;

    //
    // Length of the current packet payload.
    //
    uint16_t PayloadLength;

    //
    // Lengths of the destination and source connection IDs
    //
    uint8_t DestCIDLen;
    uint8_t SourceCIDLen;

    //
    // The type of key used to decrypt the packet.
    //
    QUIC_PACKET_KEY_TYPE KeyType;

    //
    // Flag indicating we have found the connection the packet belongs to.
    //
    BOOLEAN AssignedToConnection : 1;

    //
    // Flag indicating the invariant header has been validated.
    //
    BOOLEAN ValidatedHeaderInv : 1;

    //
    // Flag indicating the packet has a short header. This is only set once
    // ValidatedHeaderInv is TRUE.
    //
    BOOLEAN IsShortHeader : 1;

    //
    // Flag indicating the version specific header has been validated.
    //
    BOOLEAN ValidatedHeaderVer : 1;

    //
    // Flag indicating the Initial packet has a valid Token.
    //
    BOOLEAN ValidToken : 1;

    //
    // Flag indicating the PacketNumber is valid.
    //
    BOOLEAN PacketNumberSet : 1;

    //
    // Flag indicating 0-RTT encryption.
    //
    BOOLEAN EncryptedWith0Rtt : 1;

    //
    // Flag indicating the packet couldn't be decrypted yet, because the key
    // isn't available yet; so the packet was deferred for later.
    //
    BOOLEAN DecryptionDeferred : 1;

    //
    // Flag indicating the packet was completely parsed successfully.
    //
    BOOLEAN CompletelyValid : 1;

    //
    // Flag indicating the packet is the largest packet number seen so far.
    //
    BOOLEAN NewLargestPacketNumber : 1;

} QUIC_RECV_PACKET;

typedef enum _QUIC_BINDING_LOOKUP_TYPE {

    QUIC_BINDING_LOOKUP_SINGLE,         // Single connection
    QUIC_BINDING_LOOKUP_HASH,           // Single hash table of connections
    QUIC_BINDING_LOOKUP_MULTI_HASH      // Partitioned hash tables of connections

} QUIC_BINDING_LOOKUP_TYPE;

//
// Represents a UDP binding of local IP address and UDP port, and optionally
// remote IP address.
//
typedef struct _QUIC_BINDING {

    //
    // The link in the library's global list of bindings.
    //
    QUIC_LIST_ENTRY Link;

    //
    // Indicates whether the binding is exclusively owned already. Defaults
    // to TRUE.
    //
    BOOLEAN Exclusive : 1;

    //
    // Indicates that the binding is also explicitly connected to a remote
    // address, effectively fixing the 4-tuple of the binding.
    //
    BOOLEAN Connected : 1;

    //
    // Number of (connection and listener) references to the binding.
    //
    uint32_t RefCount;

    //
    // The number of connections that haven't completed the handshake.
    //
    long HandshakeConnections;

    //
    // A randomly created reserved version.
    //
    uint32_t RandomReservedVersion;

#ifdef QUIC_COMPARTMENT_ID
    //
    // The network compartment ID.
    //
    QUIC_COMPARTMENT_ID CompartmentId;
#endif

    //
    // The datapath binding.
    //
    PQUIC_DATAPATH_BINDING DatapathBinding;

    //
    // Lock for accessing the listeners.
    //
    QUIC_DISPATCH_RW_LOCK RwLock;

    //
    // The listeners registered on this binding.
    //
    QUIC_LIST_ENTRY Listeners;

    //
    // Lookup tables for connection IDs.
    //
    QUIC_LOOKUP Lookup;

    //
    // Used for generating stateless reset hashes.
    //
    QUIC_HASH* ResetTokenHash;
    QUIC_DISPATCH_LOCK ResetTokenLock;

    //
    // Stateless operation tracking structures.
    //
    QUIC_DISPATCH_LOCK StatelessOperLock;
    QUIC_HASHTABLE StatelessOperTable;
    QUIC_LIST_ENTRY StatelessOperList;
    QUIC_POOL StatelessOperCtxPool;
    uint32_t StatelessOperCount;

    struct {

        struct {
            uint64_t DroppedPackets;
        } Recv;

    } Stats;

} QUIC_BINDING, *PQUIC_BINDING;

//
// Global callbacks for all QUIC UDP bindings.
//
QUIC_DATAPATH_RECEIVE_CALLBACK QuicBindingReceive;
QUIC_DATAPATH_UNREACHABLE_CALLBACK QuicBindingUnreachable;

//
// Initializes a new binding.
//
_IRQL_requires_max_(PASSIVE_LEVEL)
QUIC_STATUS
QuicBindingInitialize(
#ifdef QUIC_COMPARTMENT_ID
    _In_ QUIC_COMPARTMENT_ID CompartmentId,
#endif
    _In_ BOOLEAN ShareBinding,
    _In_opt_ const QUIC_ADDR * LocalAddress,
    _In_opt_ const QUIC_ADDR * RemoteAddress,
    _Out_ PQUIC_BINDING* NewBinding
    );

//
// Uninitializes the binding. This cleans up the datapath binding, which blocks
// on all outstanding upcalls. DO NOT call this on a datapath upcall thread!
//
_IRQL_requires_max_(PASSIVE_LEVEL)
void
QuicBindingUninitialize(
    _In_ PQUIC_BINDING Binding
    );

//
// Tracing rundown for the binding.
//
_IRQL_requires_max_(DISPATCH_LEVEL)
void
QuicBindingTraceRundown(
    _In_ PQUIC_BINDING Binding
    );

//
// Looks up the listener based on the ALPN list. Optionally, outputs the
// first ALPN that matches.
//
_IRQL_requires_max_(PASSIVE_LEVEL)
_Success_(return != NULL)
PQUIC_LISTENER
QuicBindingGetListener(
    _In_ PQUIC_BINDING Binding,
    _In_ const QUIC_NEW_CONNECTION_INFO* Info
    );

//
// Attempts to register a listener with the binding.
//
_IRQL_requires_max_(PASSIVE_LEVEL)
BOOLEAN
QuicBindingRegisterListener(
    _In_ PQUIC_BINDING Binding,
    _In_ PQUIC_LISTENER Listener
    );

//
// Unregister a listener from the binding.
//
_IRQL_requires_max_(PASSIVE_LEVEL)
void
QuicBindingUnregisterListener(
    _In_ PQUIC_BINDING Binding,
    _In_ PQUIC_LISTENER Listener
    );

//
// Attempts to insert the connection's new source CID into the binding's
// lookup table.
//
_IRQL_requires_max_(DISPATCH_LEVEL)
BOOLEAN
QuicBindingAddSourceConnectionID(
    _In_ PQUIC_BINDING Binding,
    _In_ QUIC_CID_HASH_ENTRY* SourceCID
    );

//
// Removes a single source CID from the binding's lookup table.
//
_IRQL_requires_max_(DISPATCH_LEVEL)
void
QuicBindingRemoveSourceConnectionID(
    _In_ PQUIC_BINDING Binding,
    _In_ QUIC_CID_HASH_ENTRY* SourceCID
    );

//
// Removes all the connection's source CIDs from the binding's lookup table.
//
_IRQL_requires_max_(DISPATCH_LEVEL)
void
QuicBindingRemoveConnection(
    _In_ PQUIC_BINDING Binding,
    _In_ PQUIC_CONNECTION Connection
    );

//
// Moves all the connections source CIDs from the one binding's lookup table to
// another.
//
_IRQL_requires_max_(DISPATCH_LEVEL)
void
QuicBindingMoveSourceConnectionIDs(
    _In_ PQUIC_BINDING BindingSrc,
    _In_ PQUIC_BINDING BindingDest,
    _In_ PQUIC_CONNECTION Connection
    );

//
// Processes a stateless operation that was queued.
//
_IRQL_requires_max_(PASSIVE_LEVEL)
void
QuicBindingProcessStatelessOperation(
    _In_ uint32_t OperationType,
    _In_ QUIC_STATELESS_CONTEXT* StatelessCtx
    );

//
// Called when the operation is done with the stateless context.
//
_IRQL_requires_max_(PASSIVE_LEVEL)
void
QuicBindingReleaseStatelessOperation(
    _In_ QUIC_STATELESS_CONTEXT* StatelessCtx,
    _In_ BOOLEAN ReturnDatagram
    );

//
// Sends data to a remote host. Note, the buffer must remain valid for
// the duration of the send operation.
//
_IRQL_requires_max_(DISPATCH_LEVEL)
QUIC_STATUS
QuicBindingSendTo(
    _In_ PQUIC_BINDING Binding,
    _In_ const QUIC_ADDR * RemoteAddress,
    _In_ PQUIC_DATAPATH_SEND_CONTEXT SendContext
    );

//
// Sends data to a remote host. Note, the buffer must remain valid for
// the duration of the send operation.
//
_IRQL_requires_max_(DISPATCH_LEVEL)
QUIC_STATUS
QuicBindingSendFromTo(
    _In_ PQUIC_BINDING Binding,
    _In_ const QUIC_ADDR * LocalAddress,
    _In_ const QUIC_ADDR * RemoteAddress,
    _In_ PQUIC_DATAPATH_SEND_CONTEXT SendContext
    );

//
// Generates a stateless reset token for the given connection ID.
//
_IRQL_requires_max_(DISPATCH_LEVEL)
QUIC_STATUS
QuicBindingGenerateStatelessResetToken(
    _In_ PQUIC_BINDING Binding,
    _In_reads_(MSQUIC_CONNECTION_ID_LENGTH)
        const uint8_t* const CID,
    _Out_writes_all_(QUIC_STATELESS_RESET_TOKEN_LENGTH)
        uint8_t* ResetToken
    );

//
// Decrypts the retry token.
//
inline
_IRQL_requires_max_(DISPATCH_LEVEL)
BOOLEAN
QuicRetryTokenDecrypt(
    _In_ const QUIC_RECV_PACKET* const Packet,
    _In_reads_(sizeof(QUIC_RETRY_TOKEN_CONTENTS))
        const uint8_t* TokenBuffer,
    _Out_ QUIC_RETRY_TOKEN_CONTENTS* Token
    )
{
    //
    // Copy the token locally so as to not effect the original packet buffer,
    //
    QuicCopyMemory(Token, TokenBuffer, sizeof(QUIC_RETRY_TOKEN_CONTENTS));

    uint8_t Iv[QUIC_IV_LENGTH];
    QuicCopyMemory(Iv, Packet->DestCID, MSQUIC_CONNECTION_ID_LENGTH);
    QuicZeroMemory(
        Iv + MSQUIC_CONNECTION_ID_LENGTH,
        QUIC_IV_LENGTH - MSQUIC_CONNECTION_ID_LENGTH);

    return
        QUIC_SUCCEEDED(
        QuicDecrypt(
            MsQuicLib.StatelessRetryKey,
            Iv,
            0,
            NULL,
            sizeof(QUIC_RETRY_TOKEN_CONTENTS),
            (uint8_t*)Token));
}
