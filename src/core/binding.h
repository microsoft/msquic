/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.

--*/

typedef struct QUIC_PARTITIONED_HASHTABLE QUIC_PARTITIONED_HASHTABLE;
typedef struct QUIC_STATELESS_CONTEXT QUIC_STATELESS_CONTEXT;

//
// Structure that MsQuic servers use for encoding data for stateless retries and
// NEW_TOKEN data.
//
typedef struct QUIC_TOKEN_CONTENTS {
    struct {
        uint64_t IsNewToken : 1;
        uint64_t Timestamp  : 63;
    } Authenticated;
    struct {
        QUIC_ADDR RemoteAddress;
        uint8_t OrigConnId[QUIC_MAX_CONNECTION_ID_LENGTH_V1];
        uint8_t OrigConnIdLength;
    } Encrypted;
    uint8_t EncryptionTag[CXPLAT_ENCRYPTION_OVERHEAD];
} QUIC_TOKEN_CONTENTS;

//
// The per recv buffer context type.
//
typedef struct CXPLAT_RECV_PACKET {

    //
    // The unique identifier for the packet.
    //
    uint64_t PacketId;

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
        const struct QUIC_HEADER_INVARIANT* Invariant;
        const struct QUIC_VERSION_NEGOTIATION_PACKET* VerNeg;
        const struct QUIC_LONG_HEADER_V1* LH;
        const struct QUIC_RETRY_PACKET_V1* Retry;
        const struct QUIC_SHORT_HEADER_V1* SH;
    };

    //
    // Destination connection ID.
    //
    const uint8_t* DestCid;

    //
    // Sources connection ID. Only valid for long header packets.
    //
    const uint8_t* SourceCid;

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
    uint8_t DestCidLen;
    uint8_t SourceCidLen;

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
    // Flag indicating the packet is encrypted.
    //
    BOOLEAN Encrypted : 1;

    //
    // Flag indicating 0-RTT encryption.
    //
    BOOLEAN EncryptedWith0Rtt : 1;

    //
    // Flag indicating the packet couldn't be decrypted yet, because the key
    // isn't available yet, or a stateless operation has been queued; so it is
    // still in use and release the packet later.
    //
    BOOLEAN ReleaseDeferred : 1;

    //
    // Flag indicating the packet was completely parsed successfully.
    //
    BOOLEAN CompletelyValid : 1;

    //
    // Flag indicating the packet is the largest packet number seen so far.
    //
    BOOLEAN NewLargestPacketNumber : 1;

    //
    // Flag indicating the packet contained a non-probing frame.
    //
    BOOLEAN HasNonProbingFrame : 1;

} CXPLAT_RECV_PACKET;

typedef enum QUIC_BINDING_LOOKUP_TYPE {

    QUIC_BINDING_LOOKUP_SINGLE,         // Single connection
    QUIC_BINDING_LOOKUP_HASH,           // Single hash table of connections
    QUIC_BINDING_LOOKUP_MULTI_HASH      // Partitioned hash tables of connections

} QUIC_BINDING_LOOKUP_TYPE;

//
// Represents a UDP binding of local IP address and UDP port, and optionally
// remote IP address.
//
typedef struct QUIC_BINDING {

    //
    // The link in the library's global list of bindings.
    //
    CXPLAT_LIST_ENTRY Link;

    //
    // Indicates whether the binding is exclusively owned already. Defaults
    // to TRUE.
    //
    BOOLEAN Exclusive : 1;

    //
    // Indicates whether the binding is owned by the server side (i.e. listener
    // and server connections) or by the client side. Different receive side
    // logic is used for each, so the binding cannot be shared between clients
    // and servers.
    //
    BOOLEAN ServerOwned : 1;

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
    CXPLAT_SOCKET* Socket;

    //
    // Lock for accessing the listeners.
    //
    CXPLAT_DISPATCH_RW_LOCK RwLock;

    //
    // The listeners registered on this binding.
    //
    CXPLAT_LIST_ENTRY Listeners;

    //
    // Lookup tables for connection IDs.
    //
    QUIC_LOOKUP Lookup;

    //
    // Stateless operation tracking structures.
    //
    CXPLAT_DISPATCH_LOCK StatelessOperLock;
    CXPLAT_HASHTABLE StatelessOperTable;
    CXPLAT_LIST_ENTRY StatelessOperList;
    CXPLAT_POOL StatelessOperCtxPool;
    uint32_t StatelessOperCount;

    struct {

        struct {
            uint64_t DroppedPackets;
        } Recv;

    } Stats;

} QUIC_BINDING;

//
// Global callbacks for all QUIC UDP bindings.
//
CXPLAT_DATAPATH_RECEIVE_CALLBACK QuicBindingReceive;
CXPLAT_DATAPATH_UNREACHABLE_CALLBACK QuicBindingUnreachable;

//
// Initializes a new binding.
//
_IRQL_requires_max_(PASSIVE_LEVEL)
QUIC_STATUS
QuicBindingInitialize(
    _In_ const CXPLAT_UDP_CONFIG* UdpConfig,
    _Out_ QUIC_BINDING** NewBinding
    );

//
// Uninitializes the binding. This cleans up the datapath binding, which blocks
// on all outstanding upcalls. DO NOT call this on a datapath upcall thread!
//
_IRQL_requires_max_(PASSIVE_LEVEL)
void
QuicBindingUninitialize(
    _In_ QUIC_BINDING* Binding
    );

//
// Tracing rundown for the binding.
//
_IRQL_requires_max_(DISPATCH_LEVEL)
void
QuicBindingTraceRundown(
    _In_ QUIC_BINDING* Binding
    );

//
// Queries the local IP address of the binding.
//
_IRQL_requires_max_(DISPATCH_LEVEL)
void
QuicBindingGetLocalAddress(
    _In_ QUIC_BINDING* Binding,
    _Out_ QUIC_ADDR* Address
    );

//
// Queries the remote IP address of the binding.
//
_IRQL_requires_max_(DISPATCH_LEVEL)
void
QuicBindingGetRemoteAddress(
    _In_ QUIC_BINDING* Binding,
    _Out_ QUIC_ADDR* Address
    );

//
// Looks up the listener based on the ALPN list. Optionally, outputs the
// first ALPN that matches.
//
_IRQL_requires_max_(PASSIVE_LEVEL)
_Success_(return != NULL)
QUIC_LISTENER*
QuicBindingGetListener(
    _In_ QUIC_BINDING* Binding,
    _In_opt_ QUIC_CONNECTION* Connection,
    _Inout_ QUIC_NEW_CONNECTION_INFO* Info
    );

//
// Attempts to register a listener with the binding.
//
_IRQL_requires_max_(PASSIVE_LEVEL)
BOOLEAN
QuicBindingRegisterListener(
    _In_ QUIC_BINDING* Binding,
    _In_ QUIC_LISTENER* Listener
    );

//
// Unregister a listener from the binding.
//
_IRQL_requires_max_(PASSIVE_LEVEL)
void
QuicBindingUnregisterListener(
    _In_ QUIC_BINDING* Binding,
    _In_ QUIC_LISTENER* Listener
    );

//
// Passes the connection to the binding to (possibly) accept it.
//
_IRQL_requires_max_(PASSIVE_LEVEL)
void
QuicBindingAcceptConnection(
    _In_ QUIC_BINDING* Binding,
    _In_ QUIC_CONNECTION* Connection,
    _In_ QUIC_NEW_CONNECTION_INFO* Info
    );

//
// Attempts to insert the connection's new source CID into the binding's
// lookup table.
//
_IRQL_requires_max_(DISPATCH_LEVEL)
BOOLEAN
QuicBindingAddSourceConnectionID(
    _In_ QUIC_BINDING* Binding,
    _In_ QUIC_CID_HASH_ENTRY* SourceCid
    );

//
// Removes a single source CID from the binding's lookup table.
//
_IRQL_requires_max_(DISPATCH_LEVEL)
void
QuicBindingRemoveSourceConnectionID(
    _In_ QUIC_BINDING* Binding,
    _In_ QUIC_CID_HASH_ENTRY* SourceCid,
    _In_ CXPLAT_SLIST_ENTRY** Entry
    );

//
// Removes all the connection's source CIDs from the binding's lookup table.
//
_IRQL_requires_max_(DISPATCH_LEVEL)
void
QuicBindingRemoveConnection(
    _In_ QUIC_BINDING* Binding,
    _In_ QUIC_CONNECTION* Connection
    );

//
// Moves all the connections source CIDs from the one binding's lookup table to
// another.
//
_IRQL_requires_max_(DISPATCH_LEVEL)
void
QuicBindingMoveSourceConnectionIDs(
    _In_ QUIC_BINDING* BindingSrc,
    _In_ QUIC_BINDING* BindingDest,
    _In_ QUIC_CONNECTION* Connection
    );

//
// Indicates to the binding that the connection is no longer accepting
// handshake/long header packets.
//
_IRQL_requires_max_(DISPATCH_LEVEL)
void
QuicBindingOnConnectionHandshakeConfirmed(
    _In_ QUIC_BINDING* Binding,
    _In_ QUIC_CONNECTION* Connection
    );

//
// Queues a stateless operation on the binding.
//
_IRQL_requires_max_(DISPATCH_LEVEL)
BOOLEAN
QuicBindingQueueStatelessOperation(
    _In_ QUIC_BINDING* Binding,
    _In_ QUIC_OPERATION_TYPE OperType,
    _In_ CXPLAT_RECV_DATA* Datagram
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
QuicBindingSend(
    _In_ QUIC_BINDING* Binding,
    _In_ const CXPLAT_ROUTE* Route,
    _In_ CXPLAT_SEND_DATA* SendData,
    _In_ uint32_t BytesToSend,
    _In_ uint32_t DatagramsToSend,
    _In_ uint16_t IdealProcessor
    );

//
// Decrypts the retry token.
//
inline
_IRQL_requires_max_(DISPATCH_LEVEL)
BOOLEAN
QuicRetryTokenDecrypt(
    _In_ const CXPLAT_RECV_PACKET* const Packet,
    _In_reads_(sizeof(QUIC_TOKEN_CONTENTS))
        const uint8_t* TokenBuffer,
    _Out_ QUIC_TOKEN_CONTENTS* Token
    )
{
    //
    // Copy the token locally so as to not effect the original packet buffer,
    //
    CxPlatCopyMemory(Token, TokenBuffer, sizeof(QUIC_TOKEN_CONTENTS));

    uint8_t Iv[CXPLAT_MAX_IV_LENGTH];
    if (MsQuicLib.CidTotalLength >= CXPLAT_IV_LENGTH) {
        CxPlatCopyMemory(Iv, Packet->DestCid, CXPLAT_IV_LENGTH);
        for (uint8_t i = CXPLAT_IV_LENGTH; i < MsQuicLib.CidTotalLength; ++i) {
            Iv[i % CXPLAT_IV_LENGTH] ^= Packet->DestCid[i];
        }
    } else {
        CxPlatZeroMemory(Iv, CXPLAT_IV_LENGTH);
        CxPlatCopyMemory(Iv, Packet->DestCid, MsQuicLib.CidTotalLength);
    }

    CxPlatDispatchLockAcquire(&MsQuicLib.StatelessRetryKeysLock);

    CXPLAT_KEY* StatelessRetryKey =
        QuicLibraryGetStatelessRetryKeyForTimestamp(
            (int64_t)Token->Authenticated.Timestamp);
    if (StatelessRetryKey == NULL) {
        CxPlatDispatchLockRelease(&MsQuicLib.StatelessRetryKeysLock);
        return FALSE;
    }

    QUIC_STATUS Status =
        CxPlatDecrypt(
            StatelessRetryKey,
            Iv,
            sizeof(Token->Authenticated),
            (uint8_t*) &Token->Authenticated,
            sizeof(Token->Encrypted) + sizeof(Token->EncryptionTag),
            (uint8_t*)&Token->Encrypted);

    CxPlatDispatchLockRelease(&MsQuicLib.StatelessRetryKeysLock);
    return QUIC_SUCCEEDED(Status);
}
