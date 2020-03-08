/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.

Abstract:

    miTLS TLS Implementation for QUIC

--*/

#include "platform_internal.h"

#ifdef QUIC_LOGS_WPP
#include "tls_mitls.tmh"
#endif

#define IS_WINDOWS 1
#pragma warning(disable:4996) // Deprecated APIs
#include <EverCrypt.h>
#include <mitlsffi.h>

uint16_t QuicTlsTPHeaderSize = 0;

#define QUIC_SUPPORTED_CIPHER_SUITES        "TLS_AES_128_GCM_SHA256"
#define QUIC_SERVER_SIGNATURE_ALGORITHMS    "ECDSA+SHA256:ECDSA+SHA384:ECDSA+SHA512:RSAPSS+SHA256:RSAPSS+SHA384:RSAPSS+SHA512"
#define QUIC_CLIENT_SIGNATURE_ALGORITHMS    "ECDSA+SHA256:ECDSA+SHA384:ECDSA+SHA512:RSAPSS+SHA256:RSAPSS+SHA384:RSAPSS+SHA512"
#if QUIC_PROD_MITLS
#define QUIC_SERVER_NAMED_GROUPS            "P-521:P-384:P-256:X25519:FFDHE4096:FFDHE3072:FFDHE2048"
#define QUIC_CLIENT_NAMED_GROUPS            "P-384:P-256:X25519"
#else
#define QUIC_SERVER_NAMED_GROUPS            "X25519"
#define QUIC_CLIENT_NAMED_GROUPS            "X25519"
#endif

//
// The maximum message buffer length.
//
#define QUIC_TLS_MAX_MESSAGE_LENGTH (8 * 1024)

const QUIC_PACKET_KEY_TYPE miTlsKeyTypes[2][4] =
{
    { QUIC_PACKET_KEY_INITIAL, QUIC_PACKET_KEY_HANDSHAKE, QUIC_PACKET_KEY_1_RTT, QUIC_PACKET_KEY_1_RTT },
    { QUIC_PACKET_KEY_INITIAL, QUIC_PACKET_KEY_0_RTT, QUIC_PACKET_KEY_HANDSHAKE, QUIC_PACKET_KEY_1_RTT }
};

//
// Callback for miTLS when a new ticket is ready.
//
_IRQL_requires_max_(PASSIVE_LEVEL)
_Success_(return != TLS_nego_abort)
mitls_nego_action
MITLS_CALLCONV
QuicTlsOnNegotiate(
    _In_ void *Context,
    _In_ mitls_version Version,
    _In_reads_(RawExtensionsLength)
        const uint8_t *RawExtensions,
    _In_ size_t RawExtensionsLength,
    _Deref_post_opt_count_(*CustomExtensionsLength)
        mitls_extension **CustomExtensions,
    _Out_ size_t *CustomExtensionsLength,
    _Deref_pre_opt_count_(*CookieLength)
    _Deref_post_opt_count_(*CookieLength)
        uint8_t **Cookie,
    _Inout_ size_t *CookieLength
    );

//
// Callback for miTLS when a new ticket is ready.
//
_IRQL_requires_max_(PASSIVE_LEVEL)
void
MITLS_CALLCONV
QuicTlsOnTicketReady(
    void *Context,
    const char *ServerNameIndication, // SNI
    const mitls_ticket *Ticket
    );

//
// Select a certificate based on the given SNI and list of signatures.
// Signature algorithms are represented as 16-bit integers using the
// TLS 1.3 RFC code points.
//
_IRQL_requires_max_(PASSIVE_LEVEL)
void*
MITLS_CALLCONV
QuicTlsOnCertSelect(
    void *Context,
    mitls_version TlsVersion,
    const uint8_t *ServerNameIndication,
    size_t ServerNameIndicationLength,
    const uint8_t *Alpn,
    size_t AlpnLength,
    const mitls_signature_scheme *SignatureAlgorithms,
    size_t SignatureAlgorithmsLength,
    mitls_signature_scheme *SelectedSignature
    );

//
// Write the certificate chain to 'Buffer', returning the number of written
// bytes. The chain should be written by prefixing each certificate by its
// length encoded over 3 bytes.
//
_IRQL_requires_max_(PASSIVE_LEVEL)
size_t
MITLS_CALLCONV
QuicTlsOnCertFormat(
    void *Context,
    const void *SecContext,
    uint8_t Buffer[MAX_CHAIN_LEN]
    );

//
// Tries to sign and write the signature to 'Signature', returning the
// signature size or 0 if signature failed.
//
_IRQL_requires_max_(PASSIVE_LEVEL)
size_t
MITLS_CALLCONV
QuicTlsOnCertSign(
    void *Context,
    const void *SecContext,
    const mitls_signature_scheme SignatureAlgorithm,
    const uint8_t *CertListToBeSigned, // TBS
    size_t CertListToBeSignedLength,
    uint8_t *Signature
    );

//
// Verifies that the chain (given in the same format as above) is valid, and
// that 'Signature' is a valid signature of 'CertListToBeSigned' for
// 'SignatureAlgorithm' using the public key stored in the leaf of the chain.
// N.B. this function must validate the chain (including applcation checks such
// as hostname matching).
//
_IRQL_requires_max_(PASSIVE_LEVEL)
int
MITLS_CALLCONV
QuicTlsOnCertVerify(
    void *Context,
    const uint8_t* ChainBuffer,
    size_t ChainBufferLength,
    const mitls_signature_scheme SignatureAlgorithm,
    const uint8_t* CertListToBeSigned, // TBS
    size_t CertListToBeSignedLength,
    const uint8_t *Signature,
    size_t SignatureLength
    );

//
// Helper function for miTLS to export the key we need.
//
_IRQL_requires_max_(PASSIVE_LEVEL)
_Success_(return != FALSE)
BOOLEAN
QuicPacketKeyCreate(
    _In_ QUIC_TLS* TlsContext,
    _In_ QUIC_PACKET_KEY_TYPE KeyType,
    _In_ int Epoch,
    _In_ quic_direction rw,
    _Out_ QUIC_PACKET_KEY** NewKey
    );

//
// TLS Security Config
//
typedef struct QUIC_SEC_CONFIG {

    //
    // Rundown tracking the clean up of all server security configs.
    //
    QUIC_RUNDOWN_REF* CleanupRundown;

    //
    // Reference count to keep credentials alive long enough.
    //
    long RefCount;

    //
    // Configuration flags.
    //
    uint32_t Flags;

    //
    // The certificate context, used for signing.
    //
    QUIC_CERT* Certificate;
    void* PrivateKey;

    //
    // Formatted certificate bytes for sending on the wire.
    //
    uint16_t FormatLength;
    uint8_t FormatBuffer[QUIC_TLS_MAX_MESSAGE_LENGTH];

} QUIC_SEC_CONFIG;

//
// The TLS session.
//
typedef struct QUIC_TLS_SESSION {

    //
    // Total number of references on the TLS session. Only freed once all
    // references are released.
    //
    long RefCount;

    //
    // Lock protecting parallel access to the ticket store.
    //
    QUIC_RW_LOCK TicketStoreLock;

    //
    // The in memory ticket store for this session.
    //
    QUIC_HASHTABLE TicketStore;

    //
    // Length of the Alpn array
    //
    uint16_t AlpnLength;

    //
    // Array of ALPN strings.
    //
    const char Alpn[0];

} QUIC_TLS_SESSION;

//
// Contiguous memory representation of a ticket.
//
typedef struct QUIC_TLS_TICKET {

    uint16_t ServerNameLength;
    uint16_t TicketLength;
    uint16_t SessionLength;
    _Field_size_(ServerNameLength + TicketLength + SessionLength)
    uint8_t Buffer[0];

} QUIC_TLS_TICKET;

//
// Entry into the TLS ticket store.
//
typedef struct QUIC_TLS_TICKET_ENTRY {

    QUIC_HASHTABLE_ENTRY Entry;
    long RefCount;
    QUIC_TLS_TICKET Ticket;

} QUIC_TLS_TICKET_ENTRY;

//
// Releases a reference on the TLS ticket, and frees it if it was the last ref.
//
_IRQL_requires_max_(PASSIVE_LEVEL)
void
QuicTlsTicketRelease(
    _In_ QUIC_TLS_TICKET* Ticket
    )
{
    QUIC_TLS_TICKET_ENTRY* TicketEntry =
        QUIC_CONTAINING_RECORD(Ticket, QUIC_TLS_TICKET_ENTRY, Ticket);
    if (InterlockedDecrement(&TicketEntry->RefCount) == 0) {
        QUIC_FREE(TicketEntry);
    }
}

//
// The TLS interface context.
//
typedef struct QUIC_TLS {

    //
    // Flag indicating if the TLS represents a server.
    //
    BOOLEAN IsServer : 1;

    //
    // Flag indicating the server has sent an updated ticket.
    //
    BOOLEAN TicketReady : 1;

    //
    // Index into the miTlsKeyTypes array.
    //
    uint8_t TlsKeySchedule : 1;
    uint8_t TlsKeyScheduleSet : 1;

    //
    // Parent TLS session.
    //
    QUIC_TLS_SESSION* TlsSession;

    //
    // The TLS configuration information and credentials.
    //
    QUIC_SEC_CONFIG* SecConfig;

    //
    // Server Name Indication.
    //
    const char* SNI;

    //
    // The current write buffer length.
    //
    uint32_t BufferLength;

    //
    // Buffer for writing.
    //
    const uint8_t* Buffer;

    //
    // Current reader epoch.
    //
    int32_t CurrentReaderKey;

    //
    // Current writer epoch.
    //
    int32_t CurrentWriterKey;

    //
    // Ticket from the ticket store.
    //
    QUIC_TLS_TICKET* Ticket;

    //
    // Process state for the outstanding process call.
    //
    QUIC_TLS_PROCESS_STATE* State;

    //
    // Callback handlers and input connection.
    //
    QUIC_CONNECTION* Connection;
    QUIC_TLS_PROCESS_COMPLETE_CALLBACK_HANDLER ProcessCompleteCallback;
    QUIC_TLS_RECEIVE_TP_CALLBACK_HANDLER ReceiveTPCallback;

    //
    // miTLS Config.
    //
    quic_config miTlsConfig;
    mitls_alpn miTlsConfigAlpn;

    //
    // Callbacks used my miTLS to operate on certificates.
    //
    mitls_cert_cb miTlsCertCallbacks;

    //
    // The miTLS library state.
    //
    quic_state *miTlsState;

    //
    // Storage for the ticket passed to miTLS.
    //
    mitls_ticket miTlsTicket;

    //
    // Storage for encoded local transport parameters.
    //
    mitls_extension LocalTP;

} QUIC_TLS;

//
// Callback from mitls for logging purposes.
//
void
MITLS_CALLCONV
MiTlsTraceCallback(
    _In_z_ const char *Msg
    )
{
    // TODO - Save connection in thread-local storage and retrieve it?
    QuicTraceEvent(TlsMessage, NULL, Msg);
}

QUIC_STATUS
QuicTlsLibraryInitialize(
    void
    )
{
    QUIC_STATUS Status;

    QuicTraceLogVerbose("[ tls] Initializing miTLS library");
    FFI_mitls_set_trace_callback(MiTlsTraceCallback);
    if (!FFI_mitls_init()) {
        Status = QUIC_STATUS_INVALID_STATE;
        QuicTraceLogError("[ tls] FFI_mitls_init failed.");
        goto Error;
    }

    uint8_t Key[QUIC_IV_LENGTH + 32] = { 0 }; // Always use the same null key client side right now.
    if (!FFI_mitls_set_sealing_key("AES256-GCM", Key, sizeof(Key))) {
        Status = QUIC_STATUS_INVALID_STATE;
        QuicTraceLogError("[ tls] FFI_mitls_set_sealing_key failed.");
        FFI_mitls_cleanup();
        goto Error;
    }

    //
    // Randomly initialize the server's 0-RTT ticket encryption key.
    //
    QuicRandom(sizeof(Key), Key);
    if (!FFI_mitls_set_ticket_key("AES256-GCM", Key, sizeof(Key))) {
        Status = QUIC_STATUS_INVALID_STATE;
        QuicTraceLogError("[ tls] FFI_mitls_set_ticket_key failed.");
        FFI_mitls_cleanup();
        goto Error;
    }

    Status = QUIC_STATUS_SUCCESS;

Error:

    return Status;
}

void
QuicTlsLibraryUninitialize(
    void
    )
{
    QuicTraceLogVerbose("[ tls] Cleaning up miTLS library");
    FFI_mitls_cleanup();
}

_IRQL_requires_max_(PASSIVE_LEVEL)
void
QuicTlsSecConfigDelete(
    _In_ QUIC_SEC_CONFIG* SecurityConfig
    )
{
    if (SecurityConfig->PrivateKey != NULL) {
        QuicCertDeletePrivateKey(SecurityConfig->PrivateKey);
    }
    if (SecurityConfig->Certificate != NULL &&
        !(SecurityConfig->Flags & QUIC_SEC_CONFIG_FLAG_CERTIFICATE_CONTEXT)) {
        QuicCertFree(SecurityConfig->Certificate);
    }
    QUIC_RUNDOWN_REF* Rundown = SecurityConfig->CleanupRundown;
    QUIC_FREE(SecurityConfig);
    if (Rundown != NULL) {
        QuicRundownRelease(Rundown);
    }
}

_IRQL_requires_max_(PASSIVE_LEVEL)
QUIC_STATUS
QuicTlsServerSecConfigCreate(
    _Inout_ QUIC_RUNDOWN_REF* Rundown,
    _In_ QUIC_SEC_CONFIG_FLAGS Flags,
    _In_opt_ void* Certificate,
    _In_opt_z_ const char* Principal,
    _In_opt_ void* Context,
    _In_ QUIC_SEC_CONFIG_CREATE_COMPLETE_HANDLER CompletionHandler
    )
{
    QUIC_STATUS Status;
    QUIC_SEC_CONFIG* SecurityConfig = NULL;

    if (Flags & QUIC_SEC_CONFIG_FLAG_CERTIFICATE_FILE) {
        Status = QUIC_STATUS_INVALID_PARAMETER;
        goto Error;
    }

    if (!QuicRundownAcquire(Rundown)) {
        QuicTraceLogError("[ tls] Failed to acquire sec config rundown.");
        Status = QUIC_STATUS_INVALID_STATE;
        goto Error;
    }

#pragma prefast(suppress: __WARNING_6014, "Memory is correctly freed (QuicTlsSecConfigDelete).")
    SecurityConfig = QUIC_ALLOC_PAGED(sizeof(QUIC_SEC_CONFIG));
    if (SecurityConfig == NULL) {
        QuicRundownRelease(Rundown);
        Status = QUIC_STATUS_OUT_OF_MEMORY;
        goto Error;
    }

    SecurityConfig->CleanupRundown = Rundown;
    SecurityConfig->Flags = Flags;
    SecurityConfig->RefCount = 1;
    SecurityConfig->Certificate = NULL;
    SecurityConfig->PrivateKey = NULL;

    if (Flags == QUIC_SEC_CONFIG_FLAG_CERTIFICATE_NULL) {
        //
        // Using NULL certificate and private key.
        //
        goto Format;
    } else if (Flags & QUIC_SEC_CONFIG_FLAG_CERTIFICATE_CONTEXT) {
        if (Certificate == NULL) {
            Status = QUIC_STATUS_INVALID_PARAMETER;
            goto Error;
        }
        SecurityConfig->Certificate = (QUIC_CERT*)Certificate;
    } else {
        Status =
            QuicCertCreate(
                Flags,
                Certificate,
                Principal,
                &SecurityConfig->Certificate);
        if (QUIC_FAILED(Status)) {
            goto Error;
        }
    }

    SecurityConfig->PrivateKey =
        QuicCertGetPrivateKey(SecurityConfig->Certificate);
    if (SecurityConfig->PrivateKey == NULL) {
        Status = QUIC_STATUS_INVALID_PARAMETER;
        goto Error;
    }

Format:

    SecurityConfig->FormatLength =
        (uint16_t)QuicCertFormat(
            SecurityConfig->Certificate,
            sizeof(SecurityConfig->FormatBuffer),
            SecurityConfig->FormatBuffer);

    Status = QUIC_STATUS_SUCCESS;

    CompletionHandler(
        Context,
        Status,
        SecurityConfig);
    SecurityConfig = NULL;

Error:

    if (SecurityConfig != NULL) {
        QuicTlsSecConfigDelete(SecurityConfig);
    }

    return Status;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
QUIC_STATUS
QuicTlsClientSecConfigCreate(
    _In_ uint32_t Flags,
    _Outptr_ QUIC_SEC_CONFIG** ClientConfig
    )
{
    #pragma prefast(suppress: __WARNING_6014, "Memory is correctly freed (QuicTlsSecConfigDelete).")
    QUIC_SEC_CONFIG* SecurityConfig = QUIC_ALLOC_PAGED(sizeof(QUIC_SEC_CONFIG));
    if (SecurityConfig == NULL) {
        return QUIC_STATUS_OUT_OF_MEMORY;
    }

    QuicZeroMemory(SecurityConfig, sizeof(*SecurityConfig));
    SecurityConfig->Flags = (uint32_t)Flags;
    SecurityConfig->RefCount = 1;

    *ClientConfig = SecurityConfig;
    return QUIC_STATUS_SUCCESS;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
QUIC_SEC_CONFIG*
QuicTlsSecConfigAddRef(
    _In_ QUIC_SEC_CONFIG* SecurityConfig
    )
{
    InterlockedIncrement(&SecurityConfig->RefCount);
    return SecurityConfig;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
void
QUIC_API
QuicTlsSecConfigRelease(
    _In_ QUIC_SEC_CONFIG* SecurityConfig
    )
{
    if (InterlockedDecrement(&SecurityConfig->RefCount) == 0) {
        QuicTlsSecConfigDelete(SecurityConfig);
    }
}

_IRQL_requires_max_(PASSIVE_LEVEL)
QUIC_STATUS
QuicTlsSessionInitialize(
    _In_z_ const char* ALPN,
    _Out_ QUIC_TLS_SESSION** NewTlsSession
    )
{
    QUIC_STATUS Status;
    QUIC_TLS_SESSION* TlsSession = NULL;

    size_t ALPNLength = strlen(ALPN);
    if (ALPNLength > UINT16_MAX) {
        Status = QUIC_STATUS_INVALID_PARAMETER;
        goto Error;
    }

    TlsSession = QUIC_ALLOC_PAGED(sizeof(QUIC_TLS_SESSION) + ALPNLength);
    if (TlsSession == NULL) {
        Status = QUIC_STATUS_OUT_OF_MEMORY;
        goto Error;
    }

    if (!QuicHashtableInitializeEx(&TlsSession->TicketStore, QUIC_HASH_MIN_SIZE)) {
        Status = QUIC_STATUS_OUT_OF_MEMORY;
        goto Error;
    }

    QuicRwLockInitialize(&TlsSession->TicketStoreLock);
    QuicCopyMemory((char*)TlsSession->Alpn, ALPN, ALPNLength);
    TlsSession->AlpnLength = (uint16_t)ALPNLength;
    TlsSession->RefCount = 1;

    *NewTlsSession = TlsSession;
    TlsSession = NULL;

    Status = QUIC_STATUS_SUCCESS;

Error:

    if (TlsSession != NULL) {
        QUIC_FREE(TlsSession);
    }

    return Status;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
void
QuicTlsSessionFree(
    _In_opt_ QUIC_TLS_SESSION* TlsSession
    )
{
    if (TlsSession != NULL) {

        //
        // Enumerate and free all entries in the table.
        //
        QUIC_HASHTABLE_ENTRY* Entry;
        QUIC_HASHTABLE_ENUMERATOR Enumerator;
        QuicHashtableEnumerateBegin(&TlsSession->TicketStore, &Enumerator);
        while (TRUE) {
            Entry = QuicHashtableEnumerateNext(&TlsSession->TicketStore, &Enumerator);
            if (Entry == NULL) {
                QuicHashtableEnumerateEnd(&TlsSession->TicketStore, &Enumerator);
                break;
            }
            QuicHashtableRemove(&TlsSession->TicketStore, Entry, NULL);
            QUIC_FREE(Entry);
        }

        QuicHashtableUninitialize(&TlsSession->TicketStore);
        QuicRwLockUninitialize(&TlsSession->TicketStoreLock);
        QUIC_FREE(TlsSession);
    }
}

_IRQL_requires_max_(PASSIVE_LEVEL)
QUIC_TLS_SESSION*
QuicTlsSessionAddRef(
    _In_ QUIC_TLS_SESSION* TlsSession
    )
{
    InterlockedIncrement(&TlsSession->RefCount);
    return TlsSession;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
void
QuicTlsSessionRelease(
    _In_ QUIC_TLS_SESSION* TlsSession
    )
{
    if (InterlockedDecrement(&TlsSession->RefCount) == 0) {
        QuicTlsSessionFree(TlsSession);
    }
}

_IRQL_requires_max_(PASSIVE_LEVEL)
void
QuicTlsSessionUninitialize(
    _In_opt_ QUIC_TLS_SESSION* TlsSession
    )
{
    if (TlsSession != NULL) {
        QuicTlsSessionRelease(TlsSession);
    }
}

_IRQL_requires_max_(PASSIVE_LEVEL)
QUIC_STATUS
QuicTlsSessionSetTicketKey(
    _In_ QUIC_TLS_SESSION* TlsSession,
    _In_reads_bytes_(44)
        const void* Buffer
    )
{
    UNREFERENCED_PARAMETER(TlsSession); // miTLS doesn't actually support sessions.
    if (!FFI_mitls_set_ticket_key("AES256-GCM", (uint8_t*)Buffer, 44)) {
        QuicTraceLogError("[ tls] FFI_mitls_set_ticket_key failed.");
        return QUIC_STATUS_INVALID_STATE;
    }
    return QUIC_STATUS_SUCCESS;
}

//
// Requires TlsSession->TicketStoreLock to be held (shared or exclusive).
//
_IRQL_requires_max_(PASSIVE_LEVEL)
QUIC_TLS_TICKET_ENTRY*
QuicTlsSessionLookupTicketEntry(
    _In_ QUIC_TLS_SESSION* TlsSession,
    _In_ uint16_t ServerNameLength,
    _In_reads_(ServerNameLength)
        const char* ServerName,
    _In_ uint32_t TicketHash
    )
{
    QUIC_HASHTABLE_LOOKUP_CONTEXT Context;
    QUIC_HASHTABLE_ENTRY* Entry =
        QuicHashtableLookup(&TlsSession->TicketStore, TicketHash, &Context);

    while (Entry != NULL) {
        QUIC_TLS_TICKET_ENTRY* Temp =
            QUIC_CONTAINING_RECORD(Entry, QUIC_TLS_TICKET_ENTRY, Entry);
        if (Temp->Ticket.ServerNameLength == ServerNameLength &&
            memcmp(Temp->Ticket.Buffer, ServerName, ServerNameLength) == 0) {
            return Temp;
        }
        Entry = QuicHashtableLookupNext(&TlsSession->TicketStore, &Context);
    }

    return NULL;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
void
QuicTlsSessionInsertTicketEntry(
    _In_ QUIC_TLS_SESSION* TlsSession,
    _In_ QUIC_TLS_TICKET_ENTRY* NewTicketEntry
    )
{
    uint32_t TicketHash =
        QuicHashSimple(
            NewTicketEntry->Ticket.ServerNameLength,
            NewTicketEntry->Ticket.Buffer);

    QuicRwLockAcquireExclusive(&TlsSession->TicketStoreLock);

    //
    // Since we only allow one entry per server name, we need to see if there
    // is already a ticket in the store, and if so, remove it.
    //
    QUIC_TLS_TICKET_ENTRY* OldTicketEntry =
        QuicTlsSessionLookupTicketEntry(
            TlsSession,
            NewTicketEntry->Ticket.ServerNameLength,
            (const char*)NewTicketEntry->Ticket.Buffer,
            TicketHash);

    if (OldTicketEntry != NULL) {
        QuicHashtableRemove(
            &TlsSession->TicketStore, &OldTicketEntry->Entry, NULL);
    }

    //
    // Add the new ticket to the store.
    //
    QuicHashtableInsert(
        &TlsSession->TicketStore,
        &NewTicketEntry->Entry,
        TicketHash,
        NULL);

    QuicRwLockReleaseExclusive(&TlsSession->TicketStoreLock);

    if (OldTicketEntry != NULL) {
        //
        // Release the old ticket outside the lock.
        //
        QuicTlsTicketRelease(&OldTicketEntry->Ticket);
    }
}

_IRQL_requires_max_(PASSIVE_LEVEL)
QUIC_TLS_TICKET*
QuicTlsSessionGetTicket(
    _In_ QUIC_TLS_SESSION* TlsSession,
    _In_ uint16_t ServerNameLength,
    _In_reads_(ServerNameLength)
        const char* ServerName
    )
{
    uint32_t TicketHash =
        QuicHashSimple(ServerNameLength, (const uint8_t*)ServerName);

    QuicRwLockAcquireShared(&TlsSession->TicketStoreLock);

    QUIC_TLS_TICKET_ENTRY* TicketEntry =
        QuicTlsSessionLookupTicketEntry(
            TlsSession, ServerNameLength, ServerName, TicketHash);

    if (TicketEntry != NULL) {
        InterlockedIncrement(&TicketEntry->RefCount);
    }

    QuicRwLockReleaseShared(&TlsSession->TicketStoreLock);

    return TicketEntry  == NULL ? NULL : &TicketEntry->Ticket;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
QUIC_STATUS
QuicTlsSessionAddTicket(
    _In_ QUIC_TLS_SESSION* TlsSession,
    _In_ uint32_t BufferLength,
    _In_reads_bytes_(BufferLength)
        const uint8_t * const Buffer
    )
{
    const QUIC_TLS_TICKET* const Ticket = (const QUIC_TLS_TICKET* const)Buffer;

    if (BufferLength < sizeof(QUIC_TLS_TICKET)) {
        return QUIC_STATUS_INVALID_PARAMETER;
    }

    uint32_t ExpectedBufferLength =
        sizeof(QUIC_TLS_TICKET) +
        Ticket->ServerNameLength +
        Ticket->TicketLength +
        Ticket->SessionLength;

    if (BufferLength < ExpectedBufferLength) {
        return QUIC_STATUS_INVALID_PARAMETER;
    }

    size_t TicketEntryLength =
        sizeof(QUIC_TLS_TICKET_ENTRY) +
        Ticket->ServerNameLength +
        Ticket->TicketLength +
        Ticket->SessionLength;

#pragma prefast(suppress: __WARNING_6014, "Memory is correctly freed (TLS Session is cleaned up).")
    QUIC_TLS_TICKET_ENTRY* TicketEntry =
        (QUIC_TLS_TICKET_ENTRY*)QUIC_ALLOC_PAGED(TicketEntryLength);

    if (TicketEntry == NULL) {
        QuicTraceLogWarning("[tlss][%p] Failed to allocate ticket entry of %u bytes.", TlsSession, (uint32_t)TicketEntryLength);
        return QUIC_STATUS_OUT_OF_MEMORY;
    }

    TicketEntry->RefCount = 1; // 1 for the store.
    memcpy(&TicketEntry->Ticket, Ticket, ExpectedBufferLength);

    QuicTlsSessionInsertTicketEntry(TlsSession, TicketEntry);

    return QUIC_STATUS_SUCCESS;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
QUIC_TLS_TICKET*
QuicTlsSessionCreateTicket(
    _In_ QUIC_TLS_SESSION* TlsSession,
    _In_z_ const char* ServerName,
    _In_ const mitls_ticket* miTlsTicket
    )
{
    uint16_t ServerNameLength = (uint16_t)strlen(ServerName);

    size_t TicketEntryLength =
        sizeof(QUIC_TLS_TICKET_ENTRY) +
        ServerNameLength +
        miTlsTicket->ticket_len +
        miTlsTicket->session_len;

    QUIC_TLS_TICKET_ENTRY* TicketEntry =
        (QUIC_TLS_TICKET_ENTRY*)QUIC_ALLOC_PAGED(TicketEntryLength);

    if (TicketEntry == NULL) {
        QuicTraceLogWarning("[tlss][%p] Failed to allocate ticket entry of %u bytes.", TlsSession, (uint32_t)TicketEntryLength);
        return NULL;
    }

    TicketEntry->RefCount = 2; // 1 for the store, 1 for the return.
    TicketEntry->Ticket.ServerNameLength = ServerNameLength;
    TicketEntry->Ticket.TicketLength = (uint16_t)miTlsTicket->ticket_len;
    TicketEntry->Ticket.SessionLength = (uint16_t)miTlsTicket->session_len;
    memcpy(TicketEntry->Ticket.Buffer, ServerName, ServerNameLength);
    memcpy(TicketEntry->Ticket.Buffer + ServerNameLength, miTlsTicket->ticket, miTlsTicket->ticket_len);
    memcpy(TicketEntry->Ticket.Buffer + ServerNameLength + miTlsTicket->ticket_len, miTlsTicket->session, miTlsTicket->session_len);

    QuicTlsSessionInsertTicketEntry(TlsSession, TicketEntry);

    return &TicketEntry->Ticket;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
QUIC_STATUS
QuicTlsInitialize(
    _In_ const QUIC_TLS_CONFIG* Config,
    _Out_ QUIC_TLS** NewTlsContext
    )
{
    QUIC_STATUS Status;
    QUIC_TLS* TlsContext;

    QUIC_DBG_ASSERT(Config != NULL);
    QUIC_DBG_ASSERT(NewTlsContext != NULL);

    TlsContext = QUIC_ALLOC_PAGED(sizeof(QUIC_TLS));
    if (TlsContext == NULL) {
        QuicTraceLogWarning("[ tls] Failed to allocate QUIC_TLS.");
        Status = QUIC_STATUS_OUT_OF_MEMORY;
        goto Exit;
    }

    QuicZeroMemory(TlsContext, sizeof(QUIC_TLS));

    //
    // Initialize internal variables.
    //
    TlsContext->IsServer = Config->IsServer;
    TlsContext->TlsSession = QuicTlsSessionAddRef(Config->TlsSession);
    TlsContext->SecConfig = QuicTlsSecConfigAddRef(Config->SecConfig);
    TlsContext->CurrentReaderKey = -1;
    TlsContext->CurrentWriterKey = -1;
    TlsContext->Connection = Config->Connection;
    TlsContext->ProcessCompleteCallback = Config->ProcessCompleteCallback;
    TlsContext->ReceiveTPCallback = Config->ReceiveTPCallback;

    TlsContext->LocalTP.ext_type = TLS_EXTENSION_TYPE_QUIC_TRANSPORT_PARAMETERS;
    TlsContext->LocalTP.ext_data = Config->LocalTPBuffer;
    TlsContext->LocalTP.ext_data_len = Config->LocalTPLength;

    TlsContext->miTlsConfig.enable_0rtt = TRUE;
    TlsContext->miTlsConfig.exts = &TlsContext->LocalTP;
    TlsContext->miTlsConfig.exts_count = 1;
    TlsContext->miTlsConfig.cipher_suites = QUIC_SUPPORTED_CIPHER_SUITES;
    TlsContext->miTlsConfig.alpn = &TlsContext->miTlsConfigAlpn;
    TlsContext->miTlsConfig.alpn_count = 1;
    TlsContext->miTlsConfigAlpn.alpn = (const uint8_t*)Config->TlsSession->Alpn;
    TlsContext->miTlsConfigAlpn.alpn_len = Config->TlsSession->AlpnLength;
    TlsContext->miTlsConfig.nego_callback = QuicTlsOnNegotiate;
    TlsContext->miTlsConfig.cert_callbacks = &TlsContext->miTlsCertCallbacks;

    if (Config->IsServer) {

        TlsContext->miTlsConfig.is_server = TRUE;
        TlsContext->miTlsConfig.callback_state = TlsContext;

        TlsContext->miTlsCertCallbacks.select = QuicTlsOnCertSelect;
        TlsContext->miTlsCertCallbacks.format = QuicTlsOnCertFormat;
        TlsContext->miTlsCertCallbacks.sign = QuicTlsOnCertSign;

        //
        // Specific algorithm depending on the cert we are using.
        //
        TlsContext->miTlsConfig.signature_algorithms = QUIC_SERVER_SIGNATURE_ALGORITHMS;
        TlsContext->miTlsConfig.named_groups = QUIC_SERVER_NAMED_GROUPS;

    } else {
        TlsContext->miTlsConfig.is_server = FALSE;

        if (Config->ServerName != NULL) {
            const size_t ServerNameLength =
                strnlen(Config->ServerName, QUIC_MAX_SNI_LENGTH + 1);
            if (ServerNameLength == QUIC_MAX_SNI_LENGTH + 1) {
                QuicTraceLogError("[ tls][%p] Invalid / Too long server name!", TlsContext);
                Status = QUIC_STATUS_INVALID_PARAMETER;
                goto Error;
            }

            TlsContext->SNI = QUIC_ALLOC_PAGED(ServerNameLength + 1);
            if (TlsContext->SNI == NULL) {
                QuicTraceLogWarning("[ tls][%p] Failed to allocate SNI.", TlsContext);
                Status = QUIC_STATUS_OUT_OF_MEMORY;
                goto Error;
            }
            memcpy((char*)TlsContext->SNI, Config->ServerName, ServerNameLength + 1);

            //
            // Look up a 0-RTT ticket from TlsSession ticket store.
            //
            TlsContext->Ticket =
                QuicTlsSessionGetTicket(
                    TlsContext->TlsSession,
                    (uint16_t)ServerNameLength,
                    Config->ServerName);

            if (TlsContext->Ticket != NULL) {

                QuicTraceLogVerbose("[ tls][%p] Using 0-RTT ticket.", TlsContext);

                TlsContext->miTlsTicket.ticket_len = TlsContext->Ticket->TicketLength;
                TlsContext->miTlsTicket.ticket =
                    TlsContext->Ticket->Buffer + TlsContext->Ticket->ServerNameLength;

                TlsContext->miTlsTicket.session_len = TlsContext->Ticket->SessionLength;
                TlsContext->miTlsTicket.session =
                    TlsContext->miTlsTicket.ticket + TlsContext->Ticket->TicketLength;

                TlsContext->miTlsConfig.server_ticket = &TlsContext->miTlsTicket;
            }
        }

        TlsContext->miTlsConfig.host_name = TlsContext->SNI;
        TlsContext->miTlsConfig.callback_state = TlsContext;

        TlsContext->miTlsConfig.ticket_callback = QuicTlsOnTicketReady;
        TlsContext->miTlsCertCallbacks.verify = QuicTlsOnCertVerify;

        //
        // List of supported algorithms for the client.
        //
        TlsContext->miTlsConfig.signature_algorithms = QUIC_CLIENT_SIGNATURE_ALGORITHMS;
        TlsContext->miTlsConfig.named_groups = QUIC_CLIENT_NAMED_GROUPS;
    }

    //
    // Initialize the miTLS library.
    //
    if (!FFI_mitls_quic_create(&TlsContext->miTlsState, &TlsContext->miTlsConfig)) {
        QuicTraceLogError("[ tls][%p] FFI_mitls_quic_create failed.", TlsContext);
        Status = QUIC_STATUS_INVALID_PARAMETER;
        goto Error;
    }

    *NewTlsContext = TlsContext;
    Status = QUIC_STATUS_SUCCESS;

Error:

    if (QUIC_FAILED(Status)) {
        QuicTlsSecConfigRelease(TlsContext->SecConfig);
        if (TlsContext->SNI) {
            QUIC_FREE(TlsContext->SNI);
        }
        QuicTlsSessionRelease(TlsContext->TlsSession);
        QUIC_FREE(TlsContext);
    }

Exit:

    return Status;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
void
QuicTlsUninitialize(
    _In_opt_ QUIC_TLS* TlsContext
    )
{
    if (TlsContext != NULL) {

        FFI_mitls_quic_free(TlsContext->miTlsState);

        if (TlsContext->Ticket != NULL) {
            QuicTlsTicketRelease(TlsContext->Ticket);
        }

        if (TlsContext->SecConfig != NULL) {
            QuicTlsSecConfigRelease(TlsContext->SecConfig);
        }

        if (TlsContext->SNI != NULL) {
            QUIC_FREE(TlsContext->SNI);
        }
        
        if (TlsContext->LocalTP.ext_data != NULL) {
            QUIC_FREE(TlsContext->LocalTP.ext_data);
        }

        QuicTlsSessionRelease(TlsContext->TlsSession);
        QUIC_FREE(TlsContext);
    }
}

_IRQL_requires_max_(PASSIVE_LEVEL)
void
QuicTlsReset(
    _In_ QUIC_TLS* TlsContext
    )
{
    QUIC_DBG_ASSERT(TlsContext->IsServer == FALSE);

    TlsContext->BufferLength = 0;
    TlsContext->CurrentReaderKey = -1;
    TlsContext->CurrentWriterKey = -1;
    TlsContext->TlsKeyScheduleSet = FALSE;

    //
    // Free old miTLS state.
    //
    FFI_mitls_quic_free(TlsContext->miTlsState);
    TlsContext->miTlsState = NULL;

    //
    // Reinitialize new miTLS state.
    //
    if (!FFI_mitls_quic_create(&TlsContext->miTlsState, &TlsContext->miTlsConfig)) {
        QuicTraceLogError("[ tls][%p] FFI_mitls_quic_create failed.", TlsContext);
        QUIC_DBG_ASSERT(FALSE);
    }
}

_IRQL_requires_max_(PASSIVE_LEVEL)
QUIC_SEC_CONFIG*
QuicTlsGetSecConfig(
    _In_ QUIC_TLS* TlsContext
    )
{
    return QuicTlsSecConfigAddRef(TlsContext->SecConfig);
}

_IRQL_requires_max_(PASSIVE_LEVEL)
QUIC_TLS_RESULT_FLAGS
QuicTlsProcessData(
    _In_ QUIC_TLS* TlsContext,
    _In_reads_bytes_(*BufferLength)
        const uint8_t * Buffer,
    _Inout_ uint32_t * BufferLength,
    _Inout_ QUIC_TLS_PROCESS_STATE* State
    )
{
    QUIC_TLS_RESULT_FLAGS ResultFlags = 0;
    uint32_t ConsumedBytes;

    QUIC_DBG_ASSERT(Buffer != NULL || *BufferLength == 0);

    //
    // Validate buffer lengths.
    //
    if (TlsContext->BufferLength + *BufferLength > QUIC_TLS_MAX_MESSAGE_LENGTH) {
        ResultFlags = QUIC_TLS_RESULT_ERROR;
        QuicTraceLogError("[ tls][%p] Error: Attempt to write too much buffer.", TlsContext);
        goto Error;
    }

    TlsContext->State = State;

    if (*BufferLength) {
        QuicTraceLogVerbose("[ tls][%p] Writing %d bytes", TlsContext, *BufferLength);

        //
        // Copy the data pointer into our buffer pointer.
        //
        TlsContext->Buffer = Buffer;

        //
        // Store new buffer length.
        //
        TlsContext->BufferLength = *BufferLength;

        //
        // Indicate that we will return pending, but just immediately invoke
        // the completed callback.
        //
        ResultFlags = QUIC_TLS_RESULT_PENDING;
        TlsContext->ProcessCompleteCallback(TlsContext->Connection);

    } else {

        //
        // We process the inital data inline.
        //
        TlsContext->BufferLength = 0;
        ResultFlags = QuicTlsProcessDataComplete(TlsContext, &ConsumedBytes);
        *BufferLength = ConsumedBytes;
    }

Error:

    return ResultFlags;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
QUIC_TLS_RESULT_FLAGS
QuicTlsProcessDataComplete(
    _In_ QUIC_TLS* TlsContext,
    _Out_ uint32_t * BufferConsumed
    )
{
    QUIC_TLS_RESULT_FLAGS ResultFlags = 0;
    QUIC_TLS_PROCESS_STATE* State = TlsContext->State;

    if (TlsContext->IsServer) {
        QUIC_DBG_ASSERT(TlsContext->Buffer != NULL);
    }

    uint32_t BufferOffset = 0;

    while (!(ResultFlags & QUIC_TLS_RESULT_ERROR)) {

        quic_process_ctx Context = {
            TlsContext->Buffer + BufferOffset,              // input
            TlsContext->BufferLength - BufferOffset,        // input_len
            State->Buffer + State->BufferLength,            // output
            State->BufferAllocLength - State->BufferLength, // output_len
            0
        };

        QuicTraceLogVerbose(
            "[ tls][%p] FFI_mitls_quic_process processing %d input bytes.",
            TlsContext, (uint32_t)Context.input_len);

        //
        // Pass the data to miTLS for processing.
        //
        if (!FFI_mitls_quic_process(TlsContext->miTlsState, &Context)) {
            QuicTraceLogError(
                "[ tls][%p] FFI_mitls_quic_process failed, tls_error %hu, %s.",
                TlsContext, Context.tls_error, Context.tls_error_desc);
            State->AlertCode = Context.tls_error;
            ResultFlags |= QUIC_TLS_RESULT_ERROR;
            break;
        }

        QuicTraceLogVerbose(
            "[ tls][%p] FFI_mitls_quic_process read %u bytes and has %u bytes ready to send.",
            TlsContext, (uint32_t)Context.consumed_bytes, (uint32_t)Context.output_len);

        QUIC_DBG_ASSERT(Context.consumed_bytes <= Context.input_len);
        QUIC_DBG_ASSERT((int64_t)Context.output_len <= State->BufferAllocLength - State->BufferLength);
        QUIC_FRE_ASSERT(Context.to_be_written == 0); // TODO - Support dynamic sizes?

        //
        // Update the buffer offsets based on the output of miTLS.
        //
        BufferOffset += (uint32_t)Context.consumed_bytes;
        State->BufferLength += (uint16_t)Context.output_len;
        State->BufferTotalLength += (uint16_t)Context.output_len;

        if (Context.output_len != 0) {
            ResultFlags |= QUIC_TLS_RESULT_DATA;
        }

        if (Context.flags & QFLAG_COMPLETE && !State->HandshakeComplete) {
            QuicTraceLogVerbose("[ tls][%p] Handshake complete", TlsContext);
            State->HandshakeComplete = TRUE;
            ResultFlags |= QUIC_TLS_RESULT_COMPLETE;

            if (TlsContext->IsServer) {
                QuicTraceLogVerbose("[ tls][%p] Sending new 0-RTT ticket", TlsContext);
                if (!FFI_mitls_quic_send_ticket(TlsContext->miTlsState, NULL, 0)) {
                    QuicTraceLogError("[ tls][%p] Failed to send 0-RTT ticket!", TlsContext);
                }
            }
        }

        if (Context.flags & QFLAG_REJECTED_0RTT) {
            if (TlsContext->IsServer) {
                State->EarlyDataAttempted = TRUE;
            }
            if (State->EarlyDataAttempted) {
                ResultFlags |= QUIC_TLS_RESULT_EARLY_DATA_REJECT;
            }
            QuicTraceLogVerbose("[ tls][%p] Early data rejected", TlsContext);
        }

        BOOLEAN ReadKeyUpdated = Context.cur_reader_key != TlsContext->CurrentReaderKey;
        BOOLEAN WriteKeyUpdated = Context.cur_writer_key != TlsContext->CurrentWriterKey;

        //
        // If there was no state change or output, break out now.
        //
        if (Context.output_len == 0 && !ReadKeyUpdated && !WriteKeyUpdated) {
            break;
        }

        if (!TlsContext->TlsKeyScheduleSet) {
            //
            // Some magic code that determines if we are using the 0-RTT key enum or not.
            //
            if (TlsContext->IsServer) {
                if (ReadKeyUpdated) {
                    //
                    // We know early data is accepted if we get 0-RTT keys.
                    //
                    ResultFlags |= QUIC_TLS_RESULT_EARLY_DATA_ACCEPT;
                    QuicTraceLogVerbose("[ tls][%p] Early data accepted", TlsContext);
                    TlsContext->TlsKeySchedule = 1; // 0-RTT allowed.
                    State->SessionResumed = TRUE;
                    State->EarlyDataAttempted = TRUE;
                    State->EarlyDataAccepted = TRUE;
                } else {
                    TlsContext->TlsKeySchedule = 0;
                    if (!(Context.flags & QFLAG_REJECTED_0RTT)) {
                        QuicTraceLogVerbose("[ tls][%p] Early data not attempted", TlsContext);
                    }
                }
            } else {
                if (WriteKeyUpdated) {
                    QuicTraceLogVerbose("[ tls][%p] Early data attempted", TlsContext);
                    TlsContext->TlsKeySchedule = 1; // 0-RTT allowed.
                    State->EarlyDataAttempted = TRUE;
                } else {
                    TlsContext->TlsKeySchedule = 0;
                }
            }
            QuicTraceLogVerbose("[ tls][%p] Key schedule = %hu", TlsContext, TlsContext->TlsKeySchedule);
            TlsContext->TlsKeyScheduleSet = TRUE;
        }

        if (ReadKeyUpdated) {
            QUIC_PACKET_KEY_TYPE NewKeyType =
                miTlsKeyTypes[TlsContext->TlsKeySchedule][Context.cur_reader_key + 1];
            if (QuicPacketKeyCreate(
                    TlsContext,
                    NewKeyType,
                    Context.cur_reader_key,
                    QUIC_Reader,
                    &State->ReadKeys[NewKeyType])) {
                switch (NewKeyType) {
                case QUIC_PACKET_KEY_0_RTT:
                    QuicTraceLogVerbose("[ tls][%p] 0-RTT read key exported", TlsContext);
                    break;
                case QUIC_PACKET_KEY_HANDSHAKE:
                    QuicTraceLogVerbose("[ tls][%p] Handshake read key exported", TlsContext);
                    break;
                case QUIC_PACKET_KEY_1_RTT:
                    QuicTraceLogVerbose("[ tls][%p] 1-RTT read key exported", TlsContext);
                    if (!TlsContext->IsServer) {
                        if (State->EarlyDataAttempted &&
                            !(Context.flags & QFLAG_REJECTED_0RTT)) {
                            //
                            // We know 0-RTT was accepted by the server once we have
                            // the 1-RTT keys and we haven't received any 0-RTT
                            // rejected event/flag from miTLS.
                            //
                            ResultFlags |= QUIC_TLS_RESULT_EARLY_DATA_ACCEPT;
                            State->SessionResumed = TRUE;
                            State->EarlyDataAccepted = TRUE;
                            QuicTraceLogVerbose("[ tls][%p] Early data accepted", TlsContext);
                        }
                    }
                    break;
                default:
                    QUIC_FRE_ASSERT(FALSE);
                    break;
                }
            }

            ResultFlags |= QUIC_TLS_RESULT_READ_KEY_UPDATED;
            State->ReadKey = NewKeyType;
            TlsContext->CurrentReaderKey = Context.cur_reader_key;

            if (State->ReadKey > State->WriteKey &&
                State->ReadKey != QUIC_PACKET_KEY_0_RTT) {
                //
                // Must always have corresponding write key for every read key.
                //
                ResultFlags |= QUIC_TLS_RESULT_WRITE_KEY_UPDATED;
                State->WriteKey = QUIC_PACKET_KEY_HANDSHAKE;
            }
        }

        if (WriteKeyUpdated) {
            QUIC_PACKET_KEY_TYPE NewKeyType =
                miTlsKeyTypes[TlsContext->TlsKeySchedule][Context.cur_writer_key + 1];
            if (QuicPacketKeyCreate(
                    TlsContext,
                    NewKeyType,
                    Context.cur_writer_key,
                    QUIC_Writer,
                    &State->WriteKeys[NewKeyType])) {
                switch (NewKeyType) {
                case QUIC_PACKET_KEY_0_RTT:
                    QuicTraceLogVerbose("[ tls][%p] 0-RTT write key exported", TlsContext);
                    break;
                case QUIC_PACKET_KEY_HANDSHAKE:
                    QuicTraceLogVerbose("[ tls][%p] Handshake write key exported", TlsContext);
                    break;
                case QUIC_PACKET_KEY_1_RTT:
                    QuicTraceLogVerbose("[ tls][%p] 1-RTT write key exported", TlsContext);
                    break;
                default:
                    QUIC_FRE_ASSERT(FALSE);
                    break;
                }
            }

            switch (NewKeyType) {
            case QUIC_PACKET_KEY_0_RTT:
                break;
            case QUIC_PACKET_KEY_HANDSHAKE:
                State->BufferOffsetHandshake = State->BufferTotalLength;
                QuicTraceLogVerbose("[ tls][%p] Handshake write offset = %u", TlsContext, State->BufferOffsetHandshake);
                break;
            case QUIC_PACKET_KEY_1_RTT:
                State->BufferOffset1Rtt = State->BufferTotalLength;
                QuicTraceLogVerbose("[ tls][%p] 1-RTT write offset = %u", TlsContext, State->BufferOffset1Rtt);
                break;
            default:
                QUIC_FRE_ASSERT(FALSE);
                break;
            }

            ResultFlags |= QUIC_TLS_RESULT_WRITE_KEY_UPDATED;
            TlsContext->CurrentWriterKey = Context.cur_writer_key;

            if (NewKeyType > State->WriteKey &&
                NewKeyType != QUIC_PACKET_KEY_0_RTT) {
                ResultFlags |= QUIC_TLS_RESULT_WRITE_KEY_UPDATED;
                State->WriteKey = NewKeyType;
            }
        }
    }

    //
    // Report how much buffer was drained, and reset the Buffer and Length.
    //
    TlsContext->BufferLength = 0;
    TlsContext->Buffer = NULL;
    *BufferConsumed = BufferOffset;

    QuicTraceLogVerbose("[ tls][%p] Consumed %d bytes", TlsContext, BufferOffset);

    if (TlsContext->TicketReady) {
        ResultFlags |= QUIC_TLS_RESULT_TICKET;
    }

    return ResultFlags;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
void*
MITLS_CALLCONV
QuicTlsOnCertSelect(
    void *Context,
    mitls_version TlsVersion,
    const uint8_t *ServerNameIndication,
    size_t ServerNameIndicationLength,
    const uint8_t *AlpnBuffer,
    size_t AlpnBufferLength,
    const mitls_signature_scheme *SignatureAlgorithms,
    size_t SignatureAlgorithmsLength,
    mitls_signature_scheme *SelectedSignature
    )
{
    UNREFERENCED_PARAMETER(AlpnBuffer);
    UNREFERENCED_PARAMETER(AlpnBufferLength);
    QUIC_TLS* TlsContext = (QUIC_TLS*)Context;
    const QUIC_SEC_CONFIG* SecurityConfig = NULL;

    QUIC_DBG_ASSERT(TlsContext);
    QUIC_DBG_ASSERT(TlsContext->IsServer);

    QuicTraceLogVerbose("[ tls][%p] OnCertSelect", TlsContext);

    //
    // Only allow TLS 1.3.
    //
    if (TlsVersion != TLS_1p3) {
        QuicTraceLogError("[ tls][%p] Unsupported TLS version %hu", TlsContext, TlsVersion);
        goto Error;
    }

    //
    // Validate and save a copy of the SNI.
    //

    if (ServerNameIndicationLength >= QUIC_MAX_SNI_LENGTH) {
        QuicTraceLogError("[ tls][%p] Too long server name!", TlsContext);
        goto Error;
    }

    if (ServerNameIndicationLength != 0) {
        TlsContext->SNI = QUIC_ALLOC_PAGED((uint16_t)(ServerNameIndicationLength + 1));
        if (TlsContext->SNI == NULL) {
            QuicTraceLogWarning("[ tls][%p] Failed to allocate SNI.", TlsContext);
            goto Error;
        }

        memcpy((char*)TlsContext->SNI, ServerNameIndication, ServerNameIndicationLength);
        ((char*)TlsContext->SNI)[ServerNameIndicationLength] = 0;
    } else {
        TlsContext->SNI = NULL;
    }

    //
    // Use the application layer-selected certificate.
    //
    SecurityConfig = TlsContext->SecConfig;
    QUIC_DBG_ASSERT(SecurityConfig != NULL);
    QUIC_DBG_ASSERT(TlsContext->TlsSession != NULL);

    //
    // Select a matching signature algorithm for the certificate.
    //
    QUIC_DBG_ASSERT(SignatureAlgorithmsLength != 0);
    if (!QuicCertSelect(
            SecurityConfig->Certificate,
            SignatureAlgorithms,
            SignatureAlgorithmsLength,
            SelectedSignature)) {
        if (SignatureAlgorithmsLength == 1) {
            QuicTraceLogError("[ tls][%p] No matching signature algorithms, {0x%hx}",
                TlsContext, SignatureAlgorithms[0]);
        } else if (SignatureAlgorithmsLength == 2) {
            QuicTraceLogError("[ tls][%p] No matching signature algorithms, {0x%hx, 0x%hx}",
                TlsContext, SignatureAlgorithms[0], SignatureAlgorithms[1]);
        } else if (SignatureAlgorithmsLength == 3) {
            QuicTraceLogError("[ tls][%p] No matching signature algorithms, {0x%hx, 0x%hx, 0x%hx}",
                TlsContext, SignatureAlgorithms[0], SignatureAlgorithms[1], SignatureAlgorithms[2]);
        } else if (SignatureAlgorithmsLength == 4) {
            QuicTraceLogError("[ tls][%p] No matching signature algorithms, {0x%hx, 0x%hx, 0x%hx, 0x%hx}",
                TlsContext, SignatureAlgorithms[0], SignatureAlgorithms[1], SignatureAlgorithms[2],
                SignatureAlgorithms[3]);
        } else if (SignatureAlgorithmsLength == 5) {
            QuicTraceLogError("[ tls][%p] No matching signature algorithms, {0x%hx, 0x%hx, 0x%hx, 0x%hx, 0x%hx}",
                TlsContext, SignatureAlgorithms[0], SignatureAlgorithms[1], SignatureAlgorithms[2],
                SignatureAlgorithms[3], SignatureAlgorithms[4]);
        } else {
            QuicTraceLogError("[ tls][%p] No matching signature algorithms, {0x%hx, 0x%hx, 0x%hx, 0x%hx, 0x%hx, 0x%hx, ...}",
                TlsContext, SignatureAlgorithms[0], SignatureAlgorithms[1], SignatureAlgorithms[2],
                SignatureAlgorithms[3], SignatureAlgorithms[4], SignatureAlgorithms[5]);
        }
        SecurityConfig = NULL;
        goto Error;
    }

    QuicTraceLogInfo("[ tls][%p] Server certificate selected. SNI: %s; Algorithm: 0x%4.4x",
        TlsContext, TlsContext->SNI, *SelectedSignature);

Error:

    return (void*)SecurityConfig;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
_Success_(return != TLS_nego_abort)
mitls_nego_action
MITLS_CALLCONV
QuicTlsOnNegotiate(
    _In_ void *Context,
    _In_ mitls_version Version,
    _In_reads_(RawExtensionsLength)
        const uint8_t *RawExtensions,
    _In_ size_t RawExtensionsLength,
    _Deref_post_opt_count_(*CustomExtensionsLength)
        mitls_extension **CustomExtensions,
    _Out_ size_t *CustomExtensionsLength,
    _Deref_pre_opt_count_(*CookieLength)
    _Deref_post_opt_count_(*CookieLength)
        uint8_t **Cookie,
    _Inout_ size_t *CookieLength
    )
{
    QUIC_TLS* TlsContext = (QUIC_TLS*)Context;
    QUIC_DBG_ASSERT(TlsContext);

    mitls_nego_action Action = TLS_nego_abort;
    uint8_t *TransportParams;
    size_t TransportParamsLength;

    UNREFERENCED_PARAMETER(Cookie);
    UNREFERENCED_PARAMETER(CookieLength);

    QuicTraceLogVerbose("[ tls][%p] OnNegotiate", TlsContext);

    //
    // Only allow TLS 1.3.
    //
    if (Version != TLS_1p3) {
        QuicTraceLogError("[ tls][%p] Unsupported TLS version %hu", TlsContext, Version);
        goto Exit;
    }

    //
    // Decode and validate peer's QUIC transport parameters.
    //

    if (!FFI_mitls_find_custom_extension(
            TlsContext->IsServer,
            RawExtensions,
            RawExtensionsLength,
            TLS_EXTENSION_TYPE_QUIC_TRANSPORT_PARAMETERS,
            &TransportParams,
            &TransportParamsLength)) {
        QuicTraceLogError("[ tls][%p] Missing QUIC transport parameters.", TlsContext);
        goto Exit;
    }

    if (!TlsContext->ReceiveTPCallback(
            TlsContext->Connection,
            (uint16_t)TransportParamsLength,
            TransportParams)) {
        QuicTraceLogError("[ tls][%p] Failed to process the QUIC transport parameters.", TlsContext);
        goto Exit;
    }

    Action = TLS_nego_accept;

    if (TlsContext->IsServer) {

        //
        // Configure output extensions.
        //
        QUIC_DBG_ASSERT(TlsContext->LocalTP.ext_data != NULL);
        QUIC_DBG_ASSERT(TlsContext->LocalTP.ext_data_len != 0);
        *CustomExtensions = &TlsContext->LocalTP;
        *CustomExtensionsLength = 1;
    }

Exit:

    return Action;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
size_t
MITLS_CALLCONV
QuicTlsOnCertFormat(
    void *Context,
    const void *SecContext,
    uint8_t Buffer[MAX_CHAIN_LEN]
    )
{
    QUIC_TLS* TlsContext = (QUIC_TLS*)Context;
    QUIC_DBG_ASSERT(TlsContext);
    QUIC_SEC_CONFIG* SecurityConfig = (QUIC_SEC_CONFIG*)SecContext;
    QUIC_DBG_ASSERT(SecurityConfig);

    QuicTraceLogVerbose("[ tls][%p] OnCertFormat", TlsContext);

    QUIC_DBG_ASSERT(SecurityConfig->FormatLength <= MAX_CHAIN_LEN);
    if (SecurityConfig->FormatLength > MAX_CHAIN_LEN) {
        return 0;
    }

    memcpy(Buffer, SecurityConfig->FormatBuffer, SecurityConfig->FormatLength);
    return SecurityConfig->FormatLength;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
size_t
MITLS_CALLCONV
QuicTlsOnCertSign(
    void *Context,
    const void *SecContext,
    const mitls_signature_scheme SignatureAlgorithm,
    const uint8_t *CertListToBeSigned,
    size_t CertListToBeSignedLength,
    uint8_t *Signature
    )
{
    QUIC_TLS* TlsContext = (QUIC_TLS*)Context;
    QUIC_DBG_ASSERT(TlsContext);
    QUIC_SEC_CONFIG* SecurityConfig = (QUIC_SEC_CONFIG*)SecContext;
    QUIC_DBG_ASSERT(SecurityConfig);

    QuicTraceLogVerbose("[ tls][%p] OnCertSign", TlsContext);

    size_t SignatureLength = MAX_SIGNATURE_LEN;

    if (SecurityConfig->PrivateKey == NULL) {
        *Signature = 0;
        SignatureLength = 1;
    } else if (!QuicCertSign(
            SecurityConfig->PrivateKey,
            SignatureAlgorithm,
            CertListToBeSigned,
            CertListToBeSignedLength,
            Signature,
            &SignatureLength)) {
        SignatureLength = 0;
    }

    return SignatureLength;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
int
MITLS_CALLCONV
QuicTlsOnCertVerify(
    void *Context,
    const uint8_t* ChainBuffer,
    size_t ChainBufferLength,
    const mitls_signature_scheme SignatureAlgorithm,
    const uint8_t* CertListToBeSigned,
    size_t CertListToBeSignedLength,
    const uint8_t *Signature,
    size_t SignatureLength
    )
{
    QUIC_TLS* TlsContext = (QUIC_TLS*)Context;
    QUIC_DBG_ASSERT(TlsContext);

    QuicTraceLogVerbose("[ tls][%p] OnCertVerify", TlsContext);

    int Result = 0;
    QUIC_CERT* Certificate = NULL;

    if (TlsContext->SecConfig->Flags & QUIC_CERTIFICATE_FLAG_DISABLE_CERT_VALIDATION) {
        QuicTraceLogWarning("[ tls][%p] Certificate validation disabled!", TlsContext);
        Result = 1;
        goto Error;
    }

    Certificate =
        QuicCertParseChain(
            ChainBufferLength,
            ChainBuffer);
    if (Certificate == NULL) {
        QuicTraceLogError("[ tls][%p] failed to parse certificate chain.", TlsContext);
        goto Error;
    }

    if (!QuicCertValidateChain(
            Certificate,
            TlsContext->SNI,
            TlsContext->SecConfig->Flags)) {
        QuicTraceLogError("[ tls][%p] Cert chain validation failed.", TlsContext);
        Result = 0;
        goto Error;
    }

    Result =
        QuicCertVerify(
            Certificate,
            SignatureAlgorithm,
            CertListToBeSigned,
            CertListToBeSignedLength,
            Signature,
            SignatureLength);

Error:

    if (Certificate != NULL) {
        QuicCertFree(Certificate);
    }

    return Result;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
void
MITLS_CALLCONV
QuicTlsOnTicketReady(
    void *Context,
    const char *ServerNameIndication,
    const mitls_ticket *Ticket
    )
{
    QUIC_TLS* TlsContext = (QUIC_TLS*)Context;
    QUIC_DBG_ASSERT(TlsContext);

    QuicTraceLogVerbose("[ tls][%p] Received new ticket. ticket_len:%d session_len:%d for %s",
        TlsContext, (uint32_t)Ticket->ticket_len, (uint32_t)Ticket->session_len, ServerNameIndication);

    //
    // Release any previous ticket.
    //
    if (TlsContext->Ticket != NULL) {
        QuicTlsTicketRelease(TlsContext->Ticket);
    }

    //
    // Add new ticket to TlsSession ticket store.
    //
    TlsContext->Ticket =
        QuicTlsSessionCreateTicket(
            TlsContext->TlsSession,
            ServerNameIndication,
            Ticket);

    if (TlsContext->Ticket != NULL) {
        TlsContext->TicketReady = TRUE;
    }
}

_IRQL_requires_max_(PASSIVE_LEVEL)
QUIC_STATUS
QuicTlsReadTicket(
    _In_ QUIC_TLS* TlsContext,
    _Inout_ uint32_t* BufferLength,
    _Out_writes_bytes_opt_(*BufferLength)
        uint8_t* Buffer
    )
{
    QUIC_STATUS Status;

    if (!TlsContext->TicketReady) {
        Status = QUIC_STATUS_INVALID_STATE;
        goto Exit;
    }

    uint32_t TicketBufferLength =
        sizeof(QUIC_TLS_TICKET) +
        TlsContext->Ticket->ServerNameLength +
        TlsContext->Ticket->TicketLength +
        TlsContext->Ticket->SessionLength;

    if (*BufferLength < TicketBufferLength) {
        *BufferLength = TicketBufferLength;
        Status = QUIC_STATUS_BUFFER_TOO_SMALL;
        goto Exit;
    }

    if (Buffer == NULL) {
        Status = QUIC_STATUS_INVALID_PARAMETER;
        goto Exit;
    }

    QuicTraceLogVerbose("[ tls][%p] Ticket (%u bytes) read.", TlsContext, TicketBufferLength);

    QuicCopyMemory(
        Buffer,
        TlsContext->Ticket,
        TicketBufferLength);
    *BufferLength = TicketBufferLength;

    Status = QUIC_STATUS_SUCCESS;

Exit:

    return Status;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
QUIC_STATUS
QuicTlsParamSet(
    _In_ QUIC_TLS* TlsContext,
    _In_ uint32_t Param,
    _In_ uint32_t BufferLength,
    _In_reads_bytes_(BufferLength)
        const void* Buffer
    )
{
    QUIC_STATUS Status;

    UNREFERENCED_PARAMETER(TlsContext);
    UNREFERENCED_PARAMETER(BufferLength);
    UNREFERENCED_PARAMETER(Buffer);

    switch (Param) {
    default:
        Status = QUIC_STATUS_INVALID_PARAMETER;
        break;
    }

    return Status;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
QUIC_STATUS
QuicTlsParamGet(
    _In_ QUIC_TLS* TlsContext,
    _In_ uint32_t Param,
    _Inout_ uint32_t* BufferLength,
    _Out_writes_bytes_opt_(*BufferLength)
        void* Buffer
    )
{
    QUIC_STATUS Status;

    UNREFERENCED_PARAMETER(TlsContext);
    UNREFERENCED_PARAMETER(BufferLength);
    UNREFERENCED_PARAMETER(Buffer);

    switch (Param) {
    default:
        Status = QUIC_STATUS_INVALID_PARAMETER;
        break;
    }

    return Status;
}

//
// Crypto / Key Functionality
//

typedef struct QUIC_KEY {
    QUIC_AEAD_TYPE Aead;
    uint8_t Key[32];
} QUIC_KEY;

typedef struct QUIC_HASH {
    QUIC_HASH_TYPE Type;
    uint32_t SaltLength;
    uint8_t Salt[0];
} QUIC_HASH;

typedef struct QUIC_HP_KEY {
    QUIC_AEAD_TYPE Aead;
    union {
        uint8_t case_chacha20[32];
        EverCrypt_aes128_key case_aes128;
        EverCrypt_aes256_key case_aes256;
    };
} QUIC_HP_KEY;

Spec_Hash_Definitions_hash_alg
HashTypeToEverCrypt(
    QUIC_HASH_TYPE Type
) {
    return
        (Spec_Hash_Definitions_hash_alg)
            (Spec_Hash_Definitions_SHA2_256 + Type);
}

#ifdef QUIC_TEST_MODE
void
QuicTlsLogSecret(
    _In_z_ const char* const Prefix,
    _In_reads_(Length)
        const uint8_t* const Secret,
    _In_ uint32_t Length
    )
{
    #define HEX_TO_CHAR(x) ((x) > 9 ? ('a' + ((x) - 10)) : '0' + (x))
    char SecretStr[256] = {0};
    for (uint8_t i = 0; i < Length; i++) {
        SecretStr[i*2]     = HEX_TO_CHAR(Secret[i] >> 4);
        SecretStr[i*2 + 1] = HEX_TO_CHAR(Secret[i] & 0xf);
    }
    QuicTraceLogVerbose("[ tls] %s[%u]: %s", Prefix, Length, SecretStr);
}
#else
#define QuicTlsLogSecret(Prefix, Secret, Length) UNREFERENCED_PARAMETER(Prefix)
#endif

_IRQL_requires_max_(PASSIVE_LEVEL)
void
QuicHkdfFormatLabel(
    _In_z_ const char* const Label,
    _In_ uint16_t HashLength,
    _Out_writes_all_(5 + QUIC_HKDF_PREFIX_LEN + strlen(Label))
        uint8_t* const Data,
    _Inout_ uint32_t* const DataLength
    )
{
    QUIC_DBG_ASSERT(strlen(Label) <= UINT8_MAX - QUIC_HKDF_PREFIX_LEN);
    uint8_t LabelLength = (uint8_t)strlen(Label);

    Data[0] = HashLength >> 8;
    Data[1] = HashLength & 0xff;
    Data[2] = QUIC_HKDF_PREFIX_LEN + LabelLength;
    memcpy(Data + 3, QUIC_HKDF_PREFIX, QUIC_HKDF_PREFIX_LEN);
    memcpy(Data + 3 + QUIC_HKDF_PREFIX_LEN, Label, LabelLength);
    Data[3 + QUIC_HKDF_PREFIX_LEN + LabelLength] = 0;
    *DataLength = 3 + QUIC_HKDF_PREFIX_LEN + LabelLength + 1;

    Data[*DataLength] = 0x1;
    *DataLength += 1;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
QUIC_STATUS
QuicHkdfExpandLabel(
    _In_ QUIC_HASH* Hash,
    _In_z_ const char* const Label,
    _In_ uint16_t KeyLength,
    _In_ uint32_t OutputLength, // Writes QuicHashLength(HashType) bytes.
    _Out_writes_all_(OutputLength)
        uint8_t* const Output
    )
{
    uint8_t LabelBuffer[64];
    uint32_t LabelLength = sizeof(LabelBuffer);

    _Analysis_assume_(strlen(Label) <= 23);
    QuicHkdfFormatLabel(Label, KeyLength, LabelBuffer, &LabelLength);

    return
        QuicHashCompute(
            Hash,
            LabelBuffer,
            LabelLength,
            OutputLength,
            Output);
}

_IRQL_requires_max_(PASSIVE_LEVEL)
QUIC_STATUS
QuicTlsDeriveInitialSecrets(
    _In_reads_(QUIC_VERSION_SALT_LENGTH)
        const uint8_t* const Salt,
    _In_reads_(CIDLength)
        const uint8_t* const CID,
    _In_ uint8_t CIDLength,
    _Out_ QUIC_SECRET *ClientInitial,
    _Out_ QUIC_SECRET *ServerInitial
    )
{
    QUIC_STATUS Status;
    QUIC_HASH* InitialHash = NULL;
    QUIC_HASH* DerivedHash = NULL;
    uint8_t InitialSecret[QUIC_HASH_SHA256_SIZE];

    QuicTlsLogSecret("init cid", CID, CIDLength);

    Status =
        QuicHashCreate(
            QUIC_HASH_SHA256,
            Salt,
            QUIC_VERSION_SALT_LENGTH,
            &InitialHash);
    if (QUIC_FAILED(Status)) {
        goto Error;
    }

    //
    // Extract secret for client and server secret expansion.
    //
    Status =
        QuicHashCompute(
            InitialHash,
            CID,
            CIDLength,
            sizeof(InitialSecret),
            InitialSecret);
    if (QUIC_FAILED(Status)) {
        goto Error;
    }

    QuicTlsLogSecret("init secret", InitialSecret, sizeof(InitialSecret));

    //
    // Create hash for client and server secret expansion.
    //
    Status =
        QuicHashCreate(
            QUIC_HASH_SHA256,
            InitialSecret,
            sizeof(InitialSecret),
            &DerivedHash);
    if (QUIC_FAILED(Status)) {
        goto Error;
    }

    //
    // Expand client secret.
    //
    ClientInitial->Hash = QUIC_HASH_SHA256;
    ClientInitial->Aead = QUIC_AEAD_AES_128_GCM;
    Status =
        QuicHkdfExpandLabel(
            DerivedHash,
            "client in",
            sizeof(InitialSecret),
            QUIC_HASH_SHA256_SIZE,
            ClientInitial->Secret);
    if (QUIC_FAILED(Status)) {
        goto Error;
    }

    //
    // Expand server secret.
    //
    ServerInitial->Hash = QUIC_HASH_SHA256;
    ServerInitial->Aead = QUIC_AEAD_AES_128_GCM;
    Status =
        QuicHkdfExpandLabel(
            DerivedHash,
            "server in",
            sizeof(InitialSecret),
            QUIC_HASH_SHA256_SIZE,
            ServerInitial->Secret);
    if (QUIC_FAILED(Status)) {
        goto Error;
    }

Error:

    QuicHashFree(InitialHash);
    QuicHashFree(DerivedHash);

    RtlSecureZeroMemory(InitialSecret, sizeof(InitialSecret));

    return Status;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
QUIC_STATUS
QuicPacketKeyDerive(
    _In_ QUIC_PACKET_KEY_TYPE KeyType,
    _In_ const QUIC_SECRET* const Secret,
    _In_z_ const char* const SecretName,
    _In_ BOOLEAN CreateHpKey,
    _Out_ QUIC_PACKET_KEY **NewKey
    )
{
    const uint16_t SecretLength = QuicHashLength(Secret->Hash);
    const uint16_t KeyLength = QuicKeyLength(Secret->Aead);

    QUIC_DBG_ASSERT(SecretLength >= KeyLength);
    QUIC_DBG_ASSERT(SecretLength >= QUIC_IV_LENGTH);
    QUIC_DBG_ASSERT(SecretLength <= QUIC_HASH_MAX_SIZE);

    QuicTlsLogSecret(SecretName, Secret->Secret, SecretLength);

    const uint16_t PacketKeyLength =
        sizeof(QUIC_PACKET_KEY) +
        (KeyType == QUIC_PACKET_KEY_1_RTT ? sizeof(QUIC_SECRET) : 0);
    QUIC_PACKET_KEY *Key = QUIC_ALLOC_NONPAGED(PacketKeyLength);
    if (Key == NULL) {
        QuicTraceLogWarning("[ tls] Failed to allocate packet key.");
        return QUIC_STATUS_OUT_OF_MEMORY;
    }
    QuicZeroMemory(Key, sizeof(QUIC_PACKET_KEY));
    Key->Type = KeyType;

    QUIC_HASH* Hash = NULL;
    uint8_t Temp[QUIC_HASH_MAX_SIZE];

    QUIC_STATUS Status =
        QuicHashCreate(
            Secret->Hash,
            Secret->Secret,
            SecretLength,
            &Hash);
    if (QUIC_FAILED(Status)) {
        goto Error;
    }

    Status =
        QuicHkdfExpandLabel(
            Hash,
            "quic iv",
            QUIC_IV_LENGTH,
            SecretLength,
            Temp);
    if (QUIC_FAILED(Status)) {
        goto Error;
    }

    memcpy(Key->Iv, Temp, QUIC_IV_LENGTH);
    QuicTlsLogSecret("static iv", Key->Iv, QUIC_IV_LENGTH);

    Status =
        QuicHkdfExpandLabel(
            Hash,
            "quic key",
            KeyLength,
            SecretLength,
            Temp);
    if (QUIC_FAILED(Status)) {
        goto Error;
    }

    QuicTlsLogSecret("key", Temp, KeyLength);

    Status =
        QuicKeyCreate(
            Secret->Aead,
            Temp,
            &Key->PacketKey);
    if (QUIC_FAILED(Status)) {
        goto Error;
    }

    if (CreateHpKey) {
        Status =
            QuicHkdfExpandLabel(
                Hash,
                "quic hp",
                KeyLength,
                SecretLength,
                Temp);
        if (QUIC_FAILED(Status)) {
            goto Error;
        }

        QuicTlsLogSecret("hp", Temp, KeyLength);

        Status =
            QuicHpKeyCreate(
                Secret->Aead,
                Temp,
                &Key->HeaderKey);
        if (QUIC_FAILED(Status)) {
            goto Error;
        }
    }

    if (KeyType == QUIC_PACKET_KEY_1_RTT) {
        QuicCopyMemory(Key->TrafficSecret, Secret, sizeof(QUIC_SECRET));
    }

    *NewKey = Key;
    Key = NULL;

Error:

    QuicPacketKeyFree(Key);
    QuicHashFree(Hash);

    RtlSecureZeroMemory(Temp, sizeof(Temp));

    return Status;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
_When_(NewReadKey != NULL, _At_(*NewReadKey, __drv_allocatesMem(Mem)))
_When_(NewWriteKey != NULL, _At_(*NewWriteKey, __drv_allocatesMem(Mem)))
QUIC_STATUS
QuicPacketKeyCreateInitial(
    _In_ BOOLEAN IsServer,
    _In_reads_(QUIC_VERSION_SALT_LENGTH)
        const uint8_t* const Salt,  // Version Specific
    _In_ uint8_t CIDLength,
    _In_reads_(CIDLength)
        const uint8_t* const CID,
    _Out_opt_ QUIC_PACKET_KEY** NewReadKey,
    _Out_opt_ QUIC_PACKET_KEY** NewWriteKey
    )
{
    QUIC_STATUS Status;
    QUIC_SECRET ClientInitial, ServerInitial;
    QUIC_PACKET_KEY* ReadKey = NULL, *WriteKey = NULL;

    Status =
        QuicTlsDeriveInitialSecrets(
            Salt,
            CID,
            CIDLength,
            &ClientInitial,
            &ServerInitial);
    if (QUIC_FAILED(Status)) {
        goto Error;
    }

    if (NewWriteKey != NULL) {
        Status =
            QuicPacketKeyDerive(
                QUIC_PACKET_KEY_INITIAL,
                IsServer ? &ServerInitial : &ClientInitial,
                IsServer ? "srv secret" : "cli secret",
                TRUE,
                &WriteKey);
        if (QUIC_FAILED(Status)) {
            goto Error;
        }
    }

    if (NewReadKey != NULL) {
        Status =
            QuicPacketKeyDerive(
                QUIC_PACKET_KEY_INITIAL,
                IsServer ? &ClientInitial : &ServerInitial,
                IsServer ? "cli secret" : "srv secret",
                TRUE,
                &ReadKey);
        if (QUIC_FAILED(Status)) {
            goto Error;
        }
    }

    if (NewWriteKey != NULL) {
        *NewWriteKey = WriteKey;
        WriteKey = NULL;
    }

    if (NewReadKey != NULL) {
        *NewReadKey = ReadKey;
        ReadKey = NULL;
    }

Error:

    QuicPacketKeyFree(ReadKey);
    QuicPacketKeyFree(WriteKey);

    RtlSecureZeroMemory(ClientInitial.Secret, sizeof(ClientInitial.Secret));
    RtlSecureZeroMemory(ServerInitial.Secret, sizeof(ServerInitial.Secret));

    return Status;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
_Success_(return != FALSE)
BOOLEAN
QuicPacketKeyCreate(
    _In_ QUIC_TLS* TlsContext,
    _In_ QUIC_PACKET_KEY_TYPE KeyType,
    _In_ int Epoch,
    _In_ quic_direction rw,
    _Out_ QUIC_PACKET_KEY** NewKey
    )
{
    int Result;
    quic_raw_key RecordKey;
    QUIC_PACKET_KEY *Key = NULL;

    Result =
        FFI_mitls_quic_get_record_key(
            TlsContext->miTlsState,
            &RecordKey,
            Epoch,
            rw);
    if (Result == FALSE) {
        QuicTraceLogError("[ tls][%p] FFI_mitls_quic_get_record_key failed.", TlsContext);
        goto Error;
    }

    const uint16_t PacketKeyLength =
        sizeof(QUIC_PACKET_KEY) +
        (KeyType == QUIC_PACKET_KEY_1_RTT ? sizeof(QUIC_SECRET) : 0);
    Key = QUIC_ALLOC_NONPAGED(PacketKeyLength);
    if (Key == NULL) {
        QuicTraceLogWarning("[ tls][%p] Failed to allocate packet key.", TlsContext);
        Result = FALSE;
        goto Error;
    }
    QuicZeroMemory(Key, sizeof(QUIC_PACKET_KEY));
    Key->Type = KeyType;

    if (QUIC_FAILED(
        QuicKeyCreate(
            (QUIC_AEAD_TYPE)RecordKey.alg,
            RecordKey.aead_key,
            &Key->PacketKey))) {
        Result = FALSE;
        goto Error;
    }

    if (QUIC_FAILED(
        QuicHpKeyCreate(
            (QUIC_AEAD_TYPE)RecordKey.alg,
            RecordKey.pne_key,
            &Key->HeaderKey))) {
        Result = FALSE;
        goto Error;
    }

    memcpy(Key->Iv, RecordKey.aead_iv, QUIC_IV_LENGTH);

    if (KeyType == QUIC_PACKET_KEY_1_RTT) {
        quic_secret ClientReadSecret, ServerReadSecret;
        Result =
            FFI_mitls_quic_get_record_secrets(
                TlsContext->miTlsState,
                &ClientReadSecret,
                &ServerReadSecret);
        if (Result == FALSE) {
            QuicTraceLogError("[ tls][%p] FFI_mitls_quic_get_record_secrets failed.", TlsContext);
            goto Error;
        }
        quic_secret* CopySecret;
        if (TlsContext->IsServer) {
            CopySecret = (rw == QUIC_Reader) ? &ClientReadSecret : &ServerReadSecret;
        } else {
            CopySecret = (rw == QUIC_Reader) ? &ServerReadSecret : &ClientReadSecret;
        }

        switch (CopySecret->hash) {
        case TLS_hash_SHA256:
            Key->TrafficSecret->Hash = QUIC_HASH_SHA256;
            break;
        case TLS_hash_SHA384:
            Key->TrafficSecret->Hash = QUIC_HASH_SHA384;
            break;
        case TLS_hash_SHA512:
            Key->TrafficSecret->Hash = QUIC_HASH_SHA512;
            break;
        default:
            QuicTraceLogError("[ tls][%p] Unsupported hash type.", TlsContext);
            Result = FALSE;
            goto Error;
        }
        Key->TrafficSecret->Aead = (QUIC_AEAD_TYPE)CopySecret->ae;
        QuicCopyMemory(Key->TrafficSecret->Secret, CopySecret->secret, QUIC_HASH_MAX_SIZE);
    }

    *NewKey = Key;
    Key = NULL;

Error:

    QuicPacketKeyFree(Key);

    return Result != FALSE;
}

_IRQL_requires_max_(DISPATCH_LEVEL)
void
QuicPacketKeyFree(
    _In_opt_ __drv_freesMem(Mem) QUIC_PACKET_KEY* Key
    )
{
    if (Key != NULL) {
        QuicKeyFree(Key->PacketKey);
        QuicHpKeyFree(Key->HeaderKey);
        if (Key->Type >= QUIC_PACKET_KEY_1_RTT) {
            RtlSecureZeroMemory(Key->TrafficSecret, sizeof(QUIC_SECRET));
        }
        QUIC_FREE(Key);
    }
}

_IRQL_requires_max_(PASSIVE_LEVEL)
_At_(*NewKey, __drv_allocatesMem(Mem))
QUIC_STATUS
QuicPacketKeyUpdate(
    _In_ QUIC_PACKET_KEY* OldKey,
    _Out_ QUIC_PACKET_KEY** NewKey
    )
{
    if (OldKey->Type != QUIC_PACKET_KEY_1_RTT) {
        return QUIC_STATUS_INVALID_STATE;
    }

    QUIC_HASH* Hash = NULL;
    QUIC_SECRET NewTrafficSecret;
    const uint16_t SecretLength = QuicHashLength(OldKey->TrafficSecret->Hash);

    QUIC_STATUS Status =
        QuicHashCreate(
            OldKey->TrafficSecret->Hash,
            OldKey->TrafficSecret->Secret,
            SecretLength,
            &Hash);
    if (QUIC_FAILED(Status)) {
        goto Error;
    }

    Status =
        QuicHkdfExpandLabel(
            Hash,
            "quic ku",
            SecretLength,
            SecretLength,
            NewTrafficSecret.Secret);
    if (QUIC_FAILED(Status)) {
        goto Error;
    }

    NewTrafficSecret.Hash = OldKey->TrafficSecret->Hash;
    NewTrafficSecret.Aead = OldKey->TrafficSecret->Aead;

    Status =
        QuicPacketKeyDerive(
            QUIC_PACKET_KEY_1_RTT,
            &NewTrafficSecret,
            "update traffic secret",
            FALSE,
            NewKey);

    RtlSecureZeroMemory(&NewTrafficSecret, sizeof(QUIC_SECRET));
    RtlSecureZeroMemory(OldKey->TrafficSecret, sizeof(QUIC_SECRET));

Error:

    QuicHashFree(Hash);

    return Status;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
QUIC_STATUS
QuicKeyCreate(
    _In_ QUIC_AEAD_TYPE AeadType,
    _When_(AeadType == QUIC_AEAD_AES_128_GCM, _In_reads_(16))
    _When_(AeadType == QUIC_AEAD_AES_256_GCM, _In_reads_(32))
    _When_(AeadType == QUIC_AEAD_AES_384_GCM, _In_reads_(48))
    _When_(AeadType == QUIC_AEAD_CHACHA20_POLY1305, _In_reads_(32))
        const uint8_t* const RawKey,
    _Out_ QUIC_KEY** NewKey
    )
{
    uint8_t KeyLength;
    switch (AeadType) {
    case QUIC_AEAD_AES_128_GCM:
        KeyLength = 16;
        break;
    case QUIC_AEAD_AES_256_GCM:
    case QUIC_AEAD_CHACHA20_POLY1305:
        KeyLength = 32;
        break;
    default:
        return QUIC_STATUS_NOT_SUPPORTED;
    }

    QUIC_KEY* Key = QUIC_ALLOC_NONPAGED(sizeof(QUIC_KEY));
    if (Key == NULL) {
        QuicTraceLogWarning("[ tls] Failed to allocate key.");
        return QUIC_STATUS_OUT_OF_MEMORY;
    }

    Key->Aead = AeadType;
    memcpy(Key->Key, RawKey, KeyLength);

    *NewKey = Key;

    return QUIC_STATUS_SUCCESS;
}

_IRQL_requires_max_(DISPATCH_LEVEL)
void
QuicKeyFree(
    _In_opt_ QUIC_KEY* Key
    )
{
    if (Key) {
        QUIC_FREE(Key);
    }
}

_IRQL_requires_max_(DISPATCH_LEVEL)
QUIC_STATUS
#pragma prefast(suppress: __WARNING_6262, "miTLS won't be shipped in product.")
QuicEncrypt(
    _In_ QUIC_KEY* Key,
    _In_reads_bytes_(QUIC_IV_LENGTH)
        const uint8_t* const Iv,
    _In_ uint16_t AuthDataLength,
    _In_reads_bytes_opt_(AuthDataLength)
        const uint8_t* const AuthData,
    _In_ uint16_t BufferLength,
    _Out_writes_bytes_(BufferLength)
        uint8_t* Buffer
    )
{
    QUIC_DBG_ASSERT(QUIC_ENCRYPTION_OVERHEAD <= BufferLength);
    uint16_t PlainTextLength = BufferLength - QUIC_ENCRYPTION_OVERHEAD;

    uint8_t Temp[QUIC_MAX_MTU];
    QUIC_FRE_ASSERT(BufferLength <= sizeof(Temp));

    if (Key->Aead == QUIC_AEAD_AES_128_GCM) {
        EverCrypt_aes128_gcm_encrypt(Key->Key, (uint8_t*)Iv, (uint8_t*)AuthData, AuthDataLength, Buffer, PlainTextLength, Temp, Temp+PlainTextLength);
    } else if (Key->Aead == QUIC_AEAD_AES_256_GCM) {
        EverCrypt_aes256_gcm_encrypt(Key->Key, (uint8_t*)Iv, (uint8_t*)AuthData, AuthDataLength, Buffer, PlainTextLength, Temp, Temp+PlainTextLength);
    } else if (Key->Aead == QUIC_AEAD_CHACHA20_POLY1305) {
        EverCrypt_Chacha20Poly1305_aead_encrypt(Key->Key, (uint8_t*)Iv, AuthDataLength, (uint8_t*)AuthData, PlainTextLength, Buffer, Temp, Temp+PlainTextLength);
    } else {
        QUIC_FRE_ASSERT(FALSE);
        return QUIC_STATUS_NOT_SUPPORTED;
    }

    memcpy(Buffer, Temp, BufferLength);

    return QUIC_STATUS_SUCCESS;
}

_IRQL_requires_max_(DISPATCH_LEVEL)
QUIC_STATUS
#pragma prefast(suppress: __WARNING_6262, "miTLS won't be shipped in product.")
QuicDecrypt(
    _In_ QUIC_KEY* Key,
    _In_reads_bytes_(QUIC_IV_LENGTH)
        const uint8_t* const Iv,
    _In_ uint16_t AuthDataLength,
    _In_reads_bytes_opt_(AuthDataLength)
        const uint8_t* const AuthData,
    _In_ uint16_t BufferLength,
    _Inout_updates_bytes_(BufferLength)
        uint8_t* Buffer
    )
{
    QUIC_DBG_ASSERT(QUIC_ENCRYPTION_OVERHEAD <= BufferLength);
    uint16_t PlainTextLength = BufferLength - QUIC_ENCRYPTION_OVERHEAD;

    uint8_t Temp[QUIC_MAX_MTU];
    QUIC_FRE_ASSERT(BufferLength <= sizeof(Temp));

    int r = 0;
    if (Key->Aead == QUIC_AEAD_AES_128_GCM) {
        r = EverCrypt_aes128_gcm_decrypt(Key->Key, (uint8_t*)Iv, (uint8_t*)AuthData, AuthDataLength, Temp, PlainTextLength, Buffer, Buffer+PlainTextLength);
    } else if (Key->Aead == QUIC_AEAD_AES_256_GCM) {
        r = EverCrypt_aes256_gcm_decrypt(Key->Key, (uint8_t*)Iv, (uint8_t*)AuthData, AuthDataLength, Temp, PlainTextLength, Buffer, Buffer+PlainTextLength);
    } else if (Key->Aead == QUIC_AEAD_CHACHA20_POLY1305) {
        r = EverCrypt_Chacha20Poly1305_aead_decrypt(Key->Key, (uint8_t*)Iv, AuthDataLength, (uint8_t*)AuthData, PlainTextLength, Temp, Buffer, Buffer+PlainTextLength);
    } else {
        QUIC_FRE_ASSERT(FALSE);
        return QUIC_STATUS_NOT_SUPPORTED;
    }

    if (r <= 0) {
        return QUIC_STATUS_INVALID_PARAMETER;
    }

    memcpy(Buffer, Temp, PlainTextLength);

    return QUIC_STATUS_SUCCESS;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
QUIC_STATUS
QuicHpKeyCreate(
    _In_ QUIC_AEAD_TYPE AeadType,
    _When_(AeadType == QUIC_AEAD_AES_128_GCM, _In_reads_(16))
    _When_(AeadType == QUIC_AEAD_AES_256_GCM, _In_reads_(32))
    _When_(AeadType == QUIC_AEAD_CHACHA20_POLY1305, _In_reads_(32))
        const uint8_t* const RawKey,
    _Out_ QUIC_HP_KEY** NewKey
    )
{
    uint8_t KeyLength;
    switch (AeadType) {
    case QUIC_AEAD_AES_128_GCM:
        KeyLength = 16;
        break;
    case QUIC_AEAD_AES_256_GCM:
    case QUIC_AEAD_CHACHA20_POLY1305:
        KeyLength = 32;
        break;
    default:
        return QUIC_STATUS_NOT_SUPPORTED;
    }

    QUIC_HP_KEY* Key = QUIC_ALLOC_NONPAGED(sizeof(QUIC_KEY));
    if (Key == NULL) {
        QuicTraceLogWarning("[ tls] Failed to allocate key.");
        return QUIC_STATUS_OUT_OF_MEMORY;
    }

    Key->Aead = AeadType;
    if (AeadType == QUIC_AEAD_AES_128_GCM) {
        Key->case_aes128 = EverCrypt_aes128_create((uint8_t*)RawKey);
    } else if (AeadType == QUIC_AEAD_AES_256_GCM) {
        Key->case_aes256 = EverCrypt_aes256_create((uint8_t*)RawKey);
    } else if (AeadType == QUIC_AEAD_CHACHA20_POLY1305) {
        memcpy(Key->case_chacha20, RawKey, 32);
    }

    *NewKey = Key;

    return QUIC_STATUS_SUCCESS;
}

_IRQL_requires_max_(DISPATCH_LEVEL)
void
QuicHpKeyFree(
    _In_opt_ QUIC_HP_KEY* Key
    )
{
    if (Key) {
        if (Key->Aead == QUIC_AEAD_AES_128_GCM) {
            EverCrypt_aes128_free(Key->case_aes128);
        } else if (Key->Aead == QUIC_AEAD_AES_256_GCM) {
            EverCrypt_aes256_free(Key->case_aes256);
        }
        QUIC_FREE(Key);
    }
}

_IRQL_requires_max_(DISPATCH_LEVEL)
QUIC_STATUS
QuicHpComputeMask(
    _In_ QUIC_HP_KEY* Key,
    _In_ uint8_t BatchSize,
    _In_reads_bytes_(QUIC_HP_SAMPLE_LENGTH * BatchSize)
        const uint8_t* const _Cipher,
    _Out_writes_bytes_(QUIC_HP_SAMPLE_LENGTH * BatchSize)
        uint8_t* Mask
    )
{
    uint8_t* Cipher = (uint8_t*)_Cipher;
    for (uint8_t i = 0; i < BatchSize; ++i) {
        if (Key->Aead == QUIC_AEAD_AES_128_GCM) {
            EverCrypt_aes128_compute(Key->case_aes128, Cipher, Mask);
        } else if (Key->Aead == QUIC_AEAD_AES_256_GCM) {
            EverCrypt_aes256_compute(Key->case_aes256, Cipher, Mask);
        } else if (Key->Aead == QUIC_AEAD_CHACHA20_POLY1305) {
            uint8_t zero[5] = {0};
            uint32_t ctr = Cipher[0] + (Cipher[1] << 8) + (Cipher[2] << 16) + (Cipher[3] << 24);
            EverCrypt_Cipher_chacha20(5, Mask, Cipher+4, (uint8_t*)Key->case_chacha20, zero, ctr);
        } else {
            return QUIC_STATUS_NOT_SUPPORTED;
        }
        Cipher += 16;
        Mask += 16;
    }
    return QUIC_STATUS_SUCCESS;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
QUIC_STATUS
QuicHashCreate(
    _In_ QUIC_HASH_TYPE HashType,
    _In_reads_(SaltLength)
        const uint8_t* const Salt,
    _In_ uint32_t SaltLength,
    _Out_ QUIC_HASH** NewHash
    )
{
    switch (HashType) {
    case QUIC_HASH_SHA256:
    case QUIC_HASH_SHA384:
    case QUIC_HASH_SHA512:
        break;
    default:
        return QUIC_STATUS_NOT_SUPPORTED;
    }

    QUIC_HASH* Hash = QUIC_ALLOC_NONPAGED(sizeof(QUIC_HASH) + SaltLength);
    if (Hash == NULL) {
        QuicTraceLogWarning("[ tls] Failed to allocate hash.");
        return QUIC_STATUS_OUT_OF_MEMORY;
    }

    Hash->Type = HashType;
    Hash->SaltLength = SaltLength;
    memcpy(Hash->Salt, Salt, SaltLength);

    *NewHash = Hash;

    return QUIC_STATUS_SUCCESS;
}

_IRQL_requires_max_(DISPATCH_LEVEL)
void
QuicHashFree(
    _In_opt_ QUIC_HASH* Hash
    )
{
    if (Hash) {
        QUIC_FREE(Hash);
    }
}

_IRQL_requires_max_(DISPATCH_LEVEL)
QUIC_STATUS
QuicHashCompute(
    _In_ QUIC_HASH* Hash,
    _In_reads_(InputLength)
        const uint8_t* const Input,
    _In_ uint32_t InputLength,
    _In_ uint32_t OutputLength,
    _Out_writes_all_(OutputLength)
        uint8_t* const Output
    )
{
    UNREFERENCED_PARAMETER(OutputLength);
    EverCrypt_HMAC_compute(
        HashTypeToEverCrypt(Hash->Type),
        Output,
        Hash->Salt,
        Hash->SaltLength,
        (uint8_t*)Input,
        InputLength);
    return QUIC_STATUS_SUCCESS;
}
