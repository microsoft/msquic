/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.

Abstract:

    miTLS TLS Implementation for QUIC

--*/

#include "platform_internal.h"
#ifdef QUIC_CLOG
#include "tls_mitls.c.clog.h"
#endif

#define IS_WINDOWS 1
#pragma warning(disable:4996) // Deprecated APIs
#include <EverCrypt.h>
#include <mitlsffi.h>

uint16_t CxPlatTlsTPHeaderSize = 0;

#define CXPLAT_SUPPORTED_CIPHER_SUITES        "TLS_AES_256_GCM_SHA384:TLS_AES_128_GCM_SHA256"
#define CXPLAT_SERVER_SIGNATURE_ALGORITHMS    "ECDSA+SHA256:ECDSA+SHA384:ECDSA+SHA512:RSAPSS+SHA256:RSAPSS+SHA384:RSAPSS+SHA512"
#define CXPLAT_CLIENT_SIGNATURE_ALGORITHMS    "ECDSA+SHA256:ECDSA+SHA384:ECDSA+SHA512:RSAPSS+SHA256:RSAPSS+SHA384:RSAPSS+SHA512"
#if CXPLAT_PROD_MITLS
#define CXPLAT_SERVER_NAMED_GROUPS            "P-521:P-384:P-256:X25519:FFDHE4096:FFDHE3072:FFDHE2048"
#define CXPLAT_CLIENT_NAMED_GROUPS            "P-384:P-256:X25519"
#else
#define CXPLAT_SERVER_NAMED_GROUPS            "X25519"
#define CXPLAT_CLIENT_NAMED_GROUPS            "X25519"
#endif

//
// The maximum message buffer length.
//
#define CXPLAT_TLS_MAX_MESSAGE_LENGTH (8 * 1024)

const QUIC_PACKET_KEY_TYPE miTlsKeyTypes[2][4] =
{
    { QUIC_PACKET_KEY_INITIAL, QUIC_PACKET_KEY_HANDSHAKE, QUIC_PACKET_KEY_1_RTT, QUIC_PACKET_KEY_1_RTT },
    { QUIC_PACKET_KEY_INITIAL, QUIC_PACKET_KEY_0_RTT, QUIC_PACKET_KEY_HANDSHAKE, QUIC_PACKET_KEY_1_RTT }
};

//
// Callback for miTLS when extensions are ready.
//
_IRQL_requires_max_(PASSIVE_LEVEL)
_Success_(return != TLS_nego_abort)
mitls_nego_action
MITLS_CALLCONV
CxPlatTlsOnNegotiate(
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
CxPlatTlsOnTicketReady(
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
CxPlatTlsOnCertSelect(
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
CxPlatTlsOnCertFormat(
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
CxPlatTlsOnCertSign(
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
CxPlatTlsOnCertVerify(
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
    _In_ CXPLAT_TLS* TlsContext,
    _In_ QUIC_PACKET_KEY_TYPE KeyType,
    _In_ int Epoch,
    _In_ quic_direction rw,
    _Out_ QUIC_PACKET_KEY** NewKey
    );

//
// TLS Security Config
//
typedef struct CXPLAT_SEC_CONFIG {

    QUIC_CREDENTIAL_TYPE Type;
    QUIC_CREDENTIAL_FLAGS Flags;

    CXPLAT_TLS_CALLBACKS Callbacks;

    //
    // The certificate context, used for signing.
    //
    QUIC_CERTIFICATE* Certificate;
    void* PrivateKey;

    //
    // Formatted certificate bytes for sending on the wire.
    //
    uint16_t FormatLength;
    uint8_t FormatBuffer[CXPLAT_TLS_MAX_MESSAGE_LENGTH];

} CXPLAT_SEC_CONFIG;

//
// Contiguous memory representation of a ticket.
//
typedef struct CXPLAT_TLS_TICKET {

    uint32_t TicketLength;
    uint32_t SessionLength;
    _Field_size_(TicketLength + SessionLength)
    uint8_t Buffer[0];

} CXPLAT_TLS_TICKET;

//
// The TLS interface context.
//
typedef struct CXPLAT_TLS {

    //
    // Flag indicating if the TLS represents a server.
    //
    BOOLEAN IsServer : 1;

    //
    // Indicates the client attempted 0-RTT.
    //
    BOOLEAN EarlyDataAttempted : 1;

    //
    // Index into the miTlsKeyTypes array.
    //
    uint8_t TlsKeySchedule : 1;
    uint8_t TlsKeyScheduleSet : 1;

    //
    // The TLS extension type for the QUIC transport parameters.
    //
    uint16_t QuicTpExtType;

    //
    // The TLS configuration information and credentials.
    //
    CXPLAT_SEC_CONFIG* SecConfig;

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
    // Process state for the outstanding process call.
    //
    CXPLAT_TLS_PROCESS_STATE* State;

    //
    // Callback handlers and input connection.
    //
    QUIC_CONNECTION* Connection;

    //
    // miTLS Config.
    //
    quic_config miTlsConfig;

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
    // Storage for encoded TLS extensions.
    //
    mitls_extension Extensions[2];

#ifdef CXPLAT_TLS_SECRETS_SUPPORT
    //
    // Optional pointer to struct to store TLS secrets.
    //
    CXPLAT_TLS_SECRETS* TlsSecrets;
#endif

} CXPLAT_TLS;

DWORD miTlsCurrentConnectionIndex = TLS_OUT_OF_INDEXES; // Thread-local storage index

//
// Callback from mitls for logging purposes.
//
void
MITLS_CALLCONV
MiTlsTraceCallback(
    _In_z_ const char *Msg
    )
{
    QuicTraceEvent(
        TlsMessage,
        "[ tls][%p] %s",
        TlsGetValue(miTlsCurrentConnectionIndex),
        Msg);
}

QUIC_STATUS
CxPlatTlsLibraryInitialize(
    void
    )
{
    QUIC_STATUS Status;

    miTlsCurrentConnectionIndex = TlsAlloc();

    QuicTraceLogVerbose(
        miTlsInitialize,
        "[ tls] Initializing miTLS library");
    FFI_mitls_set_trace_callback(MiTlsTraceCallback);
    if (!FFI_mitls_init()) {
        Status = QUIC_STATUS_INVALID_STATE;
        QuicTraceEvent(
            LibraryError,
            "[ lib] ERROR, %s.",
            "FFI_mitls_init failed");
        goto Error;
    }

    uint8_t Key[CXPLAT_IV_LENGTH + 32] = { 0 }; // Always use the same null key client side right now.
    if (!FFI_mitls_set_sealing_key("AES256-GCM", Key, sizeof(Key))) {
        Status = QUIC_STATUS_INVALID_STATE;
        QuicTraceEvent(
            LibraryError,
            "[ lib] ERROR, %s.",
            "FFI_mitls_set_sealing_key failed");
        FFI_mitls_cleanup();
        goto Error;
    }

    //
    // Randomly initialize the server's 0-RTT ticket encryption key.
    //
    CxPlatRandom(sizeof(Key), Key);
    if (!FFI_mitls_set_ticket_key("AES256-GCM", Key, sizeof(Key))) {
        Status = QUIC_STATUS_INVALID_STATE;
        QuicTraceEvent(
            LibraryError,
            "[ lib] ERROR, %s.",
            "FFI_mitls_set_ticket_key failed");
        FFI_mitls_cleanup();
        goto Error;
    }

    Status = QUIC_STATUS_SUCCESS;

Error:

    if (QUIC_FAILED(Status)) {
        TlsFree(miTlsCurrentConnectionIndex);
    }

    return Status;
}

void
CxPlatTlsLibraryUninitialize(
    void
    )
{
    QuicTraceLogVerbose(
        miTlsUninitialize,
        "[ tls] Cleaning up miTLS library");
    FFI_mitls_cleanup();
    TlsFree(miTlsCurrentConnectionIndex);
}

_IRQL_requires_max_(PASSIVE_LEVEL)
QUIC_STATUS
CxPlatTlsSecConfigCreate(
    _In_ const QUIC_CREDENTIAL_CONFIG* CredConfig,
    _In_ const CXPLAT_TLS_CALLBACKS* TlsCallbacks,
    _In_opt_ void* Context,
    _In_ CXPLAT_SEC_CONFIG_CREATE_COMPLETE_HANDLER CompletionHandler
    )
{
    if (CredConfig->Flags & QUIC_CREDENTIAL_FLAG_LOAD_ASYNCHRONOUS &&
        CredConfig->AsyncHandler == NULL) {
        return QUIC_STATUS_INVALID_PARAMETER;
    }

    if (CredConfig->Flags & QUIC_CREDENTIAL_FLAG_ENABLE_OCSP ||
        CredConfig->Flags & QUIC_CREDENTIAL_FLAG_DEFER_CERTIFICATE_VALIDATION) {
        return QUIC_STATUS_NOT_SUPPORTED; // Not supported by this TLS implementation
    }

    if (CredConfig->Flags & QUIC_CREDENTIAL_FLAG_CLIENT) {
        if (CredConfig->Type != QUIC_CREDENTIAL_TYPE_NONE) {
            return QUIC_STATUS_NOT_SUPPORTED; // Not supported for client (yet)
        }
    } else {
        if (CredConfig->Type == QUIC_CREDENTIAL_TYPE_NONE) {
            return QUIC_STATUS_INVALID_PARAMETER; // Required for server
        }
    }

#pragma prefast(suppress: __WARNING_6014, "Memory is correctly freed (CxPlatTlsSecConfigDelete).")
    CXPLAT_SEC_CONFIG* SecurityConfig = CXPLAT_ALLOC_PAGED(sizeof(CXPLAT_SEC_CONFIG), QUIC_POOL_TLS_SECCONF);
    if (SecurityConfig == NULL) {
        return QUIC_STATUS_OUT_OF_MEMORY;
    }

    SecurityConfig->Type = CredConfig->Type;
    SecurityConfig->Flags = CredConfig->Flags;
    SecurityConfig->Callbacks = *TlsCallbacks;
    SecurityConfig->Certificate = NULL;
    SecurityConfig->PrivateKey = NULL;
    SecurityConfig->FormatLength = 0;

    QUIC_STATUS Status = QUIC_STATUS_SUCCESS;

    if (!(CredConfig->Flags & QUIC_CREDENTIAL_FLAG_CLIENT)) {

        Status = CxPlatCertCreate(CredConfig, &SecurityConfig->Certificate);
        if (QUIC_FAILED(Status)) {
            goto Error;
        }

        SecurityConfig->PrivateKey =
            CxPlatCertGetPrivateKey(SecurityConfig->Certificate);
        if (SecurityConfig->PrivateKey == NULL) {
            Status = QUIC_STATUS_INVALID_PARAMETER;
            goto Error;
        }

        SecurityConfig->FormatLength =
            (uint16_t)CxPlatCertFormat(
                SecurityConfig->Certificate,
                sizeof(SecurityConfig->FormatBuffer),
                SecurityConfig->FormatBuffer);
    }

    CompletionHandler(
        CredConfig,
        Context,
        Status,
        SecurityConfig);
    SecurityConfig = NULL;

    if (CredConfig->Flags & QUIC_CREDENTIAL_FLAG_LOAD_ASYNCHRONOUS) {
        Status = QUIC_STATUS_PENDING;
    } else {
        Status = QUIC_STATUS_SUCCESS;
    }

Error:

    if (SecurityConfig != NULL) {
        CxPlatTlsSecConfigDelete(SecurityConfig);
    }

    return Status;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
void
CxPlatTlsSecConfigDelete(
    __drv_freesMem(ServerConfig) _Frees_ptr_ _In_
        CXPLAT_SEC_CONFIG* SecurityConfig
    )
{
    if (SecurityConfig->PrivateKey != NULL) {
        CxPlatCertDeletePrivateKey(SecurityConfig->PrivateKey);
    }
    if (SecurityConfig->Certificate != NULL &&
        (SecurityConfig->Type != QUIC_CREDENTIAL_TYPE_CERTIFICATE_CONTEXT)) {
        CxPlatCertFree(SecurityConfig->Certificate);
    }
    CXPLAT_FREE(SecurityConfig, QUIC_POOL_TLS_SECCONF);
}

const uint8_t miTlsTicketKeyLength = 44;

_IRQL_requires_max_(PASSIVE_LEVEL)
QUIC_STATUS
CxPlatTlsSecConfigSetTicketKeys(
    _In_ CXPLAT_SEC_CONFIG* SecurityConfig,
    _In_reads_(KeyCount) QUIC_TICKET_KEY_CONFIG* KeyConfig,
    _In_ uint8_t KeyCount
    )
{
    CXPLAT_DBG_ASSERT(KeyCount >= 1);
    UNREFERENCED_PARAMETER(KeyCount);

    if (KeyConfig->MaterialLength < miTlsTicketKeyLength) {
        return QUIC_STATUS_INVALID_PARAMETER;
    }

    if (SecurityConfig->Flags & QUIC_CREDENTIAL_FLAG_CLIENT) {
        if (!FFI_mitls_set_sealing_key("AES256-GCM", KeyConfig->Material, miTlsTicketKeyLength)) {
            QuicTraceEvent(
                LibraryError,
                "[ lib] ERROR, %s.",
                "FFI_mitls_set_sealing_key failed");
            return QUIC_STATUS_INVALID_STATE;
        }

    } else {
        if (!FFI_mitls_set_ticket_key("AES256-GCM", KeyConfig->Material, miTlsTicketKeyLength)) {
            QuicTraceEvent(
                LibraryError,
                "[ lib] ERROR, %s.",
                "FFI_mitls_set_ticket_key failed");
            return QUIC_STATUS_INVALID_STATE;
        }
    }

    return QUIC_STATUS_SUCCESS;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
QUIC_STATUS
CxPlatTlsInitialize(
    _In_ const CXPLAT_TLS_CONFIG* Config,
    _Inout_ CXPLAT_TLS_PROCESS_STATE* State,
    _Out_ CXPLAT_TLS** NewTlsContext
    )
{
    QUIC_STATUS Status;
    CXPLAT_TLS* TlsContext;

    CXPLAT_DBG_ASSERT(Config != NULL);
    CXPLAT_DBG_ASSERT(NewTlsContext != NULL);
    CXPLAT_DBG_ASSERT(Config->SecConfig != NULL);
    UNREFERENCED_PARAMETER(State);

    TlsSetValue(miTlsCurrentConnectionIndex, Config->Connection);

    TlsContext = CXPLAT_ALLOC_PAGED(sizeof(CXPLAT_TLS) + sizeof(uint16_t) + Config->AlpnBufferLength, QUIC_POOL_TLS_CTX);
    if (TlsContext == NULL) {
        QuicTraceEvent(
            AllocFailure,
            "Allocation of '%s' failed. (%llu bytes)",
            "CXPLAT_TLS",
            sizeof(CXPLAT_TLS) + sizeof(uint16_t) + Config->AlpnBufferLength);
        Status = QUIC_STATUS_OUT_OF_MEMORY;
        goto Exit;
    }

    CxPlatZeroMemory(TlsContext, sizeof(CXPLAT_TLS));

    //
    // Initialize internal variables.
    //
    TlsContext->IsServer = Config->IsServer;
    TlsContext->SecConfig = Config->SecConfig;
    TlsContext->QuicTpExtType = Config->TPType;
    TlsContext->CurrentReaderKey = -1;
    TlsContext->CurrentWriterKey = -1;
    TlsContext->Connection = Config->Connection;

    TlsContext->Extensions[0].ext_type = TLS_EXTENSION_TYPE_APPLICATION_LAYER_PROTOCOL_NEGOTIATION;
    TlsContext->Extensions[0].ext_data_len = sizeof(uint16_t) + Config->AlpnBufferLength;
    TlsContext->Extensions[0].ext_data = (uint8_t*)(TlsContext + 1);
    *(uint16_t*)TlsContext->Extensions[0].ext_data = CxPlatByteSwapUint16(Config->AlpnBufferLength);
    CxPlatCopyMemory(
        (uint8_t*)TlsContext->Extensions[0].ext_data + sizeof(uint16_t),
        Config->AlpnBuffer,
        Config->AlpnBufferLength);

    TlsContext->Extensions[1].ext_type = Config->TPType;
    TlsContext->Extensions[1].ext_data_len = Config->LocalTPLength;
    TlsContext->Extensions[1].ext_data = Config->LocalTPBuffer;

    TlsContext->miTlsConfig.enable_0rtt = TRUE;
    TlsContext->miTlsConfig.exts = TlsContext->Extensions;
    TlsContext->miTlsConfig.exts_count = ARRAYSIZE(TlsContext->Extensions);
    TlsContext->miTlsConfig.cipher_suites = CXPLAT_SUPPORTED_CIPHER_SUITES;
    TlsContext->miTlsConfig.nego_callback = CxPlatTlsOnNegotiate;
    TlsContext->miTlsConfig.cert_callbacks = &TlsContext->miTlsCertCallbacks;

#ifdef CXPLAT_TLS_SECRETS_SUPPORT
    TlsContext->TlsSecrets = Config->TlsSecrets;
#endif

    if (Config->IsServer) {

        CXPLAT_DBG_ASSERT(Config->ResumptionTicketBuffer == NULL);

        TlsContext->miTlsConfig.is_server = TRUE;
        TlsContext->miTlsConfig.callback_state = TlsContext;

        TlsContext->miTlsCertCallbacks.select = CxPlatTlsOnCertSelect;
        TlsContext->miTlsCertCallbacks.format = CxPlatTlsOnCertFormat;
        TlsContext->miTlsCertCallbacks.sign = CxPlatTlsOnCertSign;

        //
        // Specific algorithm depending on the cert we are using.
        //
        TlsContext->miTlsConfig.signature_algorithms = CXPLAT_SERVER_SIGNATURE_ALGORITHMS;
        TlsContext->miTlsConfig.named_groups = CXPLAT_SERVER_NAMED_GROUPS;

    } else {
        TlsContext->miTlsConfig.is_server = FALSE;

        if (Config->ServerName != NULL) {
            const size_t ServerNameLength =
                strnlen(Config->ServerName, QUIC_MAX_SNI_LENGTH + 1);
            if (ServerNameLength == QUIC_MAX_SNI_LENGTH + 1) {
                QuicTraceEvent(
                    TlsError,
                    "[ tls][%p] ERROR, %s.",
                    TlsContext->Connection,
                    "SNI Too Long");
                Status = QUIC_STATUS_INVALID_PARAMETER;
                goto Error;
            }

            TlsContext->SNI = CXPLAT_ALLOC_PAGED(ServerNameLength + 1, QUIC_POOL_TLS_SNI);
            if (TlsContext->SNI == NULL) {
                QuicTraceEvent(
                    AllocFailure,
                    "Allocation of '%s' failed. (%llu bytes)",
                    "SNI",
                    ServerNameLength + 1);
                Status = QUIC_STATUS_OUT_OF_MEMORY;
                goto Error;
            }
            memcpy((char*)TlsContext->SNI, Config->ServerName, ServerNameLength + 1);

            if (Config->ResumptionTicketBuffer != NULL) {

                QuicTraceLogConnVerbose(
                    miTlsUsing0Rtt,
                    TlsContext->Connection,
                    "Using 0-RTT ticket.");

                CXPLAT_TLS_TICKET* SerializedTicket =
                    (CXPLAT_TLS_TICKET*)Config->ResumptionTicketBuffer;
                if (SerializedTicket->SessionLength + SerializedTicket->TicketLength
                    != Config->ResumptionTicketLength - sizeof(CXPLAT_TLS_TICKET)) {
                    QuicTraceEvent(
                        TlsError,
                        "[ tls][%p] ERROR, %s.",
                        TlsContext->Connection,
                        "0-RTT ticket is corrupt");
                } else {
                    TlsContext->miTlsTicket.ticket_len = SerializedTicket->TicketLength;
                    TlsContext->miTlsTicket.ticket = SerializedTicket->Buffer;

                    TlsContext->miTlsTicket.session_len = SerializedTicket->SessionLength;
                    TlsContext->miTlsTicket.session =
                        SerializedTicket->Buffer + SerializedTicket->TicketLength;

                    TlsContext->miTlsConfig.server_ticket = &TlsContext->miTlsTicket;
                }
            }
        }

        TlsContext->miTlsConfig.host_name = TlsContext->SNI;
        TlsContext->miTlsConfig.callback_state = TlsContext;

        TlsContext->miTlsConfig.ticket_callback = CxPlatTlsOnTicketReady;
        TlsContext->miTlsCertCallbacks.verify = CxPlatTlsOnCertVerify;

        //
        // List of supported algorithms for the client.
        //
        TlsContext->miTlsConfig.signature_algorithms = CXPLAT_CLIENT_SIGNATURE_ALGORITHMS;
        TlsContext->miTlsConfig.named_groups = CXPLAT_CLIENT_NAMED_GROUPS;
    }

    //
    // Initialize the miTLS library.
    //
    if (!FFI_mitls_quic_create(&TlsContext->miTlsState, &TlsContext->miTlsConfig)) {
        QuicTraceEvent(
            TlsError,
            "[ tls][%p] ERROR, %s.",
            TlsContext->Connection,
            "FFI_mitls_quic_create failed");
        Status = QUIC_STATUS_INVALID_PARAMETER;
        goto Error;
    }

    *NewTlsContext = TlsContext;
    Status = QUIC_STATUS_SUCCESS;

Error:

    if (QUIC_FAILED(Status)) {
        if (TlsContext->SNI) {
            CXPLAT_FREE(TlsContext->SNI, QUIC_POOL_TLS_SNI);
        }
        CXPLAT_FREE(TlsContext, QUIC_POOL_TLS_CTX);
    }

Exit:

    return Status;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
void
CxPlatTlsUninitialize(
    _In_opt_ CXPLAT_TLS* TlsContext
    )
{
    if (TlsContext != NULL) {

        FFI_mitls_quic_free(TlsContext->miTlsState);

        if (TlsContext->miTlsTicket.ticket != NULL) {
            CXPLAT_TLS_TICKET* SerializedTicket =
                CONTAINING_RECORD(
                    TlsContext->miTlsTicket.ticket,
                    CXPLAT_TLS_TICKET,
                    Buffer);
            CXPLAT_FREE(SerializedTicket, QUIC_POOL_CRYPTO_RESUMPTION_TICKET);
        }

        if (TlsContext->SNI != NULL) {
            CXPLAT_FREE(TlsContext->SNI, QUIC_POOL_TLS_SNI);
        }

        if (TlsContext->Extensions[1].ext_data != NULL) {
            CXPLAT_FREE(TlsContext->Extensions[1].ext_data, QUIC_POOL_TLS_TRANSPARAMS);
        }

        CXPLAT_FREE(TlsContext, QUIC_POOL_TLS_CTX);
    }
}

_IRQL_requires_max_(PASSIVE_LEVEL)
CXPLAT_TLS_RESULT_FLAGS
CxPlatTlsProcessData(
    _In_ CXPLAT_TLS* TlsContext,
    _In_ CXPLAT_TLS_DATA_TYPE DataType,
    _In_reads_bytes_(*BufferLength)
        const uint8_t * Buffer,
    _Inout_ uint32_t * BufferLength,
    _Inout_ CXPLAT_TLS_PROCESS_STATE* State
    )
{
    CXPLAT_TLS_RESULT_FLAGS ResultFlags = 0;
    uint32_t ConsumedBytes;

    CXPLAT_DBG_ASSERT(Buffer != NULL || *BufferLength == 0);

    TlsSetValue(miTlsCurrentConnectionIndex, TlsContext->Connection);

    TlsContext->State = State;

    if (DataType == CXPLAT_TLS_CRYPTO_DATA) {

        //
        // Validate buffer lengths.
        //
        if (TlsContext->BufferLength + *BufferLength > CXPLAT_TLS_MAX_MESSAGE_LENGTH) {
            ResultFlags = CXPLAT_TLS_RESULT_ERROR;
            QuicTraceEvent(
                TlsError,
                "[ tls][%p] ERROR, %s.",
                TlsContext->Connection,
                "TLS buffer too big");
            goto Error;
        }

        if (*BufferLength) {
            QuicTraceLogConnVerbose(
                miTlsProcess,
                TlsContext->Connection,
                "Processing %u bytes",
                *BufferLength);

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
            ResultFlags = CXPLAT_TLS_RESULT_PENDING;
            TlsContext->SecConfig->Callbacks.ProcessComplete(TlsContext->Connection);

        } else {

            //
            // We process the inital data inline.
            //
            TlsContext->BufferLength = 0;
            ResultFlags = CxPlatTlsProcessDataComplete(TlsContext, &ConsumedBytes);
            *BufferLength = ConsumedBytes;
        }

    } else {
        CXPLAT_DBG_ASSERT(DataType == CXPLAT_TLS_TICKET_DATA);

        CXPLAT_DBG_ASSERT(TlsContext->IsServer);

        QuicTraceLogConnVerbose(
            miTlsSend0RttTicket,
            TlsContext->Connection,
            "Sending 0-RTT ticket");

        if (!FFI_mitls_quic_send_ticket(TlsContext->miTlsState, Buffer, *BufferLength)) {
            QuicTraceEvent(
                TlsError,
                "[ tls][%p] ERROR, %s.",
                TlsContext->Connection,
                "FFI_mitls_quic_send_ticket failed");
            ResultFlags |= CXPLAT_TLS_RESULT_ERROR;
        } else {
            TlsContext->SecConfig->Callbacks.ProcessComplete(TlsContext->Connection);
            ResultFlags |= CXPLAT_TLS_RESULT_PENDING;
        }
    }

Error:

    return ResultFlags;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
CXPLAT_TLS_RESULT_FLAGS
CxPlatTlsProcessDataComplete(
    _In_ CXPLAT_TLS* TlsContext,
    _Out_ uint32_t * BufferConsumed
    )
{
    CXPLAT_TLS_RESULT_FLAGS ResultFlags = 0;
    CXPLAT_TLS_PROCESS_STATE* State = TlsContext->State;

    if (TlsContext->IsServer) {
        CXPLAT_DBG_ASSERT(TlsContext->State->HandshakeComplete || TlsContext->Buffer != NULL);
    }

    TlsSetValue(miTlsCurrentConnectionIndex, TlsContext->Connection);

    uint32_t BufferOffset = 0;

    while (!(ResultFlags & CXPLAT_TLS_RESULT_ERROR)) {

        quic_process_ctx Context = {
            TlsContext->Buffer + BufferOffset,              // input
            TlsContext->BufferLength - BufferOffset,        // input_len
            State->Buffer + State->BufferLength,            // output
            State->BufferAllocLength - State->BufferLength, // output_len
            0
        };

        QuicTraceLogConnVerbose(
            miTlsFfiProces,
            TlsContext->Connection,
            "FFI_mitls_quic_process processing %u input bytes",
            (uint32_t)Context.input_len);

        //
        // Pass the data to miTLS for processing.
        //
        if (!FFI_mitls_quic_process(TlsContext->miTlsState, &Context)) {
            QuicTraceLogConnError(
                miTlsFfiProcessFailed,
                TlsContext->Connection,
                "FFI_mitls_quic_process failed, tls_error %hu, %s",
                Context.tls_error,
                Context.tls_error_desc);
            State->AlertCode = Context.tls_error;
            ResultFlags |= CXPLAT_TLS_RESULT_ERROR;
            break;
        }

        QuicTraceLogConnVerbose(
            miTlsFfiProcessResult,
            TlsContext->Connection,
            "FFI_mitls_quic_process read %u bytes and has %u bytes ready to send",
            (uint32_t)Context.consumed_bytes,
            (uint32_t)Context.output_len);

        CXPLAT_DBG_ASSERT(Context.consumed_bytes <= Context.input_len);
        CXPLAT_DBG_ASSERT((int64_t)Context.output_len <= State->BufferAllocLength - State->BufferLength);
        CXPLAT_FRE_ASSERT(Context.to_be_written == 0); // TODO - Support dynamic sizes?

        //
        // Update the buffer offsets based on the output of miTLS.
        //
        BufferOffset += (uint32_t)Context.consumed_bytes;
        State->BufferLength += (uint16_t)Context.output_len;
        State->BufferTotalLength += (uint16_t)Context.output_len;

        if (Context.output_len != 0) {
            ResultFlags |= CXPLAT_TLS_RESULT_DATA;
        }

        if (Context.flags & QFLAG_COMPLETE && !State->HandshakeComplete) {
            QuicTraceLogConnVerbose(
                miTlsHandshakeComplete,
                TlsContext->Connection,
                "Handshake complete");
            State->HandshakeComplete = TRUE;
            ResultFlags |= CXPLAT_TLS_RESULT_COMPLETE;
        }

        if (Context.flags & QFLAG_REJECTED_0RTT) {
            if (TlsContext->IsServer) {
                TlsContext->EarlyDataAttempted = TRUE;
            }
            if (TlsContext->EarlyDataAttempted) {
                ResultFlags |= CXPLAT_TLS_RESULT_EARLY_DATA_REJECT;
            }
            State->EarlyDataState = CXPLAT_TLS_EARLY_DATA_REJECTED;
            QuicTraceLogConnVerbose(
                miTlsEarlyDataRejected,
                TlsContext->Connection,
                "Early data rejected");
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
                    ResultFlags |= CXPLAT_TLS_RESULT_EARLY_DATA_ACCEPT;
                    QuicTraceLogConnVerbose(
                        miTlsEarlyDataAccepted,
                        TlsContext->Connection,
                        "Early data accepted");
                    TlsContext->TlsKeySchedule = 1; // 0-RTT allowed.
                    State->SessionResumed = TRUE;
                    TlsContext->EarlyDataAttempted = TRUE;
                    State->EarlyDataState = CXPLAT_TLS_EARLY_DATA_ACCEPTED;
                    //
                    // Get resumption data from the client hello
                    //
                    uint32_t PreviousOffset = BufferOffset - (uint32_t)Context.consumed_bytes;
                    mitls_hello_summary HelloSummary = { 0 };
                    uint8_t* Cookie = NULL;
                    size_t CookieLen = 0;
                    uint8_t* Ticket = NULL;
                    size_t TicketLen = 0;
                    if (!FFI_mitls_get_hello_summary(
                            TlsContext->Buffer + PreviousOffset, TlsContext->BufferLength - PreviousOffset,
                            FALSE,
                            &HelloSummary,
                            &Cookie, &CookieLen,
                            &Ticket, &TicketLen)) {
                        QuicTraceLogConnError(
                            miTlsFfiGetHelloSummaryFailed,
                            TlsContext->Connection,
                            "FFI_mitls_get_hello_summary failed, cookie_len: %zu, ticket_len: %zu",
                            CookieLen,
                            TicketLen);
                        ResultFlags |= CXPLAT_TLS_RESULT_ERROR;
                        break;
                    }
                    CXPLAT_FRE_ASSERT(TicketLen <= UINT32_MAX);
                    if (!TlsContext->SecConfig->Callbacks.ReceiveTicket(
                            TlsContext->Connection,
                            (uint32_t)TicketLen, Ticket)) {
                        //
                        // QUIC or the app rejected the resumption ticket.
                        // Abandon the early data and continue the handshake.
                        //
                        ResultFlags &= ~CXPLAT_TLS_RESULT_EARLY_DATA_ACCEPT;
                        ResultFlags |= CXPLAT_TLS_RESULT_EARLY_DATA_REJECT;
                        State->EarlyDataState = CXPLAT_TLS_EARLY_DATA_REJECTED;
                        State->SessionResumed = FALSE;
                    }
                    if (Cookie) {
                        FFI_mitls_global_free(Cookie);
                        Cookie = NULL;
                    }
                    if (Ticket) {
                        FFI_mitls_global_free(Ticket);
                        Ticket = NULL;
                    }
                } else {
                    TlsContext->TlsKeySchedule = 0;
                    if (!(Context.flags & QFLAG_REJECTED_0RTT)) {
                        QuicTraceLogConnVerbose(
                            miTlsEarlyDataNotAttempted,
                            TlsContext->Connection,
                            "Early data not attempted");
                    }
                }
            } else {
                if (WriteKeyUpdated) {
                    QuicTraceLogConnVerbose(
                        miTlsEarlyDataAttempted,
                        TlsContext->Connection,
                        "Early data attempted");
                    TlsContext->TlsKeySchedule = 1; // 0-RTT allowed.
                    TlsContext->EarlyDataAttempted = TRUE;
                } else {
                    TlsContext->TlsKeySchedule = 0;
                }
            }
            QuicTraceLogConnVerbose(
                miTlsKeySchedule,
                TlsContext->Connection,
                "Key schedule = %hu",
                TlsContext->TlsKeySchedule);
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
                    QuicTraceLogConnVerbose(
                        miTls0RttReadKeyExported,
                        TlsContext->Connection,
                        "0-RTT read key exported");
                    break;
                case QUIC_PACKET_KEY_HANDSHAKE:
                    QuicTraceLogConnVerbose(
                        miTlsHandshakeReadKeyExported,
                        TlsContext->Connection,
                        "Handshake read key exported");
                    break;
                case QUIC_PACKET_KEY_1_RTT:
                    QuicTraceLogConnVerbose(
                        miTls1RttReadKeyExported,
                        TlsContext->Connection,
                        "1-RTT read key exported");
                    if (!TlsContext->IsServer) {
                        if (TlsContext->EarlyDataAttempted &&
                            !(Context.flags & QFLAG_REJECTED_0RTT)) {
                            //
                            // We know 0-RTT was accepted by the server once we have
                            // the 1-RTT keys and we haven't received any 0-RTT
                            // rejected event/flag from miTLS.
                            //
                            ResultFlags |= CXPLAT_TLS_RESULT_EARLY_DATA_ACCEPT;
                            State->SessionResumed = TRUE;
                            State->EarlyDataState = CXPLAT_TLS_EARLY_DATA_ACCEPTED;
                            QuicTraceLogConnVerbose(
                                miTlsEarlyDataAccepted,
                                TlsContext->Connection,
                                "Early data accepted");
                        }
                    }
                    break;
                default:
                    CXPLAT_FRE_ASSERT(FALSE);
                    break;
                }
            }

            ResultFlags |= CXPLAT_TLS_RESULT_READ_KEY_UPDATED;
            State->ReadKey = NewKeyType;
            TlsContext->CurrentReaderKey = Context.cur_reader_key;

            if (State->ReadKey > State->WriteKey &&
                State->ReadKey != QUIC_PACKET_KEY_0_RTT) {
                //
                // Must always have corresponding write key for every read key.
                //
                ResultFlags |= CXPLAT_TLS_RESULT_WRITE_KEY_UPDATED;
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
                    QuicTraceLogConnVerbose(
                        miTls0RttWriteKeyExported,
                        TlsContext->Connection,
                        "0-RTT write key exported");
                    break;
                case QUIC_PACKET_KEY_HANDSHAKE:
                    QuicTraceLogConnVerbose(
                        miTlsHandshakeWriteKeyExported,
                        TlsContext->Connection,
                        "Handshake write key exported");
                    break;
                case QUIC_PACKET_KEY_1_RTT:
                    QuicTraceLogConnVerbose(
                        miTls1RttWriteKeyExported,
                        TlsContext->Connection,
                        "1-RTT write key exported");
                    break;
                default:
                    CXPLAT_FRE_ASSERT(FALSE);
                    break;
                }
            }

            switch (NewKeyType) {
            case QUIC_PACKET_KEY_0_RTT:
                break;
            case QUIC_PACKET_KEY_HANDSHAKE:
                State->BufferOffsetHandshake = State->BufferTotalLength;
                QuicTraceLogConnVerbose(
                    miTlsHandshakeWriteOffsetSet,
                    TlsContext->Connection,
                    "Handshake write offset = %u",
                    State->BufferOffsetHandshake);
                break;
            case QUIC_PACKET_KEY_1_RTT:
                State->BufferOffset1Rtt = State->BufferTotalLength;
                QuicTraceLogConnVerbose(
                    miTls1RttWriteOffsetSet,
                    TlsContext->Connection,
                    "1-RTT write offset = %u",
                    State->BufferOffset1Rtt);
                break;
            default:
                CXPLAT_FRE_ASSERT(FALSE);
                break;
            }

            ResultFlags |= CXPLAT_TLS_RESULT_WRITE_KEY_UPDATED;
            TlsContext->CurrentWriterKey = Context.cur_writer_key;

            if (NewKeyType > State->WriteKey &&
                NewKeyType != QUIC_PACKET_KEY_0_RTT) {
                ResultFlags |= CXPLAT_TLS_RESULT_WRITE_KEY_UPDATED;
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

    QuicTraceLogConnVerbose(
        miTlsFfiProcesComplete,
        TlsContext->Connection,
        "Consumed %u bytes",
        BufferOffset);

    return ResultFlags;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
void*
MITLS_CALLCONV
CxPlatTlsOnCertSelect(
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
    CXPLAT_TLS* TlsContext = (CXPLAT_TLS*)Context;
    const CXPLAT_SEC_CONFIG* SecurityConfig = NULL;

    CXPLAT_DBG_ASSERT(TlsContext);
    CXPLAT_DBG_ASSERT(TlsContext->IsServer);

    QuicTraceLogConnVerbose(
        miTlsOnCertSelect,
        TlsContext->Connection,
        "OnCertSelect");

    //
    // Only allow TLS 1.3.
    //
    if (TlsVersion != TLS_1p3) {
        QuicTraceEvent(
            TlsError,
            "[ tls][%p] ERROR, %s.",
            TlsContext->Connection,
            "Unsupported TLS version");
        goto Error;
    }

    //
    // Validate and save a copy of the SNI.
    //

    if (ServerNameIndicationLength >= QUIC_MAX_SNI_LENGTH) {
        QuicTraceEvent(
            TlsError,
            "[ tls][%p] ERROR, %s.",
            TlsContext->Connection,
            "SNI too long");
        goto Error;
    }

    if (ServerNameIndicationLength != 0) {
        TlsContext->SNI = CXPLAT_ALLOC_PAGED((uint16_t)(ServerNameIndicationLength + 1), QUIC_POOL_TLS_SNI);
        if (TlsContext->SNI == NULL) {
            QuicTraceEvent(
                AllocFailure,
                "Allocation of '%s' failed. (%llu bytes)",
                "SNI",
                ServerNameIndicationLength + 1);
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
    CXPLAT_DBG_ASSERT(SecurityConfig != NULL);

    //
    // Select a matching signature algorithm for the certificate.
    //
    CXPLAT_DBG_ASSERT(SignatureAlgorithmsLength != 0);
    if (!CxPlatCertSelect(
            SecurityConfig->Certificate,
            SignatureAlgorithms,
            SignatureAlgorithmsLength,
            SelectedSignature)) {
        QuicTraceEvent(
            TlsError,
            "[ tls][%p] ERROR, %s.",
            TlsContext->Connection,
            "CxPlatCertSelect failed");
        SecurityConfig = NULL;
        goto Error;
    }

    QuicTraceLogConnInfo(
        miTlsCertSelected,
        TlsContext->Connection,
        "Server certificate selected. SNI: %s; Algorithm: 0x%4.4x",
        TlsContext->SNI,
        *SelectedSignature);

Error:

    return (void*)SecurityConfig;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
_Success_(return != TLS_nego_abort)
mitls_nego_action
MITLS_CALLCONV
CxPlatTlsOnNegotiate(
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
    CXPLAT_TLS* TlsContext = (CXPLAT_TLS*)Context;
    CXPLAT_DBG_ASSERT(TlsContext);

    mitls_nego_action Action = TLS_nego_abort;
    uint8_t *ExtensionData;
    size_t ExtensionDataLength;

    UNREFERENCED_PARAMETER(Cookie);
    UNREFERENCED_PARAMETER(CookieLength);

    QuicTraceLogConnVerbose(
        miTlsOnNegotiate,
        TlsContext->Connection,
        "OnNegotiate");

    //
    // Only allow TLS 1.3.
    //
    if (Version != TLS_1p3) {
        QuicTraceEvent(
            TlsError,
            "[ tls][%p] ERROR, %s.",
            TlsContext->Connection,
            "Unsupported TLS version");
        goto Exit;
    }

    if (!TlsContext->IsServer) {
        //
        // Decode and extract the negotiated ALPN.
        //
        if (!FFI_mitls_find_custom_extension(
                TlsContext->IsServer,
                RawExtensions,
                RawExtensionsLength,
                TLS_EXTENSION_TYPE_APPLICATION_LAYER_PROTOCOL_NEGOTIATION,
                &ExtensionData,
                &ExtensionDataLength)) {
            QuicTraceEvent(
                TlsError,
                "[ tls][%p] ERROR, %s.",
                TlsContext->Connection,
                "Missing ALPN extension");
            goto Exit;
        }
        QuicTraceLogConnVerbose(
            miTlsProcessServerAlpn,
            TlsContext->Connection,
            "Processing server ALPN (Length=%u)",
            (uint32_t)ExtensionDataLength);
        if (ExtensionDataLength < 4) {
            QuicTraceEvent(
                TlsError,
                "[ tls][%p] ERROR, %s.",
                TlsContext->Connection,
                "ALPN extension length is too short");
            goto Exit;
        }
        const uint16_t AlpnListLength = CxPlatByteSwapUint16(*(uint16_t*)ExtensionData);
        if (AlpnListLength + sizeof(uint16_t) != ExtensionDataLength) {
            QuicTraceEvent(
                TlsError,
                "[ tls][%p] ERROR, %s.",
                TlsContext->Connection,
                "ALPN list length is incorrect");
            goto Exit;
        }
        const uint8_t AlpnLength = ExtensionData[2];
        if (AlpnLength + sizeof(uint8_t) != AlpnListLength) {
            QuicTraceEvent(
                TlsError,
                "[ tls][%p] ERROR, %s.",
                TlsContext->Connection,
                "ALPN length is incorrect");
            goto Exit;
        }
        const uint8_t* Alpn = ExtensionData + 3;
        TlsContext->State->NegotiatedAlpn =
            CxPlatTlsAlpnFindInList(
                (uint16_t)TlsContext->Extensions[0].ext_data_len - 2,
                TlsContext->Extensions[0].ext_data + 2,
                AlpnLength,
                Alpn);
        if (TlsContext->State->NegotiatedAlpn == NULL) {
            QuicTraceEvent(
                TlsError,
                "[ tls][%p] ERROR, %s.",
                TlsContext->Connection,
                "Failed to find a matching ALPN");
            goto Exit;
        }

        //
        // Decode and validate peer's QUIC transport parameters.
        //

        if (!FFI_mitls_find_custom_extension(
                TlsContext->IsServer,
                RawExtensions,
                RawExtensionsLength,
                TlsContext->QuicTpExtType,
                &ExtensionData,
                &ExtensionDataLength)) {
            QuicTraceEvent(
                TlsError,
                "[ tls][%p] ERROR, %s.",
                TlsContext->Connection,
                "Missing QUIC transport parameters");
            goto Exit;
        }

        if (!TlsContext->SecConfig->Callbacks.ReceiveTP(
                TlsContext->Connection,
                (uint16_t)ExtensionDataLength,
                ExtensionData)) {
            QuicTraceEvent(
                TlsError,
                "[ tls][%p] ERROR, %s.",
                TlsContext->Connection,
                "Failed to process the QUIC transport parameters");
            goto Exit;
        }
    }

    Action = TLS_nego_accept;

    if (TlsContext->IsServer) {

        //
        // Configure output extensions.
        //
        *CustomExtensions = TlsContext->Extensions;
        *CustomExtensionsLength = ARRAYSIZE(TlsContext->Extensions);
    }

Exit:

    return Action;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
size_t
MITLS_CALLCONV
CxPlatTlsOnCertFormat(
    void *Context,
    const void *SecContext,
    uint8_t Buffer[MAX_CHAIN_LEN]
    )
{
    CXPLAT_TLS* TlsContext = (CXPLAT_TLS*)Context;
    CXPLAT_DBG_ASSERT(TlsContext);
    CXPLAT_SEC_CONFIG* SecurityConfig = (CXPLAT_SEC_CONFIG*)SecContext;
    CXPLAT_DBG_ASSERT(SecurityConfig);

    QuicTraceLogConnVerbose(
        miTlsOnCertFormat,
        TlsContext->Connection,
        "OnCertFormat");

    CXPLAT_DBG_ASSERT(SecurityConfig->FormatLength <= MAX_CHAIN_LEN);
    if (SecurityConfig->FormatLength > MAX_CHAIN_LEN) {
        return 0;
    }

    memcpy(Buffer, SecurityConfig->FormatBuffer, SecurityConfig->FormatLength);
    return SecurityConfig->FormatLength;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
size_t
MITLS_CALLCONV
CxPlatTlsOnCertSign(
    void *Context,
    const void *SecContext,
    const mitls_signature_scheme SignatureAlgorithm,
    const uint8_t *CertListToBeSigned,
    size_t CertListToBeSignedLength,
    uint8_t *Signature
    )
{
    CXPLAT_TLS* TlsContext = (CXPLAT_TLS*)Context;
    CXPLAT_DBG_ASSERT(TlsContext);
    CXPLAT_SEC_CONFIG* SecurityConfig = (CXPLAT_SEC_CONFIG*)SecContext;
    CXPLAT_DBG_ASSERT(SecurityConfig);

    QuicTraceLogConnVerbose(
        miTlsOnCertSign,
        TlsContext->Connection,
        "OnCertSign");

    size_t SignatureLength = MAX_SIGNATURE_LEN;

    if (SecurityConfig->PrivateKey == NULL) {
        *Signature = 0;
        SignatureLength = 1;
    } else if (!CxPlatCertSign(
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
CxPlatTlsOnCertVerify(
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
    CXPLAT_TLS* TlsContext = (CXPLAT_TLS*)Context;
    CXPLAT_DBG_ASSERT(TlsContext);

    QuicTraceLogConnVerbose(
        miTlsOnCertVerify,
        TlsContext->Connection,
        "OnCertVerify");

    int Result = 0;
    QUIC_CERTIFICATE* Certificate = NULL;

    if (TlsContext->SecConfig->Flags & QUIC_CREDENTIAL_FLAG_NO_CERTIFICATE_VALIDATION) {
        QuicTraceLogConnWarning(
            miTlsCertValidationDisabled,
            TlsContext->Connection,
            "Certificate validation disabled!");
        goto Indicate; // Skip internal validation
    }

    Certificate =
        CxPlatCertParseChain(
            ChainBufferLength,
            ChainBuffer);
    if (Certificate == NULL) {
        QuicTraceEvent(
            TlsError,
            "[ tls][%p] ERROR, %s.",
            TlsContext->Connection,
            "CxPlatCertParseChain failed");
        goto Error;
    }

    if (!CxPlatCertValidateChain(
            Certificate,
            TlsContext->SNI,
            0)) {
        QuicTraceEvent(
            TlsError,
            "[ tls][%p] ERROR, %s.",
            TlsContext->Connection,
            "Cert chain validation failed");
        goto Error;
    }

    if (!CxPlatCertVerify(
            Certificate,
            SignatureAlgorithm,
            CertListToBeSigned,
            CertListToBeSignedLength,
            Signature,
            SignatureLength)) {
        QuicTraceEvent(
            TlsError,
            "[ tls][%p] ERROR, %s.",
            TlsContext->Connection,
            "CxPlatCertVerify failed");
        goto Error;
    }

Indicate:

    if ((TlsContext->SecConfig->Flags & QUIC_CREDENTIAL_FLAG_INDICATE_CERTIFICATE_RECEIVED) &&
        !TlsContext->SecConfig->Callbacks.CertificateReceived(
            TlsContext->Connection,
            NULL,
            0,
            0)) {
        QuicTraceEvent(
            TlsError,
            "[ tls][%p] ERROR, %s.",
            TlsContext->Connection,
            "Indicate certificate received failed");
        goto Error;
    }

    Result = 1;

Error:

    if (Certificate != NULL) {
        CxPlatCertFree(Certificate);
    }

    return Result;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
void
MITLS_CALLCONV
CxPlatTlsOnTicketReady(
    void *Context,
    const char *ServerNameIndication,
    const mitls_ticket *Ticket
    )
{
    CXPLAT_TLS* TlsContext = (CXPLAT_TLS*)Context;
    CXPLAT_DBG_ASSERT(TlsContext);

    QuicTraceLogConnVerbose(
        miTlsRecvNewSessionTicket,
        TlsContext->Connection,
        "Received new ticket. ticket_len:%u session_len:%u for %s",
        (uint32_t)Ticket->ticket_len,
        (uint32_t)Ticket->session_len,
        ServerNameIndication);

    CXPLAT_DBG_ASSERT(Ticket->ticket_len + Ticket->session_len <= UINT32_MAX);
    CXPLAT_DBG_ASSERT(Ticket->ticket_len + Ticket->session_len >= Ticket->ticket_len);

    uint32_t TotalSize =
        sizeof(CXPLAT_TLS_TICKET) +
        (uint32_t)(Ticket->ticket_len + Ticket->session_len);

    CXPLAT_TLS_TICKET *SerializedTicket = CXPLAT_ALLOC_NONPAGED(TotalSize, QUIC_POOL_PLATFORM_TMP_ALLOC);
    if (SerializedTicket == NULL) {
        QuicTraceEvent(
            AllocFailure,
            "Allocation of '%s' failed. (%llu bytes)",
            "CXPLAT_TLS_TICKET",
            TotalSize);
        return;
    }

    SerializedTicket->TicketLength = (uint32_t)Ticket->ticket_len;
    SerializedTicket->SessionLength = (uint32_t)Ticket->session_len;
    CxPlatCopyMemory(
        SerializedTicket->Buffer,
        Ticket->ticket,
        SerializedTicket->TicketLength);
    CxPlatCopyMemory(
        SerializedTicket->Buffer + SerializedTicket->TicketLength,
        Ticket->session,
        SerializedTicket->SessionLength);

    (void)TlsContext->SecConfig->Callbacks.ReceiveTicket(
        TlsContext->Connection,
        TotalSize,
        (uint8_t*)SerializedTicket);

    CXPLAT_FREE(SerializedTicket, QUIC_POOL_PLATFORM_TMP_ALLOC);
}

_IRQL_requires_max_(PASSIVE_LEVEL)
QUIC_STATUS
CxPlatTlsParamSet(
    _In_ CXPLAT_TLS* TlsContext,
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
CxPlatTlsParamGet(
    _In_ CXPLAT_TLS* TlsContext,
    _In_ uint32_t Param,
    _Inout_ uint32_t* BufferLength,
    _Inout_updates_bytes_opt_(*BufferLength)
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

typedef struct CXPLAT_KEY {
    CXPLAT_AEAD_TYPE Aead;
    uint8_t Key[32];
} CXPLAT_KEY;

typedef struct CXPLAT_HASH {
    CXPLAT_HASH_TYPE Type;
    uint32_t SaltLength;
    uint8_t Salt[0];
} CXPLAT_HASH;

typedef struct CXPLAT_HP_KEY {
    CXPLAT_AEAD_TYPE Aead;
    union {
        uint8_t case_chacha20[32];
        EverCrypt_aes128_key case_aes128;
        EverCrypt_aes256_key case_aes256;
    };
} CXPLAT_HP_KEY;

Spec_Hash_Definitions_hash_alg
HashTypeToEverCrypt(
    CXPLAT_HASH_TYPE Type
) {
    return
        (Spec_Hash_Definitions_hash_alg)
            (Spec_Hash_Definitions_SHA2_256 + Type);
}

#ifdef DEBUG
void
CxPlatTlsLogSecret(
    _In_z_ const char* const Prefix,
    _In_reads_(Length)
        const uint8_t* const Secret,
    _In_ uint32_t Length
    )
{
    #define HEX_TO_CHAR(x) ((x) > 9 ? ('a' + ((x) - 10)) : '0' + (x))
    char SecretStr[256 + 1] = {0};
    CXPLAT_DBG_ASSERT(Length * 2 < sizeof(SecretStr));
    for (uint8_t i = 0; i < Length; i++) {
        SecretStr[i*2]     = HEX_TO_CHAR(Secret[i] >> 4);
        SecretStr[i*2 + 1] = HEX_TO_CHAR(Secret[i] & 0xf);
    }
    QuicTraceLogVerbose(
        miTlsLogSecret,
        "[ tls] %s[%u]: %s",
        Prefix,
        Length,
        SecretStr);
}
#else
#define CxPlatTlsLogSecret(Prefix, Secret, Length) UNREFERENCED_PARAMETER(Prefix)
#endif

_IRQL_requires_max_(PASSIVE_LEVEL)
void
CxPlatHkdfFormatLabel(
    _In_z_ const char* const Label,
    _In_ uint16_t HashLength,
    _Out_writes_all_(5 + CXPLAT_HKDF_PREFIX_LEN + strlen(Label))
        uint8_t* const Data,
    _Inout_ uint32_t* const DataLength
    )
{
    CXPLAT_DBG_ASSERT(strlen(Label) <= UINT8_MAX - CXPLAT_HKDF_PREFIX_LEN);
    uint8_t LabelLength = (uint8_t)strlen(Label);

    Data[0] = HashLength >> 8;
    Data[1] = HashLength & 0xff;
    Data[2] = CXPLAT_HKDF_PREFIX_LEN + LabelLength;
    memcpy(Data + 3, CXPLAT_HKDF_PREFIX, CXPLAT_HKDF_PREFIX_LEN);
    memcpy(Data + 3 + CXPLAT_HKDF_PREFIX_LEN, Label, LabelLength);
    Data[3 + CXPLAT_HKDF_PREFIX_LEN + LabelLength] = 0;
    *DataLength = 3 + CXPLAT_HKDF_PREFIX_LEN + LabelLength + 1;

    Data[*DataLength] = 0x1;
    *DataLength += 1;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
QUIC_STATUS
CxPlatHkdfExpandLabel(
    _In_ CXPLAT_HASH* Hash,
    _In_z_ const char* const Label,
    _In_ uint16_t KeyLength,
    _In_ uint32_t OutputLength, // Writes CxPlatHashLength(HashType) bytes.
    _Out_writes_all_(OutputLength)
        uint8_t* const Output
    )
{
    uint8_t LabelBuffer[64];
    uint32_t LabelLength = sizeof(LabelBuffer);

    _Analysis_assume_(strlen(Label) <= 23);
    CxPlatHkdfFormatLabel(Label, KeyLength, LabelBuffer, &LabelLength);

    return
        CxPlatHashCompute(
            Hash,
            LabelBuffer,
            LabelLength,
            OutputLength,
            Output);
}

_IRQL_requires_max_(PASSIVE_LEVEL)
QUIC_STATUS
CxPlatTlsDeriveInitialSecrets(
    _In_reads_(CXPLAT_VERSION_SALT_LENGTH)
        const uint8_t* const Salt,
    _In_reads_(CIDLength)
        const uint8_t* const CID,
    _In_ uint8_t CIDLength,
    _Out_ CXPLAT_SECRET *ClientInitial,
    _Out_ CXPLAT_SECRET *ServerInitial
    )
{
    QUIC_STATUS Status;
    CXPLAT_HASH* InitialHash = NULL;
    CXPLAT_HASH* DerivedHash = NULL;
    uint8_t InitialSecret[CXPLAT_HASH_SHA256_SIZE];

    CxPlatTlsLogSecret("init cid", CID, CIDLength);

    Status =
        CxPlatHashCreate(
            CXPLAT_HASH_SHA256,
            Salt,
            CXPLAT_VERSION_SALT_LENGTH,
            &InitialHash);
    if (QUIC_FAILED(Status)) {
        goto Error;
    }

    //
    // Extract secret for client and server secret expansion.
    //
    Status =
        CxPlatHashCompute(
            InitialHash,
            CID,
            CIDLength,
            sizeof(InitialSecret),
            InitialSecret);
    if (QUIC_FAILED(Status)) {
        goto Error;
    }

    CxPlatTlsLogSecret("init secret", InitialSecret, sizeof(InitialSecret));

    //
    // Create hash for client and server secret expansion.
    //
    Status =
        CxPlatHashCreate(
            CXPLAT_HASH_SHA256,
            InitialSecret,
            sizeof(InitialSecret),
            &DerivedHash);
    if (QUIC_FAILED(Status)) {
        goto Error;
    }

    //
    // Expand client secret.
    //
    ClientInitial->Hash = CXPLAT_HASH_SHA256;
    ClientInitial->Aead = CXPLAT_AEAD_AES_128_GCM;
    Status =
        CxPlatHkdfExpandLabel(
            DerivedHash,
            "client in",
            sizeof(InitialSecret),
            CXPLAT_HASH_SHA256_SIZE,
            ClientInitial->Secret);
    if (QUIC_FAILED(Status)) {
        goto Error;
    }

    //
    // Expand server secret.
    //
    ServerInitial->Hash = CXPLAT_HASH_SHA256;
    ServerInitial->Aead = CXPLAT_AEAD_AES_128_GCM;
    Status =
        CxPlatHkdfExpandLabel(
            DerivedHash,
            "server in",
            sizeof(InitialSecret),
            CXPLAT_HASH_SHA256_SIZE,
            ServerInitial->Secret);
    if (QUIC_FAILED(Status)) {
        goto Error;
    }

Error:

    CxPlatHashFree(InitialHash);
    CxPlatHashFree(DerivedHash);

    RtlSecureZeroMemory(InitialSecret, sizeof(InitialSecret));

    return Status;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
QUIC_STATUS
QuicPacketKeyDerive(
    _In_ QUIC_PACKET_KEY_TYPE KeyType,
    _In_ const CXPLAT_SECRET* const Secret,
    _In_z_ const char* const SecretName,
    _In_ BOOLEAN CreateHpKey,
    _Out_ QUIC_PACKET_KEY **NewKey
    )
{
    const uint16_t SecretLength = CxPlatHashLength(Secret->Hash);
    const uint16_t KeyLength = CxPlatKeyLength(Secret->Aead);

    CXPLAT_DBG_ASSERT(SecretLength >= KeyLength);
    CXPLAT_DBG_ASSERT(SecretLength >= CXPLAT_IV_LENGTH);
    CXPLAT_DBG_ASSERT(SecretLength <= CXPLAT_HASH_MAX_SIZE);

    CxPlatTlsLogSecret(SecretName, Secret->Secret, SecretLength);

    const uint16_t PacketKeyLength =
        sizeof(QUIC_PACKET_KEY) +
        (KeyType == QUIC_PACKET_KEY_1_RTT ? sizeof(CXPLAT_SECRET) : 0);
    QUIC_PACKET_KEY *Key = CXPLAT_ALLOC_NONPAGED(PacketKeyLength, QUIC_POOL_TLS_PACKETKEY);
    if (Key == NULL) {
        QuicTraceEvent(
            AllocFailure,
            "Allocation of '%s' failed. (%llu bytes)",
            "QUIC_PACKET_KEY",
            PacketKeyLength);
        return QUIC_STATUS_OUT_OF_MEMORY;
    }
    CxPlatZeroMemory(Key, sizeof(QUIC_PACKET_KEY));
    Key->Type = KeyType;

    CXPLAT_HASH* Hash = NULL;
    uint8_t Temp[CXPLAT_HASH_MAX_SIZE];

    QUIC_STATUS Status =
        CxPlatHashCreate(
            Secret->Hash,
            Secret->Secret,
            SecretLength,
            &Hash);
    if (QUIC_FAILED(Status)) {
        goto Error;
    }

    Status =
        CxPlatHkdfExpandLabel(
            Hash,
            "quic iv",
            CXPLAT_IV_LENGTH,
            SecretLength,
            Temp);
    if (QUIC_FAILED(Status)) {
        goto Error;
    }

    memcpy(Key->Iv, Temp, CXPLAT_IV_LENGTH);
    CxPlatTlsLogSecret("static iv", Key->Iv, CXPLAT_IV_LENGTH);

    Status =
        CxPlatHkdfExpandLabel(
            Hash,
            "quic key",
            KeyLength,
            SecretLength,
            Temp);
    if (QUIC_FAILED(Status)) {
        goto Error;
    }

    CxPlatTlsLogSecret("key", Temp, KeyLength);

    Status =
        CxPlatKeyCreate(
            Secret->Aead,
            Temp,
            &Key->PacketKey);
    if (QUIC_FAILED(Status)) {
        goto Error;
    }

    if (CreateHpKey) {
        Status =
            CxPlatHkdfExpandLabel(
                Hash,
                "quic hp",
                KeyLength,
                SecretLength,
                Temp);
        if (QUIC_FAILED(Status)) {
            goto Error;
        }

        CxPlatTlsLogSecret("hp", Temp, KeyLength);

        Status =
            CxPlatHpKeyCreate(
                Secret->Aead,
                Temp,
                &Key->HeaderKey);
        if (QUIC_FAILED(Status)) {
            goto Error;
        }
    }

    if (KeyType == QUIC_PACKET_KEY_1_RTT) {
        CxPlatCopyMemory(Key->TrafficSecret, Secret, sizeof(CXPLAT_SECRET));
    }

    *NewKey = Key;
    Key = NULL;

Error:

    QuicPacketKeyFree(Key);
    CxPlatHashFree(Hash);

    RtlSecureZeroMemory(Temp, sizeof(Temp));

    return Status;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
_When_(NewReadKey != NULL, _At_(*NewReadKey, __drv_allocatesMem(Mem)))
_When_(NewWriteKey != NULL, _At_(*NewWriteKey, __drv_allocatesMem(Mem)))
QUIC_STATUS
QuicPacketKeyCreateInitial(
    _In_ BOOLEAN IsServer,
    _In_reads_(CXPLAT_VERSION_SALT_LENGTH)
        const uint8_t* const Salt,  // Version Specific
    _In_ uint8_t CIDLength,
    _In_reads_(CIDLength)
        const uint8_t* const CID,
    _Out_opt_ QUIC_PACKET_KEY** NewReadKey,
    _Out_opt_ QUIC_PACKET_KEY** NewWriteKey
    )
{
    QUIC_STATUS Status;
    CXPLAT_SECRET ClientInitial, ServerInitial;
    QUIC_PACKET_KEY* ReadKey = NULL, *WriteKey = NULL;

    Status =
        CxPlatTlsDeriveInitialSecrets(
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
    _In_ CXPLAT_TLS* TlsContext,
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
        QuicTraceEvent(
            TlsError,
            "[ tls][%p] ERROR, %s.",
            TlsContext->Connection,
            "FFI_mitls_quic_get_record_key failed");
        goto Error;
    }

    const uint16_t PacketKeyLength =
        sizeof(QUIC_PACKET_KEY) +
        (KeyType == QUIC_PACKET_KEY_1_RTT ? sizeof(CXPLAT_SECRET) : 0);
    Key = CXPLAT_ALLOC_NONPAGED(PacketKeyLength, QUIC_POOL_TLS_PACKETKEY);
    if (Key == NULL) {
        QuicTraceEvent(
            AllocFailure,
            "Allocation of '%s' failed. (%llu bytes)",
            "QUIC_PACKET_KEY",
            PacketKeyLength);
        Result = FALSE;
        goto Error;
    }
    CxPlatZeroMemory(Key, sizeof(QUIC_PACKET_KEY));
    Key->Type = KeyType;

    if (QUIC_FAILED(
        CxPlatKeyCreate(
            (CXPLAT_AEAD_TYPE)RecordKey.alg,
            RecordKey.aead_key,
            &Key->PacketKey))) {
        Result = FALSE;
        goto Error;
    }
    CxPlatTlsLogSecret((rw == QUIC_Reader) ? "read key" : "write key", RecordKey.aead_key, CxPlatKeyLength((CXPLAT_AEAD_TYPE)RecordKey.alg));

    if (QUIC_FAILED(
        CxPlatHpKeyCreate(
            (CXPLAT_AEAD_TYPE)RecordKey.alg,
            RecordKey.pne_key,
            &Key->HeaderKey))) {
        Result = FALSE;
        goto Error;
    }
    CxPlatTlsLogSecret((rw == QUIC_Reader) ? "read hp" : "write hp", RecordKey.pne_key, CxPlatKeyLength((CXPLAT_AEAD_TYPE)RecordKey.alg));

    memcpy(Key->Iv, RecordKey.aead_iv, CXPLAT_IV_LENGTH);
    CxPlatTlsLogSecret("static iv", Key->Iv, CXPLAT_IV_LENGTH);
    if (KeyType == QUIC_PACKET_KEY_1_RTT) {
        quic_secret ClientReadSecret, ServerReadSecret;
        Result =
            FFI_mitls_quic_get_record_secrets(
                TlsContext->miTlsState,
                &ClientReadSecret,
                &ServerReadSecret);
        if (Result == FALSE) {
            QuicTraceEvent(
                TlsError,
                "[ tls][%p] ERROR, %s.",
                TlsContext->Connection,
                "FFI_mitls_quic_get_record_secrets failed");
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
            Key->TrafficSecret->Hash = CXPLAT_HASH_SHA256;
            break;
        case TLS_hash_SHA384:
            Key->TrafficSecret->Hash = CXPLAT_HASH_SHA384;
            break;
        case TLS_hash_SHA512:
            Key->TrafficSecret->Hash = CXPLAT_HASH_SHA512;
            break;
        default:
            QuicTraceEvent(
                TlsError,
                "[ tls][%p] ERROR, %s.",
                TlsContext->Connection,
                "Unsupported hash type");
            Result = FALSE;
            goto Error;
        }
        Key->TrafficSecret->Aead = (CXPLAT_AEAD_TYPE)CopySecret->ae;
        CxPlatCopyMemory(Key->TrafficSecret->Secret, CopySecret->secret, CXPLAT_HASH_MAX_SIZE);
    }

#ifdef CXPLAT_TLS_SECRETS_SUPPORT
    if (TlsContext->TlsSecrets != NULL) {
        switch (KeyType) {
        case QUIC_PACKET_KEY_1_RTT: {
            quic_secret ClientReadSecret, ServerReadSecret;
            if (FFI_mitls_quic_get_record_secrets(
                    TlsContext->miTlsState,
                    &ClientReadSecret,
                    &ServerReadSecret)) {
                TlsContext->TlsSecrets->SecretLength = (uint8_t)CxPlatHashLength(ServerReadSecret.hash - 3);
                memcpy(
                    TlsContext->TlsSecrets->ServerTrafficSecret0,
                    ServerReadSecret.secret,
                    TlsContext->TlsSecrets->SecretLength);
                TlsContext->TlsSecrets->IsSet.ServerTrafficSecret0 = TRUE;
                memcpy(
                    TlsContext->TlsSecrets->ClientTrafficSecret0,
                    ClientReadSecret.secret,
                    TlsContext->TlsSecrets->SecretLength);
                TlsContext->TlsSecrets->IsSet.ClientTrafficSecret0 = TRUE;
            }
            //
            // We're done with the TlsSecrets.
            //
            TlsContext->TlsSecrets = NULL;
            break;
        }
        default:
            //
            // miTls doesn't provide an interface to get the intermediate
            // traffic secrets, so only 1-RTT keys can be decrypted.
            //
            break;
        }
    }
#endif

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
        CxPlatKeyFree(Key->PacketKey);
        CxPlatHpKeyFree(Key->HeaderKey);
        if (Key->Type >= QUIC_PACKET_KEY_1_RTT) {
            RtlSecureZeroMemory(Key->TrafficSecret, sizeof(CXPLAT_SECRET));
        }
        CXPLAT_FREE(Key, QUIC_POOL_TLS_PACKETKEY);
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

    CXPLAT_HASH* Hash = NULL;
    CXPLAT_SECRET NewTrafficSecret;
    const uint16_t SecretLength = CxPlatHashLength(OldKey->TrafficSecret->Hash);

    QUIC_STATUS Status =
        CxPlatHashCreate(
            OldKey->TrafficSecret->Hash,
            OldKey->TrafficSecret->Secret,
            SecretLength,
            &Hash);
    if (QUIC_FAILED(Status)) {
        goto Error;
    }

    Status =
        CxPlatHkdfExpandLabel(
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

    RtlSecureZeroMemory(&NewTrafficSecret, sizeof(CXPLAT_SECRET));
    RtlSecureZeroMemory(OldKey->TrafficSecret, sizeof(CXPLAT_SECRET));

Error:

    CxPlatHashFree(Hash);

    return Status;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
QUIC_STATUS
CxPlatKeyCreate(
    _In_ CXPLAT_AEAD_TYPE AeadType,
    _When_(AeadType == CXPLAT_AEAD_AES_128_GCM, _In_reads_(16))
    _When_(AeadType == CXPLAT_AEAD_AES_256_GCM, _In_reads_(32))
    _When_(AeadType == CXPLAT_AEAD_AES_384_GCM, _In_reads_(48))
    _When_(AeadType == CXPLAT_AEAD_CHACHA20_POLY1305, _In_reads_(32))
        const uint8_t* const RawKey,
    _Out_ CXPLAT_KEY** NewKey
    )
{
    uint8_t KeyLength;
    switch (AeadType) {
    case CXPLAT_AEAD_AES_128_GCM:
        KeyLength = 16;
        break;
    case CXPLAT_AEAD_AES_256_GCM:
    case CXPLAT_AEAD_CHACHA20_POLY1305:
        KeyLength = 32;
        break;
    default:
        return QUIC_STATUS_NOT_SUPPORTED;
    }

    CXPLAT_KEY* Key = CXPLAT_ALLOC_NONPAGED(sizeof(CXPLAT_KEY), QUIC_POOL_TLS_KEY);
    if (Key == NULL) {
        QuicTraceEvent(
            AllocFailure,
            "Allocation of '%s' failed. (%llu bytes)",
            "CXPLAT_KEY",
            sizeof(CXPLAT_KEY));
        return QUIC_STATUS_OUT_OF_MEMORY;
    }

    Key->Aead = AeadType;
    memcpy(Key->Key, RawKey, KeyLength);

    *NewKey = Key;

    return QUIC_STATUS_SUCCESS;
}

_IRQL_requires_max_(DISPATCH_LEVEL)
void
CxPlatKeyFree(
    _In_opt_ CXPLAT_KEY* Key
    )
{
    if (Key) {
        CXPLAT_FREE(Key, QUIC_POOL_TLS_KEY);
    }
}

_IRQL_requires_max_(DISPATCH_LEVEL)
QUIC_STATUS
#pragma prefast(suppress: __WARNING_6262, "miTLS won't be shipped in product.")
CxPlatEncrypt(
    _In_ CXPLAT_KEY* Key,
    _In_reads_bytes_(CXPLAT_IV_LENGTH)
        const uint8_t* const Iv,
    _In_ uint16_t AuthDataLength,
    _In_reads_bytes_opt_(AuthDataLength)
        const uint8_t* const AuthData,
    _In_ uint16_t BufferLength,
    _When_(BufferLength > CXPLAT_ENCRYPTION_OVERHEAD, _Inout_updates_bytes_(BufferLength))
    _When_(BufferLength <= CXPLAT_ENCRYPTION_OVERHEAD, _Out_writes_bytes_(BufferLength))
        uint8_t* Buffer
    )
{
    CXPLAT_DBG_ASSERT(CXPLAT_ENCRYPTION_OVERHEAD <= BufferLength);
    uint16_t PlainTextLength = BufferLength - CXPLAT_ENCRYPTION_OVERHEAD;

    uint8_t Temp[CXPLAT_MAX_MTU];
    CXPLAT_FRE_ASSERT(BufferLength <= sizeof(Temp));

    if (Key->Aead == CXPLAT_AEAD_AES_128_GCM) {
        EverCrypt_aes128_gcm_encrypt(Key->Key, (uint8_t*)Iv, (uint8_t*)AuthData, AuthDataLength, Buffer, PlainTextLength, Temp, Temp+PlainTextLength);
    } else if (Key->Aead == CXPLAT_AEAD_AES_256_GCM) {
        EverCrypt_aes256_gcm_encrypt(Key->Key, (uint8_t*)Iv, (uint8_t*)AuthData, AuthDataLength, Buffer, PlainTextLength, Temp, Temp+PlainTextLength);
    } else if (Key->Aead == CXPLAT_AEAD_CHACHA20_POLY1305) {
        EverCrypt_Chacha20Poly1305_aead_encrypt(Key->Key, (uint8_t*)Iv, AuthDataLength, (uint8_t*)AuthData, PlainTextLength, Buffer, Temp, Temp+PlainTextLength);
    } else {
        CXPLAT_FRE_ASSERT(FALSE);
        return QUIC_STATUS_NOT_SUPPORTED;
    }

    memcpy(Buffer, Temp, BufferLength);

    return QUIC_STATUS_SUCCESS;
}

_IRQL_requires_max_(DISPATCH_LEVEL)
QUIC_STATUS
#pragma prefast(suppress: __WARNING_6262, "miTLS won't be shipped in product.")
CxPlatDecrypt(
    _In_ CXPLAT_KEY* Key,
    _In_reads_bytes_(CXPLAT_IV_LENGTH)
        const uint8_t* const Iv,
    _In_ uint16_t AuthDataLength,
    _In_reads_bytes_opt_(AuthDataLength)
        const uint8_t* const AuthData,
    _In_ uint16_t BufferLength,
    _Inout_updates_bytes_(BufferLength)
        uint8_t* Buffer
    )
{
    CXPLAT_DBG_ASSERT(CXPLAT_ENCRYPTION_OVERHEAD <= BufferLength);
    uint16_t PlainTextLength = BufferLength - CXPLAT_ENCRYPTION_OVERHEAD;

    uint8_t Temp[CXPLAT_MAX_MTU];
    CXPLAT_FRE_ASSERT(BufferLength <= sizeof(Temp));

    int r = 0;
    if (Key->Aead == CXPLAT_AEAD_AES_128_GCM) {
        r = EverCrypt_aes128_gcm_decrypt(Key->Key, (uint8_t*)Iv, (uint8_t*)AuthData, AuthDataLength, Temp, PlainTextLength, Buffer, Buffer+PlainTextLength);
    } else if (Key->Aead == CXPLAT_AEAD_AES_256_GCM) {
        r = EverCrypt_aes256_gcm_decrypt(Key->Key, (uint8_t*)Iv, (uint8_t*)AuthData, AuthDataLength, Temp, PlainTextLength, Buffer, Buffer+PlainTextLength);
    } else if (Key->Aead == CXPLAT_AEAD_CHACHA20_POLY1305) {
        r = EverCrypt_Chacha20Poly1305_aead_decrypt(Key->Key, (uint8_t*)Iv, AuthDataLength, (uint8_t*)AuthData, PlainTextLength, Temp, Buffer, Buffer+PlainTextLength);
    } else {
        CXPLAT_FRE_ASSERT(FALSE);
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
CxPlatHpKeyCreate(
    _In_ CXPLAT_AEAD_TYPE AeadType,
    _When_(AeadType == CXPLAT_AEAD_AES_128_GCM, _In_reads_(16))
    _When_(AeadType == CXPLAT_AEAD_AES_256_GCM, _In_reads_(32))
    _When_(AeadType == CXPLAT_AEAD_CHACHA20_POLY1305, _In_reads_(32))
        const uint8_t* const RawKey,
    _Out_ CXPLAT_HP_KEY** NewKey
    )
{
    uint8_t KeyLength;
    switch (AeadType) {
    case CXPLAT_AEAD_AES_128_GCM:
        KeyLength = 16;
        break;
    case CXPLAT_AEAD_AES_256_GCM:
    case CXPLAT_AEAD_CHACHA20_POLY1305:
        KeyLength = 32;
        break;
    default:
        return QUIC_STATUS_NOT_SUPPORTED;
    }

    CXPLAT_HP_KEY* Key = CXPLAT_ALLOC_NONPAGED(sizeof(CXPLAT_HP_KEY), QUIC_POOL_TLS_HP_KEY);
    if (Key == NULL) {
        QuicTraceEvent(
            AllocFailure,
            "Allocation of '%s' failed. (%llu bytes)",
            "CXPLAT_HP_KEY",
            sizeof(CXPLAT_HP_KEY));
        return QUIC_STATUS_OUT_OF_MEMORY;
    }

    Key->Aead = AeadType;
    if (AeadType == CXPLAT_AEAD_AES_128_GCM) {
        Key->case_aes128 = EverCrypt_aes128_create((uint8_t*)RawKey);
    } else if (AeadType == CXPLAT_AEAD_AES_256_GCM) {
        Key->case_aes256 = EverCrypt_aes256_create((uint8_t*)RawKey);
    } else if (AeadType == CXPLAT_AEAD_CHACHA20_POLY1305) {
        memcpy(Key->case_chacha20, RawKey, 32);
    }

    *NewKey = Key;

    return QUIC_STATUS_SUCCESS;
}

_IRQL_requires_max_(DISPATCH_LEVEL)
void
CxPlatHpKeyFree(
    _In_opt_ CXPLAT_HP_KEY* Key
    )
{
    if (Key) {
        if (Key->Aead == CXPLAT_AEAD_AES_128_GCM) {
            EverCrypt_aes128_free(Key->case_aes128);
        } else if (Key->Aead == CXPLAT_AEAD_AES_256_GCM) {
            EverCrypt_aes256_free(Key->case_aes256);
        }
        CXPLAT_FREE(Key, QUIC_POOL_TLS_HP_KEY);
    }
}

_IRQL_requires_max_(DISPATCH_LEVEL)
QUIC_STATUS
CxPlatHpComputeMask(
    _In_ CXPLAT_HP_KEY* Key,
    _In_ uint8_t BatchSize,
    _In_reads_bytes_(CXPLAT_HP_SAMPLE_LENGTH * BatchSize)
        const uint8_t* const _Cipher,
    _Out_writes_bytes_(CXPLAT_HP_SAMPLE_LENGTH * BatchSize)
        uint8_t* Mask
    )
{
    uint8_t* Cipher = (uint8_t*)_Cipher;
    for (uint8_t i = 0; i < BatchSize; ++i) {
        if (Key->Aead == CXPLAT_AEAD_AES_128_GCM) {
            EverCrypt_aes128_compute(Key->case_aes128, Cipher, Mask);
        } else if (Key->Aead == CXPLAT_AEAD_AES_256_GCM) {
            EverCrypt_aes256_compute(Key->case_aes256, Cipher, Mask);
        } else if (Key->Aead == CXPLAT_AEAD_CHACHA20_POLY1305) {
            static const uint8_t zero[] = {0, 0, 0, 0, 0};
            uint32_t ctr = Cipher[0] + (Cipher[1] << 8) + (Cipher[2] << 16) + (Cipher[3] << 24);
            EverCrypt_Cipher_chacha20(sizeof(zero), Mask, (uint8_t*)zero, (uint8_t*)Key->case_chacha20, Cipher+4, ctr);
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
CxPlatHashCreate(
    _In_ CXPLAT_HASH_TYPE HashType,
    _In_reads_(SaltLength)
        const uint8_t* const Salt,
    _In_ uint32_t SaltLength,
    _Out_ CXPLAT_HASH** NewHash
    )
{
    switch (HashType) {
    case CXPLAT_HASH_SHA256:
    case CXPLAT_HASH_SHA384:
    case CXPLAT_HASH_SHA512:
        break;
    default:
        return QUIC_STATUS_NOT_SUPPORTED;
    }

    CXPLAT_HASH* Hash = CXPLAT_ALLOC_NONPAGED(sizeof(CXPLAT_HASH) + SaltLength, QUIC_POOL_TLS_HASH);
    if (Hash == NULL) {
        QuicTraceEvent(
            AllocFailure,
            "Allocation of '%s' failed. (%llu bytes)",
            "CXPLAT_HASH",
            sizeof(CXPLAT_HASH) + SaltLength);
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
CxPlatHashFree(
    _In_opt_ CXPLAT_HASH* Hash
    )
{
    if (Hash) {
        CXPLAT_FREE(Hash, QUIC_POOL_TLS_HASH);
    }
}

_IRQL_requires_max_(DISPATCH_LEVEL)
QUIC_STATUS
CxPlatHashCompute(
    _In_ CXPLAT_HASH* Hash,
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
