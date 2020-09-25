/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.

Abstract:

    Stub TLS Implementation for QUIC

--*/

#include "platform_internal.h"
#ifdef QUIC_CLOG
#include "tls_stub.c.clog.h"
#endif

uint16_t QuicTlsTPHeaderSize = 0;

#define TLS1_PROTOCOL_VERSION 0x0301
#define TLS_MESSAGE_HEADER_LENGTH 4
#define TLS_RANDOM_LENGTH 32
#define TLS_SESSION_ID_LENGTH 32

typedef enum eTlsHandshakeType {
    TlsHandshake_ClientHello = 0x01
} eTlsHandshakeType;

typedef enum eTlsExtensions {
    TlsExt_ServerName = 0x00,
    TlsExt_AppProtocolNegotiation = 0x10,
    TlsExt_SessionTicket = 0x23,
    TlsExt_QuicTransportParameters = 0xffa5,
} eTlsExtensions;

typedef enum eSniNameType {
    TlsExt_Sni_NameType_HostName = 0
} eSniNameType;

typedef enum QUIC_FAKE_TLS_MESSAGE_TYPE {

    QUIC_TLS_MESSAGE_INVALID,
    QUIC_TLS_MESSAGE_CLIENT_INITIAL,
    QUIC_TLS_MESSAGE_CLIENT_HANDSHAKE,
    QUIC_TLS_MESSAGE_SERVER_INITIAL,
    QUIC_TLS_MESSAGE_SERVER_HANDSHAKE,
    QUIC_TLS_MESSAGE_TICKET,
    QUIC_TLS_MESSAGE_MAX

} QUIC_FAKE_TLS_MESSAGE_TYPE;

QUIC_STATIC_ASSERT(
    (uint32_t)QUIC_TLS_MESSAGE_CLIENT_INITIAL == (uint32_t)TlsHandshake_ClientHello,
    "Stub need to fake client hello exactly");

const uint16_t MinMessageLengths[] = {
    0,                              // QUIC_TLS_MESSAGE_INVALID
    0,                              // QUIC_TLS_MESSAGE_CLIENT_INITIAL (Dynamic)
    7 + 1,                          // QUIC_TLS_MESSAGE_CLIENT_HANDSHAKE
    7 + 1 + 32,                     // QUIC_TLS_MESSAGE_SERVER_INITIAL
    7 + 4 + 32,                     // QUIC_TLS_MESSAGE_SERVER_HANDSHAKE
    4                               // QUIC_TLS_MESSAGE_TICKET
};

static
uint16_t
TlsReadUint16(
    _In_reads_(2) const uint8_t* Buffer
    )
{
    return
        (((uint32_t)Buffer[0] << 8) +
          (uint32_t)Buffer[1]);
}

static
void
TlsWriteUint16(
    _Out_writes_all_(2) uint8_t* Buffer,
    _In_ uint16_t Value
    )
{
    Buffer[0] = (uint8_t)(Value >> 8);
    Buffer[1] = (uint8_t)Value;
}

static
uint32_t
TlsReadUint24(
    _In_reads_(3) const uint8_t* Buffer
    )
{
    return
        (((uint32_t)Buffer[0] << 16) +
         ((uint32_t)Buffer[1] << 8) +
          (uint32_t)Buffer[2]);
}

static
void
TlsWriteUint24(
    _Out_writes_all_(3) uint8_t* Buffer,
    _In_ uint32_t Value
    )
{
    Buffer[0] = (uint8_t)(Value >> 16);
    Buffer[1] = (uint8_t)(Value >> 8);
    Buffer[2] = (uint8_t)Value;
}

#pragma pack(push)
#pragma pack(1)

typedef struct QUIC_TLS_SNI_EXT {
    uint8_t ExtType[2];                 // TlsExt_ServerName
    uint8_t ExtLen[2];
    uint8_t ListLen[2];
    uint8_t NameType;                   // TlsExt_Sni_NameType_HostName
    uint8_t NameLength[2];
    uint8_t Name[0];
} QUIC_TLS_SNI_EXT;

typedef struct QUIC_TLS_ALPN_EXT {
    uint8_t ExtType[2];                 // TlsExt_AppProtocolNegotiation
    uint8_t ExtLen[2];
    uint8_t AlpnListLength[2];
    uint8_t AlpnList[0];
} QUIC_TLS_ALPN_EXT;

typedef struct QUIC_TLS_SESSION_TICKET_EXT {
    uint8_t ExtType[2];                 // TlsExt_SessionTicket
    uint8_t ExtLen[2];
    uint8_t Ticket[0];
} QUIC_TLS_SESSION_TICKET_EXT;

typedef struct QUIC_TLS_QUIC_TP_EXT {
    uint8_t ExtType[2];                 // TlsExt_QuicTransportParameters
    uint8_t ExtLen[2];
    uint8_t TP[0];
} QUIC_TLS_QUIC_TP_EXT;

typedef struct QUIC_TLS_CLIENT_HELLO { // All multi-byte fields are Network Byte Order
    uint8_t Version[2];
    uint8_t Random[TLS_RANDOM_LENGTH];
    uint8_t SessionIdLength;            // 0
    uint8_t CipherSuiteLength[2];
    uint8_t CompressionMethodLength;    // 1
    uint8_t CompressionMethod;

    uint8_t ExtListLength[2];
    uint8_t ExtList[0];
    // QUIC_TLS_SNI_EXT
    // QUIC_TLS_ALPN_EXT
    // QUIC_TLS_SESSION_TICKET_EXT
    // QUIC_TLS_QUIC_TP_EXT
} QUIC_TLS_CLIENT_HELLO;

typedef struct QUIC_FAKE_TLS_MESSAGE {
    uint8_t Type;
    uint8_t Length[3]; // Uses TLS 24-bit length encoding
    union {
        QUIC_TLS_CLIENT_HELLO CLIENT_INITIAL;
        struct {
            uint8_t Success;
        } CLIENT_HANDSHAKE;
        struct {
            uint8_t Success : 1;
            uint8_t EarlyDataAccepted : 1;
            uint8_t HandshakeSecret[32];
        } SERVER_INITIAL;
        struct {
            uint8_t OneRttSecret[32];
            uint16_t CertificateLength;
            uint16_t ExtListLength;
            uint8_t Certificate[0];
            // uint8_t ExtList[0];
            // QUIC_TLS_ALPN_EXT
            // QUIC_TLS_QUIC_TP_EXT
        } SERVER_HANDSHAKE;
        struct {
            uint8_t Ticket[0];
        } TICKET;
    };
} QUIC_FAKE_TLS_MESSAGE;

#pragma pack(pop)

typedef struct QUIC_KEY {
    uint64_t Secret;
} QUIC_KEY;

typedef struct QUIC_SEC_CONFIG {

    QUIC_CREDENTIAL_TYPE Type;
    QUIC_CREDENTIAL_FLAGS Flags;
    QUIC_CERTIFICATE* Certificate;
    uint16_t FormatLength;
    uint8_t FormatBuffer[SIZEOF_CERT_CHAIN_LIST_LENGTH];

} QUIC_SEC_CONFIG;

typedef struct QUIC_TLS {

    BOOLEAN IsServer : 1;
    BOOLEAN EarlyDataAttempted : 1;

    QUIC_FAKE_TLS_MESSAGE_TYPE LastMessageType; // Last message sent.

    QUIC_SEC_CONFIG* SecConfig;

    QUIC_CONNECTION* Connection;
    QUIC_TLS_RECEIVE_TP_CALLBACK_HANDLER ReceiveTPCallback;
    QUIC_TLS_RECEIVE_TICKET_CALLBACK_HANDLER ReceiveTicketCallback;

    uint16_t AlpnBufferLength;
    const uint8_t* AlpnBuffer;

    const char* SNI;

    const uint8_t* ResumptionTicketBuffer;
    uint32_t ResumptionTicketLength;

    const uint8_t* LocalTPBuffer;
    uint32_t LocalTPLength;

} QUIC_TLS;

char
GetTlsIdentifier(
    _In_ const QUIC_TLS* TlsContext
    )
{
    const char IDs[2] = { 'C', 'S' };
    return IDs[TlsContext->IsServer];
}

__drv_allocatesMem(Mem)
QUIC_PACKET_KEY*
QuicStubAllocKey(
    _In_ QUIC_PACKET_KEY_TYPE Type,
    _In_reads_(QUIC_AEAD_AES_256_GCM_SIZE)
        const uint8_t* Secret
    )
{
    size_t PacketKeySize =
        sizeof(QUIC_PACKET_KEY) +
        (Type == QUIC_PACKET_KEY_1_RTT ? sizeof(QUIC_SECRET) : 0);
    QUIC_PACKET_KEY *Key = QUIC_ALLOC_NONPAGED(PacketKeySize);
    QUIC_FRE_ASSERT(Key != NULL);
    QuicZeroMemory(Key, PacketKeySize);
    Key->Type = Type;
    QuicKeyCreate(QUIC_AEAD_AES_256_GCM, Secret, &Key->PacketKey);
    Key->HeaderKey = (QUIC_HP_KEY*)0x1;
    if (Type == QUIC_PACKET_KEY_1_RTT) {
        Key->TrafficSecret[0].Hash = QUIC_HASH_SHA256;
        Key->TrafficSecret[0].Aead = QUIC_AEAD_AES_256_GCM;
        QuicCopyMemory(Key->TrafficSecret[0].Secret, Secret, QUIC_AEAD_AES_256_GCM_SIZE);
    }
    return Key;
}

QUIC_STATUS
QuicTlsLibraryInitialize(
    void
    )
{
    return QUIC_STATUS_SUCCESS;
}

void
QuicTlsLibraryUninitialize(
    void
    )
{
}

_IRQL_requires_max_(PASSIVE_LEVEL)
QUIC_STATUS
QuicTlsSecConfigCreate(
    _In_ const QUIC_CREDENTIAL_CONFIG* CredConfig,
    _In_opt_ void* Context,
    _In_ QUIC_SEC_CONFIG_CREATE_COMPLETE_HANDLER CompletionHandler
    )
{
    if (CredConfig->Flags & QUIC_CREDENTIAL_FLAG_LOAD_ASYNCHRONOUS &&
        CredConfig->AsyncHandler == NULL) {
        return QUIC_STATUS_INVALID_PARAMETER;
    }

    if (CredConfig->Flags & QUIC_CREDENTIAL_FLAG_ENABLE_OCSP) {
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

    QUIC_STATUS Status = QUIC_STATUS_SUCCESS;

#pragma prefast(suppress: __WARNING_6014, "Memory is correctly freed (QuicTlsSecConfigDelete)")
    QUIC_SEC_CONFIG* SecurityConfig = QUIC_ALLOC_PAGED(sizeof(QUIC_SEC_CONFIG));
    if (SecurityConfig == NULL) {
        Status = QUIC_STATUS_OUT_OF_MEMORY;
        goto Error;
    }

    QuicZeroMemory(SecurityConfig, sizeof(QUIC_SEC_CONFIG));
    SecurityConfig->Type = CredConfig->Type;
    SecurityConfig->Flags = CredConfig->Flags;

    if (!(CredConfig->Flags & QUIC_CREDENTIAL_FLAG_CLIENT)) {
        if (CredConfig->Type != QUIC_CREDENTIAL_TYPE_NONE &&
            CredConfig->Type != QUIC_CREDENTIAL_TYPE_NULL) {
            Status = QuicCertCreate(CredConfig, &SecurityConfig->Certificate);
            if (QUIC_FAILED(Status)) {
                goto Error;
            }
        }

        SecurityConfig->FormatLength =
            (uint16_t)QuicCertFormat(
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
        QUIC_FREE(SecurityConfig);
    }

    return Status;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
void
QuicTlsSecConfigDelete(
    __drv_freesMem(ServerConfig) _Frees_ptr_ _In_
        QUIC_SEC_CONFIG* SecurityConfig
    )
{
    if (SecurityConfig->Type != QUIC_CREDENTIAL_TYPE_CERTIFICATE_CONTEXT) {
        QuicCertFree(SecurityConfig->Certificate);
    }
    QUIC_FREE(SecurityConfig);
}

_IRQL_requires_max_(PASSIVE_LEVEL)
QUIC_STATUS
QuicTlsInitialize(
    _In_ const QUIC_TLS_CONFIG* Config,
    _Inout_ QUIC_TLS_PROCESS_STATE* State,
    _Out_ QUIC_TLS** NewTlsContext
    )
{
    QUIC_STATUS Status;

    UNREFERENCED_PARAMETER(State);

    QUIC_TLS* TlsContext = QUIC_ALLOC_PAGED(sizeof(QUIC_TLS));
    if (TlsContext == NULL) {
        QuicTraceEvent(
            AllocFailure,
            "Allocation of '%s' failed. (%llu bytes)",
            "QUIC_TLS",
            sizeof(QUIC_TLS));
        Status = QUIC_STATUS_OUT_OF_MEMORY;
        goto Exit;
    }

    QuicZeroMemory(TlsContext, sizeof(QUIC_TLS));

    TlsContext->IsServer = Config->IsServer;
    TlsContext->AlpnBufferLength = Config->AlpnBufferLength;
    TlsContext->AlpnBuffer = Config->AlpnBuffer;
    TlsContext->LocalTPBuffer = Config->LocalTPBuffer;
    TlsContext->LocalTPLength = Config->LocalTPLength;
    TlsContext->SecConfig = Config->SecConfig;
    TlsContext->Connection = Config->Connection;
    TlsContext->ReceiveTPCallback = Config->ReceiveTPCallback;
    TlsContext->ReceiveTicketCallback = Config->ReceiveResumptionCallback;

    QuicTraceLogConnVerbose(
        StubTlsContextCreated,
        TlsContext->Connection,
        "TLS context Created");

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

        TlsContext->SNI = QUIC_ALLOC_PAGED(ServerNameLength + 1);
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
    }

    TlsContext->ResumptionTicketLength = Config->ResumptionTicketLength;
    TlsContext->ResumptionTicketBuffer = Config->ResumptionTicketBuffer;
    if (TlsContext->ResumptionTicketBuffer != NULL) {
        QuicTraceLogConnVerbose(
            StubTlsUsing0Rtt,
            TlsContext->Connection,
            "Using 0-RTT ticket.");
    }

    *NewTlsContext = TlsContext;
    Status = QUIC_STATUS_SUCCESS;

Error:

    if (QUIC_FAILED(Status)) {
        if (TlsContext->SNI) {
            QUIC_FREE(TlsContext->SNI);
        }
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
        QuicTraceLogConnVerbose(
            StubTlsContextCleaningUp,
            TlsContext->Connection,
            "Cleaning up");

        if (TlsContext->ResumptionTicketBuffer != NULL) {
            QUIC_FREE(TlsContext->ResumptionTicketBuffer);
        }

        if (TlsContext->SNI != NULL) {
            QUIC_FREE(TlsContext->SNI);
        }

        if (TlsContext->LocalTPBuffer != NULL) {
            QUIC_FREE(TlsContext->LocalTPBuffer);
        }

        QUIC_FREE(TlsContext);
    }
}

_IRQL_requires_max_(PASSIVE_LEVEL)
void
QuicTlsReset(
    _In_ QUIC_TLS* TlsContext
    )
{
    QuicTraceLogConnInfo(
        StubTlsContextReset,
        TlsContext->Connection,
        "Resetting TLS state");

    QUIC_FRE_ASSERT(TlsContext->IsServer == FALSE);
    TlsContext->LastMessageType = QUIC_TLS_MESSAGE_INVALID;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
void
QuicTlsServerProcess(
    _In_ QUIC_TLS* TlsContext,
    _Out_ QUIC_TLS_RESULT_FLAGS* ResultFlags,
    _Inout_ QUIC_TLS_PROCESS_STATE* State,
    _Inout_ uint32_t * BufferLength,
    _In_reads_bytes_(*BufferLength) const uint8_t * Buffer
    )
{
    uint16_t DrainLength = 0;

    QUIC_FRE_ASSERT(State->BufferLength < State->BufferAllocLength);
    __assume(State->BufferLength < State->BufferAllocLength);

    const QUIC_FAKE_TLS_MESSAGE* ClientMessage =
        (QUIC_FAKE_TLS_MESSAGE*)Buffer;
    QUIC_FAKE_TLS_MESSAGE* ServerMessage =
        (QUIC_FAKE_TLS_MESSAGE*)(State->Buffer + State->BufferLength);
    uint16_t MaxServerMessageLength =
        State->BufferAllocLength - State->BufferLength;

    switch (TlsContext->LastMessageType) {

    case QUIC_TLS_MESSAGE_INVALID: {
        QUIC_FRE_ASSERT(ClientMessage->Type == QUIC_TLS_MESSAGE_CLIENT_INITIAL);

        TlsContext->EarlyDataAttempted = FALSE;

        const uint8_t* ExtList = ClientMessage->CLIENT_INITIAL.ExtList;
        uint16_t ExtListLength = TlsReadUint16(ClientMessage->CLIENT_INITIAL.ExtListLength);
        while (ExtListLength > 0) {
            uint16_t ExtType = TlsReadUint16(ExtList);
            uint16_t ExtLength = TlsReadUint16(ExtList + 2);
            QUIC_FRE_ASSERT(ExtLength + 4 <= ExtListLength);

            switch (ExtType) {
            case TlsExt_ServerName: {
                const QUIC_TLS_SNI_EXT* SNI = (QUIC_TLS_SNI_EXT*)ExtList;
                uint16_t NameLength = TlsReadUint16(SNI->NameLength);
                if (NameLength != 0) {
                    TlsContext->SNI = QUIC_ALLOC_PAGED(NameLength + 1);
                    memcpy((char*)TlsContext->SNI, SNI->Name, NameLength);
                    ((char*)TlsContext->SNI)[NameLength] = 0;
                }
                break;
            }
            case TlsExt_AppProtocolNegotiation: {
                break; // Unused
            }
            case TlsExt_SessionTicket: {
                TlsContext->EarlyDataAttempted = TRUE;
                if (TlsContext->ReceiveTicketCallback(
                        TlsContext->Connection,
                        ExtLength,
                        ((QUIC_TLS_SESSION_TICKET_EXT*)ExtList)->Ticket)) {
                    State->SessionResumed = TRUE;
                    State->EarlyDataState = QUIC_TLS_EARLY_DATA_ACCEPTED;
                } else {
                    State->SessionResumed = FALSE;
                    State->EarlyDataState = QUIC_TLS_EARLY_DATA_REJECTED;
                }
                break;
            }
            case TlsExt_QuicTransportParameters: {
                const QUIC_TLS_QUIC_TP_EXT* QuicTP = (QUIC_TLS_QUIC_TP_EXT*)ExtList;
                TlsContext->ReceiveTPCallback(
                    TlsContext->Connection,
                    ExtLength,
                    QuicTP->TP);
                break;
            }
            default:
                QUIC_FRE_ASSERT(FALSE);
                break;
            }

            ExtList += ExtLength + 4;
            ExtListLength -= ExtLength + 4;
        }

        const QUIC_SEC_CONFIG* SecurityConfig = TlsContext->SecConfig;
        QUIC_FRE_ASSERT(SecurityConfig != NULL);

        if (MaxServerMessageLength < MinMessageLengths[QUIC_TLS_MESSAGE_SERVER_INITIAL]) {
            *ResultFlags |= QUIC_TLS_RESULT_ERROR;
            break;
        }

        const uint16_t SignAlgo = 0x0804;
        uint16_t SelectedSignAlgo;

        if (!QuicCertSelect(
                SecurityConfig->Certificate,
                &SignAlgo,
                1,
                &SelectedSignAlgo)) {
            QuicTraceEvent(
                TlsError,
                "[ tls][%p] ERROR, %s.",
                TlsContext->Connection,
                "QuicCertSelect failed");
            *ResultFlags |= QUIC_TLS_RESULT_ERROR;
            break;
        }

        uint8_t HandshakeSecret[QUIC_AEAD_AES_256_GCM_SIZE];
        QuicRandom(sizeof(HandshakeSecret), HandshakeSecret);

        uint16_t MessageLength = MinMessageLengths[QUIC_TLS_MESSAGE_SERVER_INITIAL];
        TlsWriteUint24(ServerMessage->Length, MessageLength - 4);
        ServerMessage->Type = QUIC_TLS_MESSAGE_SERVER_INITIAL;
        ServerMessage->SERVER_INITIAL.EarlyDataAccepted =
            State->EarlyDataState == QUIC_TLS_EARLY_DATA_ACCEPTED;
        memcpy(ServerMessage->SERVER_INITIAL.HandshakeSecret, HandshakeSecret, QUIC_AEAD_AES_256_GCM_SIZE);

        State->BufferLength = MessageLength;
        State->BufferTotalLength = MessageLength;
        State->BufferOffsetHandshake = State->BufferTotalLength;

        ServerMessage =
            (QUIC_FAKE_TLS_MESSAGE*)(State->Buffer + State->BufferLength);
        MaxServerMessageLength =
            State->BufferAllocLength - State->BufferLength;

        if (MaxServerMessageLength < MinMessageLengths[QUIC_TLS_MESSAGE_SERVER_HANDSHAKE] + SecurityConfig->FormatLength + TlsContext->LocalTPLength) {
            *ResultFlags |= QUIC_TLS_RESULT_ERROR;
            break;
        }

        if (State->EarlyDataState == QUIC_TLS_EARLY_DATA_ACCEPTED) {
            *ResultFlags |= QUIC_TLS_RESULT_EARLY_DATA_ACCEPT;
            uint8_t Secret[QUIC_AEAD_AES_256_GCM_SIZE];
            QuicZeroMemory(Secret, sizeof(Secret));
            State->ReadKeys[QUIC_PACKET_KEY_0_RTT] = QuicStubAllocKey(QUIC_PACKET_KEY_0_RTT, Secret);
        }

        *ResultFlags |= QUIC_TLS_RESULT_READ_KEY_UPDATED;
        State->ReadKey = QUIC_PACKET_KEY_HANDSHAKE;
        State->ReadKeys[QUIC_PACKET_KEY_HANDSHAKE] = QuicStubAllocKey(QUIC_PACKET_KEY_HANDSHAKE, HandshakeSecret);

        *ResultFlags |= QUIC_TLS_RESULT_WRITE_KEY_UPDATED;
        State->WriteKey = QUIC_PACKET_KEY_HANDSHAKE;
        State->WriteKeys[QUIC_PACKET_KEY_HANDSHAKE] = QuicStubAllocKey(QUIC_PACKET_KEY_HANDSHAKE, HandshakeSecret);

        uint8_t OneRttSecret[QUIC_AEAD_AES_256_GCM_SIZE];
        QuicRandom(sizeof(OneRttSecret), OneRttSecret);

        MessageLength =
            MinMessageLengths[QUIC_TLS_MESSAGE_SERVER_HANDSHAKE] +
            SecurityConfig->FormatLength +
            6 + TlsContext->AlpnBufferLength +
            4 + (uint16_t)TlsContext->LocalTPLength;
        TlsWriteUint24(ServerMessage->Length, MessageLength - 4);
        ServerMessage->Type = QUIC_TLS_MESSAGE_SERVER_HANDSHAKE;
        memcpy(ServerMessage->SERVER_HANDSHAKE.OneRttSecret, OneRttSecret, QUIC_AEAD_AES_256_GCM_SIZE);
        ServerMessage->SERVER_HANDSHAKE.CertificateLength = SecurityConfig->FormatLength;
        memcpy(ServerMessage->SERVER_HANDSHAKE.Certificate, SecurityConfig->FormatBuffer, SecurityConfig->FormatLength);

        ExtListLength = 0;

        QUIC_FRE_ASSERT(State->NegotiatedAlpn != NULL);

        QUIC_TLS_ALPN_EXT* ALPN =
            (QUIC_TLS_ALPN_EXT*)
            (ServerMessage->SERVER_HANDSHAKE.Certificate +
             SecurityConfig->FormatLength + ExtListLength);
        TlsWriteUint16(ALPN->ExtType, TlsExt_AppProtocolNegotiation);
        TlsWriteUint16(ALPN->ExtLen, 3 + State->NegotiatedAlpn[0]);
        TlsWriteUint16(ALPN->AlpnListLength, 1 + State->NegotiatedAlpn[0]);
        memcpy(ALPN->AlpnList, State->NegotiatedAlpn, State->NegotiatedAlpn[0]+1);
        ExtListLength += 7 + State->NegotiatedAlpn[0];

        QUIC_TLS_QUIC_TP_EXT* QuicTP =
            (QUIC_TLS_QUIC_TP_EXT*)
            (ServerMessage->SERVER_HANDSHAKE.Certificate +
             SecurityConfig->FormatLength + ExtListLength);
        TlsWriteUint16(QuicTP->ExtType, TlsExt_QuicTransportParameters);
        TlsWriteUint16(QuicTP->ExtLen, (uint16_t)TlsContext->LocalTPLength);
        memcpy(QuicTP->TP, TlsContext->LocalTPBuffer, TlsContext->LocalTPLength);
        ExtListLength += 4 + (uint16_t)TlsContext->LocalTPLength;

        ServerMessage->SERVER_HANDSHAKE.ExtListLength = ExtListLength;

        State->BufferLength += MessageLength;
        State->BufferTotalLength += MessageLength;
        State->BufferOffset1Rtt = State->BufferTotalLength;
        *ResultFlags |= QUIC_TLS_RESULT_DATA;

        *ResultFlags |= QUIC_TLS_RESULT_WRITE_KEY_UPDATED;
        State->WriteKey = QUIC_PACKET_KEY_1_RTT;
        State->WriteKeys[QUIC_PACKET_KEY_1_RTT] = QuicStubAllocKey(QUIC_PACKET_KEY_1_RTT, OneRttSecret);

        DrainLength = (uint16_t)TlsReadUint24(ClientMessage->Length) + 4;

        TlsContext->LastMessageType = QUIC_TLS_MESSAGE_SERVER_HANDSHAKE;
        break;
    }

    case QUIC_TLS_MESSAGE_SERVER_HANDSHAKE: {
        if (ClientMessage->Type == QUIC_TLS_MESSAGE_CLIENT_HANDSHAKE) {

            if (ClientMessage->CLIENT_HANDSHAKE.Success == FALSE) {
                QuicTraceEvent(
                    TlsError,
                    "[ tls][%p] ERROR, %s.",
                    TlsContext->Connection,
                    "Failure client finish");
                *ResultFlags |= QUIC_TLS_RESULT_ERROR;
                break;
            }

            *ResultFlags |= QUIC_TLS_RESULT_COMPLETE;

            QuicTraceLogConnInfo(
                StubTlsHandshakeComplete,
                TlsContext->Connection,
                "Handshake complete");

            TlsContext->SecConfig = NULL;

            *ResultFlags |= QUIC_TLS_RESULT_READ_KEY_UPDATED;
            State->ReadKey = QUIC_PACKET_KEY_1_RTT;
            State->ReadKeys[QUIC_PACKET_KEY_1_RTT] = QuicStubAllocKey(QUIC_PACKET_KEY_1_RTT, State->WriteKeys[QUIC_PACKET_KEY_1_RTT]->TrafficSecret[0].Secret);
            State->HandshakeComplete = TRUE;

        } else {
            QuicTraceEvent(
                TlsErrorStatus,
                "[ tls][%p] ERROR, %u, %s.",
                TlsContext->Connection,
                ClientMessage->Type,
                "Invalid message");
            *ResultFlags |= QUIC_TLS_RESULT_ERROR;
            break;
        }

        DrainLength = (uint16_t)TlsReadUint24(ClientMessage->Length) + 4;

        break;
    }

    default: {
        QuicTraceEvent(
            TlsErrorStatus,
            "[ tls][%p] ERROR, %u, %s.",
            TlsContext->Connection,
            TlsContext->LastMessageType,
            "Invalid last message");
        *ResultFlags |= QUIC_TLS_RESULT_ERROR;
        break;
    }
    }

    *BufferLength = DrainLength;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
void
QuicTlsClientProcess(
    _In_ QUIC_TLS* TlsContext,
    _Out_ QUIC_TLS_RESULT_FLAGS* ResultFlags,
    _Inout_ QUIC_TLS_PROCESS_STATE* State,
    _Inout_ uint32_t* BufferLength,
    _In_reads_bytes_(*BufferLength) const uint8_t * Buffer
    )
{
    uint16_t DrainLength = 0;

    QUIC_FRE_ASSERT(State->BufferLength < State->BufferAllocLength);
    __assume(State->BufferLength < State->BufferAllocLength);

    const QUIC_FAKE_TLS_MESSAGE* ServerMessage =
        (QUIC_FAKE_TLS_MESSAGE*)Buffer;
    QUIC_FAKE_TLS_MESSAGE* ClientMessage =
        (QUIC_FAKE_TLS_MESSAGE*)(State->Buffer + State->BufferLength);
    uint16_t MaxClientMessageLength =
        State->BufferAllocLength - State->BufferLength;

    switch (TlsContext->LastMessageType) {

    case QUIC_TLS_MESSAGE_INVALID: {

        ClientMessage->Type = TlsHandshake_ClientHello;

        TlsWriteUint16(ClientMessage->CLIENT_INITIAL.Version, 0x0302);
        ClientMessage->CLIENT_INITIAL.SessionIdLength = 0;
        TlsWriteUint16(ClientMessage->CLIENT_INITIAL.CipherSuiteLength, 0);
        ClientMessage->CLIENT_INITIAL.CompressionMethodLength = 1;

        uint16_t ExtListLength = 0;

        if (TlsContext->SNI != NULL) {
            QUIC_TLS_SNI_EXT* SNI = (QUIC_TLS_SNI_EXT*)ClientMessage->CLIENT_INITIAL.ExtList;
            uint16_t SniNameLength = (uint16_t)strlen(TlsContext->SNI);
            TlsWriteUint16(SNI->ExtType, TlsExt_ServerName);
            TlsWriteUint16(SNI->ExtLen, 5 + SniNameLength);
            TlsWriteUint16(SNI->ListLen, 3 + SniNameLength);
            SNI->NameType = TlsExt_Sni_NameType_HostName;
            TlsWriteUint16(SNI->NameLength, SniNameLength);
            memcpy(SNI->Name, TlsContext->SNI, SniNameLength);
            ExtListLength += 9 + SniNameLength;
        }

        QUIC_TLS_ALPN_EXT* ALPN =
            (QUIC_TLS_ALPN_EXT*)
            (ClientMessage->CLIENT_INITIAL.ExtList + ExtListLength);
        TlsWriteUint16(ALPN->ExtType, TlsExt_AppProtocolNegotiation);
        TlsWriteUint16(ALPN->ExtLen, 2 + TlsContext->AlpnBufferLength);
        TlsWriteUint16(ALPN->AlpnListLength, TlsContext->AlpnBufferLength);
        memcpy(ALPN->AlpnList, TlsContext->AlpnBuffer, TlsContext->AlpnBufferLength);
        ExtListLength += 6 + TlsContext->AlpnBufferLength;

        if (TlsContext->ResumptionTicketBuffer != NULL) {
            TlsContext->EarlyDataAttempted = TRUE;

            QUIC_TLS_SESSION_TICKET_EXT* Ticket =
                (QUIC_TLS_SESSION_TICKET_EXT*)
                (ClientMessage->CLIENT_INITIAL.ExtList + ExtListLength);
            TlsWriteUint16(Ticket->ExtType, TlsExt_SessionTicket);
            TlsWriteUint16(Ticket->ExtLen, (uint16_t)TlsContext->ResumptionTicketLength);
            memcpy(
                Ticket->Ticket,
                TlsContext->ResumptionTicketBuffer,
                TlsContext->ResumptionTicketLength);
            ExtListLength += 4 + (uint16_t)TlsContext->ResumptionTicketLength;
        } else {
            TlsContext->EarlyDataAttempted = FALSE;
        }

        QUIC_TLS_QUIC_TP_EXT* QuicTP =
            (QUIC_TLS_QUIC_TP_EXT*)
            (ClientMessage->CLIENT_INITIAL.ExtList + ExtListLength);
        TlsWriteUint16(QuicTP->ExtType, TlsExt_QuicTransportParameters);
        TlsWriteUint16(QuicTP->ExtLen, (uint16_t)TlsContext->LocalTPLength);
        memcpy(QuicTP->TP, TlsContext->LocalTPBuffer, TlsContext->LocalTPLength);
        ExtListLength += 4 + (uint16_t)TlsContext->LocalTPLength;

        TlsWriteUint16(ClientMessage->CLIENT_INITIAL.ExtListLength, ExtListLength);

        uint16_t MessageLength = sizeof(QUIC_TLS_CLIENT_HELLO) + ExtListLength + 4;
        TlsWriteUint24(ClientMessage->Length, MessageLength - 4);

        *ResultFlags |= QUIC_TLS_RESULT_DATA;
        State->BufferLength = MessageLength;
        State->BufferTotalLength = MessageLength;

        if (TlsContext->EarlyDataAttempted) {
            State->WriteKey = QUIC_PACKET_KEY_0_RTT;
            uint8_t Secret[QUIC_AEAD_AES_256_GCM_SIZE];
            QuicZeroMemory(Secret, sizeof(Secret));
            State->WriteKeys[QUIC_PACKET_KEY_0_RTT] = QuicStubAllocKey(QUIC_PACKET_KEY_0_RTT, Secret);
        }

        TlsContext->LastMessageType = QUIC_TLS_MESSAGE_CLIENT_INITIAL;
        break;
    }

    case QUIC_TLS_MESSAGE_CLIENT_INITIAL: {
        if (ServerMessage->Type == QUIC_TLS_MESSAGE_SERVER_INITIAL) {

            if (TlsContext->EarlyDataAttempted) {
                State->SessionResumed = ServerMessage->SERVER_INITIAL.EarlyDataAccepted;
                State->EarlyDataState =
                    ServerMessage->SERVER_INITIAL.EarlyDataAccepted ?
                        QUIC_TLS_EARLY_DATA_ACCEPTED :
                        QUIC_TLS_EARLY_DATA_REJECTED;
                if (!ServerMessage->SERVER_INITIAL.EarlyDataAccepted) {
                    *ResultFlags |= QUIC_TLS_RESULT_EARLY_DATA_REJECT;
                } else {
                    *ResultFlags |= QUIC_TLS_RESULT_EARLY_DATA_ACCEPT;
                }
            }

            State->BufferOffsetHandshake = State->BufferTotalLength;

            *ResultFlags |= QUIC_TLS_RESULT_READ_KEY_UPDATED;
            State->ReadKey = QUIC_PACKET_KEY_HANDSHAKE;
            State->ReadKeys[QUIC_PACKET_KEY_HANDSHAKE] = QuicStubAllocKey(QUIC_PACKET_KEY_HANDSHAKE, ServerMessage->SERVER_INITIAL.HandshakeSecret);

            *ResultFlags |= QUIC_TLS_RESULT_WRITE_KEY_UPDATED;
            State->WriteKey = QUIC_PACKET_KEY_HANDSHAKE;
            State->WriteKeys[QUIC_PACKET_KEY_HANDSHAKE] = QuicStubAllocKey(QUIC_PACKET_KEY_HANDSHAKE, ServerMessage->SERVER_INITIAL.HandshakeSecret);

        } else if (ServerMessage->Type == QUIC_TLS_MESSAGE_SERVER_HANDSHAKE) {

            const uint8_t* ExtList =
                    ServerMessage->SERVER_HANDSHAKE.Certificate +
                    ServerMessage->SERVER_HANDSHAKE.CertificateLength;
            uint16_t ExtListLength = ServerMessage->SERVER_HANDSHAKE.ExtListLength;
            while (ExtListLength > 0) {
                uint16_t ExtType = TlsReadUint16(ExtList);
                uint16_t ExtLength = TlsReadUint16(ExtList + 2);
                QUIC_FRE_ASSERT(ExtLength + 4 <= ExtListLength);

                switch (ExtType) {
                case TlsExt_AppProtocolNegotiation: {
                    const QUIC_TLS_ALPN_EXT* AlpnList = (QUIC_TLS_ALPN_EXT*)ExtList;
                    State->NegotiatedAlpn =
                        QuicTlsAlpnFindInList(
                            TlsContext->AlpnBufferLength,
                            TlsContext->AlpnBuffer,
                            AlpnList->AlpnList[0],
                            AlpnList->AlpnList+1);
                    if (State->NegotiatedAlpn == NULL) {
                        QuicTraceEvent(
                            TlsError,
                            "[ tls][%p] ERROR, %s.",
                            TlsContext->Connection,
                            "ALPN Mismatch");
                        *ResultFlags |= QUIC_TLS_RESULT_ERROR;
                    }
                    break;
                }
                case TlsExt_QuicTransportParameters: {
                    const QUIC_TLS_QUIC_TP_EXT* QuicTP = (QUIC_TLS_QUIC_TP_EXT*)ExtList;
                    TlsContext->ReceiveTPCallback(
                        TlsContext->Connection,
                        ExtLength,
                        QuicTP->TP);
                    break;
                }
                default:
                    QUIC_FRE_ASSERT(FALSE);
                    break;
                }

                ExtList += ExtLength + 4;
                ExtListLength -= ExtLength + 4;
            }

            if (TlsContext->SecConfig->Flags & QUIC_CREDENTIAL_FLAG_NO_CERTIFICATE_VALIDATION) {
                QuicTraceLogConnWarning(
                    StubTlsCertValidationDisabled,
                    TlsContext->Connection,
                    "Certificate validation disabled!");
            } else {

                QUIC_CERTIFICATE* ServerCert =
                    QuicCertParseChain(
                        ServerMessage->SERVER_HANDSHAKE.CertificateLength,
                        ServerMessage->SERVER_HANDSHAKE.Certificate);

                if (ServerCert == NULL) {
                    QuicTraceEvent(
                        TlsError,
                        "[ tls][%p] ERROR, %s.",
                        TlsContext->Connection,
                        "QuicCertParseChain Mismatch");
                    *ResultFlags |= QUIC_TLS_RESULT_ERROR;
                    break;
                }

                if (!QuicCertValidateChain(
                        ServerCert,
                        TlsContext->SNI,
                        TlsContext->SecConfig->Flags)) {
                    QuicTraceEvent(
                        TlsError,
                        "[ tls][%p] ERROR, %s.",
                        TlsContext->Connection,
                        "QuicCertValidateChain Mismatch");
                    *ResultFlags |= QUIC_TLS_RESULT_ERROR;
                    break;
                }
            }

            State->HandshakeComplete = TRUE;
            *ResultFlags |= QUIC_TLS_RESULT_COMPLETE;

            QuicTraceLogConnInfo(
                StubTlsHandshakeComplete,
                TlsContext->Connection,
                "Handshake complete");

            if (MaxClientMessageLength < MinMessageLengths[QUIC_TLS_MESSAGE_CLIENT_HANDSHAKE]) {
                *ResultFlags |= QUIC_TLS_RESULT_ERROR;
                break;
            }

            uint16_t MessageLength = MinMessageLengths[QUIC_TLS_MESSAGE_CLIENT_HANDSHAKE];
            TlsWriteUint24(ClientMessage->Length, MessageLength - 4);
            ClientMessage->Type = QUIC_TLS_MESSAGE_CLIENT_HANDSHAKE;
            ClientMessage->CLIENT_HANDSHAKE.Success = TRUE;

            *ResultFlags |= QUIC_TLS_RESULT_DATA;
            State->BufferLength += MessageLength;
            State->BufferTotalLength += MessageLength;
            State->BufferOffset1Rtt = State->BufferTotalLength;

            *ResultFlags |= QUIC_TLS_RESULT_READ_KEY_UPDATED;
            State->ReadKey = QUIC_PACKET_KEY_1_RTT;
            State->ReadKeys[QUIC_PACKET_KEY_1_RTT] = QuicStubAllocKey(QUIC_PACKET_KEY_1_RTT, ServerMessage->SERVER_HANDSHAKE.OneRttSecret);

            *ResultFlags |= QUIC_TLS_RESULT_WRITE_KEY_UPDATED;
            State->WriteKey = QUIC_PACKET_KEY_1_RTT;
            State->WriteKeys[QUIC_PACKET_KEY_1_RTT] = QuicStubAllocKey(QUIC_PACKET_KEY_1_RTT, ServerMessage->SERVER_HANDSHAKE.OneRttSecret);

            TlsContext->LastMessageType = QUIC_TLS_MESSAGE_CLIENT_HANDSHAKE;

        } else {
            QuicTraceEvent(
                TlsErrorStatus,
                "[ tls][%p] ERROR, %u, %s.",
                TlsContext->Connection,
                ServerMessage->Type,
                "Invalid message");
            *ResultFlags |= QUIC_TLS_RESULT_ERROR;
            break;
        }

        DrainLength = (uint16_t)TlsReadUint24(ServerMessage->Length) + 4;

        break;
    }

    case QUIC_TLS_MESSAGE_CLIENT_HANDSHAKE: {
        if (ServerMessage->Type != QUIC_TLS_MESSAGE_TICKET) {
            QuicTraceEvent(
                TlsErrorStatus,
                "[ tls][%p] ERROR, %u, %s.",
                TlsContext->Connection,
                ServerMessage->Type,
                "Invalid message");
            *ResultFlags |= QUIC_TLS_RESULT_ERROR;
            break;
        }

        uint32_t ServerMessageLength =
            TlsReadUint24(ServerMessage->Length);

        QuicTraceLogConnVerbose(
            StubTlsRecvNewSessionTicket,
            TlsContext->Connection,
            "Received new ticket. ticket_len:%u for %s",
            ServerMessageLength,
            TlsContext->SNI);

        QUIC_FRE_ASSERT(ServerMessageLength < UINT16_MAX);

        (void)TlsContext->ReceiveTicketCallback(
            TlsContext->Connection,
            ServerMessageLength,
            ServerMessage->TICKET.Ticket);

        DrainLength = (uint16_t)ServerMessageLength + 4;
        break;
    }

    default: {
        QuicTraceEvent(
            TlsErrorStatus,
            "[ tls][%p] ERROR, %u, %s.",
            TlsContext->Connection,
            TlsContext->LastMessageType,
            "Invalid last message");
        *ResultFlags |= QUIC_TLS_RESULT_ERROR;
        break;
    }
    }

    *BufferLength = DrainLength;
}

BOOLEAN
QuicTlsHasValidMessageToProcess(
    _In_ QUIC_TLS* TlsContext,
    _In_ uint32_t BufferLength,
    _In_reads_bytes_(BufferLength)
        const uint8_t* Buffer
    )
{
    if (!TlsContext->IsServer &&
        TlsContext->LastMessageType == QUIC_TLS_MESSAGE_INVALID &&
        BufferLength == 0) {
        return TRUE;
    }

    if (BufferLength < 4) {
        QuicTraceEvent(
            TlsError,
            "[ tls][%p] ERROR, %s.",
            TlsContext->Connection,
            "Insufficient data to process header");
        return FALSE;
    }

    const QUIC_FAKE_TLS_MESSAGE* Message = (QUIC_FAKE_TLS_MESSAGE*)Buffer;
    uint32_t MessageLength = TlsReadUint24(Message->Length) + 4;
    if (BufferLength < MessageLength) {
        QuicTraceEvent(
            TlsError,
            "[ tls][%p] ERROR, %s.",
            TlsContext->Connection,
            "Insufficient data to process payload");
        return FALSE;
    }

    return TRUE;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
QUIC_TLS_RESULT_FLAGS
QuicTlsProcessData(
    _In_ QUIC_TLS* TlsContext,
    _In_ QUIC_TLS_DATA_TYPE DataType,
    _In_reads_bytes_(*BufferLength)
        const uint8_t * Buffer,
    _Inout_ uint32_t * BufferLength,
    _Inout_ QUIC_TLS_PROCESS_STATE* State
    )
{
    if (*BufferLength) {
        QuicTraceLogConnVerbose(
            StubTlsProcessData,
            TlsContext->Connection,
            "Processing %u received bytes",
            *BufferLength);
    }

    QUIC_TLS_RESULT_FLAGS ResultFlags = 0;

    if (QuicTlsHasValidMessageToProcess(TlsContext, *BufferLength, Buffer)) {
        QUIC_FRE_ASSERT(DataType == QUIC_TLS_CRYPTO_DATA);

        uint16_t PrevBufferLength = State->BufferLength;
        if (TlsContext->IsServer) {
            QuicTlsServerProcess(TlsContext, &ResultFlags, State, BufferLength, Buffer);
        } else {
            QuicTlsClientProcess(TlsContext, &ResultFlags, State, BufferLength, Buffer);
        }

        QuicTraceLogConnInfo(
            StubTlsConsumedData,
            TlsContext->Connection,
            "Consumed %u bytes",
            *BufferLength);

        if (State->BufferLength > PrevBufferLength) {
            QuicTraceLogConnInfo(
                StubTlsProducedData,
                TlsContext->Connection,
                "Produced %hu bytes",
                (State->BufferLength - PrevBufferLength));
        }

    } else if (DataType == QUIC_TLS_TICKET_DATA) {
        QUIC_FRE_ASSERT(TlsContext->IsServer);

        uint16_t PrevBufferLength = State->BufferLength;
        QUIC_FAKE_TLS_MESSAGE* ServerMessage =
            (QUIC_FAKE_TLS_MESSAGE*)(State->Buffer + State->BufferLength);
        uint16_t MaxServerMessageLength =
            State->BufferAllocLength - State->BufferLength;
        if (MaxServerMessageLength < MinMessageLengths[QUIC_TLS_MESSAGE_TICKET] + *BufferLength) {
            ResultFlags |= QUIC_TLS_RESULT_ERROR;
            goto Error;
        }

        uint16_t MessageLength = MinMessageLengths[QUIC_TLS_MESSAGE_TICKET] + (uint16_t)*BufferLength;
        TlsWriteUint24(ServerMessage->Length, MessageLength - 4);
        ServerMessage->Type = QUIC_TLS_MESSAGE_TICKET;
        memcpy(ServerMessage->TICKET.Ticket, Buffer, *BufferLength);

        ResultFlags |= QUIC_TLS_RESULT_DATA;
        State->BufferLength += MessageLength;
        State->BufferTotalLength += MessageLength;

        TlsContext->LastMessageType = QUIC_TLS_MESSAGE_TICKET;

        if (State->BufferLength > PrevBufferLength) {
            QuicTraceLogConnInfo(
                StubTlsProducedData,
                TlsContext->Connection,
                "Produced %hu bytes",
                (State->BufferLength - PrevBufferLength));
        }
    } else {
        *BufferLength = 0;
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
    UNREFERENCED_PARAMETER(TlsContext);
    UNREFERENCED_PARAMETER(BufferConsumed);
    return QUIC_TLS_RESULT_ERROR;
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
    UNREFERENCED_PARAMETER(TlsContext);
    UNREFERENCED_PARAMETER(Param);
    UNREFERENCED_PARAMETER(BufferLength);
    UNREFERENCED_PARAMETER(Buffer);
    return QUIC_STATUS_NOT_SUPPORTED;
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
    UNREFERENCED_PARAMETER(TlsContext);
    UNREFERENCED_PARAMETER(Param);
    UNREFERENCED_PARAMETER(BufferLength);
    UNREFERENCED_PARAMETER(Buffer);
    return QUIC_STATUS_NOT_SUPPORTED;
}

//
// Crypto / Key Functionality
//

_IRQL_requires_max_(PASSIVE_LEVEL)
_When_(ReadKey != NULL, _At_(*ReadKey, __drv_allocatesMem(Mem)))
_When_(WriteKey != NULL, _At_(*WriteKey, __drv_allocatesMem(Mem)))
QUIC_STATUS
QuicPacketKeyCreateInitial(
    _In_ BOOLEAN IsServer,
    _In_reads_(QUIC_VERSION_SALT_LENGTH)
        const uint8_t* const Salt, // Version Specific
    _In_ uint8_t CIDLength,
    _In_reads_(CIDLength)
        const uint8_t* const CID,
    _Out_opt_ QUIC_PACKET_KEY** ReadKey,
    _Out_opt_ QUIC_PACKET_KEY** WriteKey
    )
{
    UNREFERENCED_PARAMETER(IsServer);

    uint8_t Secret[QUIC_AEAD_AES_256_GCM_SIZE];
    QuicZeroMemory(Secret, sizeof(Secret));
    for (uint8_t i = 0; i < QUIC_VERSION_SALT_LENGTH; ++i) {
        Secret[i % QUIC_AEAD_AES_256_GCM_SIZE] += Salt[i];
    }
    for (uint8_t i = 0; i < CIDLength; ++i) {
        Secret[(i + QUIC_VERSION_SALT_LENGTH) % QUIC_AEAD_AES_256_GCM_SIZE] += CID[i];
    }

    if (ReadKey != NULL) {
        *ReadKey = QuicStubAllocKey(QUIC_PACKET_KEY_INITIAL, Secret);
    }
    if (WriteKey != NULL) {
        *WriteKey = QuicStubAllocKey(QUIC_PACKET_KEY_INITIAL, Secret);
    }
    return QUIC_STATUS_SUCCESS;
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
    UNREFERENCED_PARAMETER(Secret);
    UNREFERENCED_PARAMETER(SecretName);
    UNREFERENCED_PARAMETER(CreateHpKey);
    uint8_t NullSecret[QUIC_AEAD_AES_256_GCM_SIZE];
    QuicZeroMemory(NullSecret, sizeof(NullSecret));
    *NewKey = QuicStubAllocKey(KeyType, NullSecret);
    return QUIC_STATUS_SUCCESS;
}

_IRQL_requires_max_(DISPATCH_LEVEL)
void
QuicPacketKeyFree(
    _In_opt_ __drv_freesMem(Mem) QUIC_PACKET_KEY* Key
    )
{
    if (Key != NULL) {
        QuicKeyFree(Key->PacketKey);
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
    if (OldKey == NULL || OldKey->Type != QUIC_PACKET_KEY_1_RTT) {
        return QUIC_STATUS_INVALID_STATE;
    }
    OldKey->TrafficSecret[0].Secret[0]++;
    *NewKey = QuicStubAllocKey(QUIC_PACKET_KEY_1_RTT, OldKey->TrafficSecret[0].Secret);
    return QUIC_STATUS_SUCCESS;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
QUIC_STATUS
QuicKeyCreate(
    _In_ QUIC_AEAD_TYPE AeadType,
    _When_(AeadType == QUIC_AEAD_AES_128_GCM, _In_reads_(16))
    _When_(AeadType == QUIC_AEAD_AES_256_GCM, _In_reads_(32))
    _When_(AeadType == QUIC_AEAD_CHACHA20_POLY1305, _In_reads_(32))
        const uint8_t* const RawKey,
    _Out_ QUIC_KEY** NewKey
    )
{
    QUIC_KEY *Key = QUIC_ALLOC_NONPAGED(sizeof(QUIC_KEY));
    QUIC_FRE_ASSERT(Key != NULL);
    Key->Secret = AeadType;
    for (uint16_t i = 0; i < QuicKeyLength(AeadType); ++i) {
        ((uint8_t*)&Key->Secret)[i % 8] += RawKey[i];
    }
    *NewKey = Key;
    return QUIC_STATUS_SUCCESS;
}

_IRQL_requires_max_(DISPATCH_LEVEL)
void
QuicKeyFree(
    _In_opt_ QUIC_KEY* Key
    )
{
    if (Key != NULL) {
        QUIC_FREE(Key);
    }
}

_IRQL_requires_max_(DISPATCH_LEVEL)
QUIC_STATUS
QuicEncrypt(
    _In_ QUIC_KEY* Key,
    _In_reads_bytes_(QUIC_IV_LENGTH)
        const uint8_t* const Iv,
    _In_ uint16_t AuthDataLength,
    _In_reads_bytes_opt_(AuthDataLength)
        const uint8_t* const AuthData,
    _In_ uint16_t BufferLength,
    _When_(BufferLength > QUIC_ENCRYPTION_OVERHEAD, _Inout_updates_bytes_(BufferLength))
    _When_(BufferLength <= QUIC_ENCRYPTION_OVERHEAD, _Out_writes_bytes_(BufferLength))
        uint8_t* Buffer
    )
{
    UNREFERENCED_PARAMETER(Iv);
    UNREFERENCED_PARAMETER(AuthDataLength);
    UNREFERENCED_PARAMETER(AuthData);
    uint16_t PlainTextLength = BufferLength - QUIC_ENCRYPTION_OVERHEAD;
    QuicCopyMemory(Buffer + PlainTextLength, &Key->Secret, sizeof(Key->Secret));
    QuicZeroMemory(Buffer + PlainTextLength + sizeof(Key->Secret), sizeof(uint64_t));
    return QUIC_STATUS_SUCCESS;
}

_IRQL_requires_max_(DISPATCH_LEVEL)
QUIC_STATUS
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
    UNREFERENCED_PARAMETER(Iv);
    UNREFERENCED_PARAMETER(AuthDataLength);
    UNREFERENCED_PARAMETER(AuthData);
    uint16_t PlainTextLength = BufferLength - QUIC_ENCRYPTION_OVERHEAD;
    if (memcmp(Buffer + PlainTextLength, &Key->Secret, sizeof(Key->Secret)) != 0) {
        return QUIC_STATUS_INVALID_PARAMETER;
    } else {
        return QUIC_STATUS_SUCCESS;
    }
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
    UNREFERENCED_PARAMETER(AeadType);
    UNREFERENCED_PARAMETER(RawKey);
    *NewKey = (QUIC_HP_KEY*)0x1;
    return QUIC_STATUS_SUCCESS;
}

_IRQL_requires_max_(DISPATCH_LEVEL)
void
QuicHpKeyFree(
    _In_opt_ QUIC_HP_KEY* Key
    )
{
    UNREFERENCED_PARAMETER(Key);
}

_IRQL_requires_max_(DISPATCH_LEVEL)
QUIC_STATUS
QuicHpComputeMask(
    _In_ QUIC_HP_KEY* Key,
    _In_ uint8_t BatchSize,
    _In_reads_bytes_(QUIC_HP_SAMPLE_LENGTH * BatchSize)
        const uint8_t* const Cipher,
    _Out_writes_bytes_(QUIC_HP_SAMPLE_LENGTH * BatchSize)
        uint8_t* Mask
    )
{
    UNREFERENCED_PARAMETER(Key);
    UNREFERENCED_PARAMETER(Cipher);
    QuicZeroMemory(Mask, BatchSize * QUIC_HP_SAMPLE_LENGTH);
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
    UNREFERENCED_PARAMETER(HashType);
    UNREFERENCED_PARAMETER(Salt);
    UNREFERENCED_PARAMETER(SaltLength);
    *NewHash = (QUIC_HASH*)0x1;
    return QUIC_STATUS_SUCCESS;
}

_IRQL_requires_max_(DISPATCH_LEVEL)
void
QuicHashFree(
    _In_opt_ QUIC_HASH* Hash
    )
{
    UNREFERENCED_PARAMETER(Hash);
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
    UNREFERENCED_PARAMETER(Hash);
    UNREFERENCED_PARAMETER(Input);
    UNREFERENCED_PARAMETER(InputLength);
    QuicZeroMemory(Output, OutputLength);
    return QUIC_STATUS_SUCCESS;
}
