/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.

Abstract:

    This file contains the definitions for the TLS processing interface.

--*/

#pragma once

#include <msquic.h>
#include <quic_crypt.h>

#if defined(__cplusplus)
extern "C" {
#endif

#pragma warning(disable:4201)  // nonstandard extension used: nameless struct/union
#pragma warning(disable:4214)  // nonstandard extension used: bit field types other than int

typedef struct CXPLAT_SEC_CONFIG CXPLAT_SEC_CONFIG;
typedef struct QUIC_CONNECTION QUIC_CONNECTION;
typedef struct CXPLAT_TLS CXPLAT_TLS;
typedef struct CXPLAT_TLS_SECRETS CXPLAT_TLS_SECRETS;

#define TLS_EXTENSION_TYPE_APPLICATION_LAYER_PROTOCOL_NEGOTIATION   0x0010  // Host Byte Order
#define TLS_EXTENSION_TYPE_QUIC_TRANSPORT_PARAMETERS_DRAFT          0xffa5  // Host Byte Order
#define TLS_EXTENSION_TYPE_QUIC_TRANSPORT_PARAMETERS                0x0039  // Host Byte Order

//
// The size of the header required by the TLS layer.
//
extern uint16_t CxPlatTlsTPHeaderSize;

//
// Callback for indicating process can be completed.
//
typedef
_IRQL_requires_max_(DISPATCH_LEVEL)
void
(CXPLAT_TLS_PROCESS_COMPLETE_CALLBACK)(
    _In_ QUIC_CONNECTION* Connection
    );

typedef CXPLAT_TLS_PROCESS_COMPLETE_CALLBACK *CXPLAT_TLS_PROCESS_COMPLETE_CALLBACK_HANDLER;

//
// Callback for indicating received QUIC TP parameters. Callback always happens
// in the context of a QuicTlsProcessData call; not on a separate thread.
//
typedef
_IRQL_requires_max_(PASSIVE_LEVEL)
BOOLEAN
(CXPLAT_TLS_RECEIVE_TP_CALLBACK)(
    _In_ QUIC_CONNECTION* Connection,
    _In_ uint16_t TPLength,
    _In_reads_(TPLength) const uint8_t* TPBuffer
    );

typedef CXPLAT_TLS_RECEIVE_TP_CALLBACK *CXPLAT_TLS_RECEIVE_TP_CALLBACK_HANDLER;

//
// Callback for indicating received resumption ticket. Callback always happens
// in the context of a QuicTlsProcessData call; not on a separate thread.
//
typedef
_IRQL_requires_max_(PASSIVE_LEVEL)
BOOLEAN
(CXPLAT_TLS_RECEIVE_TICKET_CALLBACK)(
    _In_ QUIC_CONNECTION* Connection,
    _In_ uint32_t TicketLength,
    _In_reads_(TicketLength) const uint8_t* Ticket
    );

typedef CXPLAT_TLS_RECEIVE_TICKET_CALLBACK *CXPLAT_TLS_RECEIVE_TICKET_CALLBACK_HANDLER;

typedef struct CXPLAT_TLS_CALLBACKS {

    //
    // Invoked for the completion of process calls that were pending.
    //
    CXPLAT_TLS_PROCESS_COMPLETE_CALLBACK_HANDLER ProcessComplete;

    //
    // Invoked when QUIC transport parameters are received.
    //
    CXPLAT_TLS_RECEIVE_TP_CALLBACK_HANDLER ReceiveTP;

    //
    // Invoked when a resumption ticket is received.
    //
    CXPLAT_TLS_RECEIVE_TICKET_CALLBACK_HANDLER ReceiveTicket;

} CXPLAT_TLS_CALLBACKS;

//
// The input configuration for creation of a TLS context.
//
typedef struct CXPLAT_TLS_CONFIG {

    BOOLEAN IsServer;

    //
    // Connection context for completion callbacks.
    //
    QUIC_CONNECTION* Connection;

    //
    // The TLS configuration information and credentials.
    //
    CXPLAT_SEC_CONFIG* SecConfig;

    //
    // The Application Layer Protocol Negotiation TLS extension buffer to send
    // in the TLS handshake. Buffer is owned by the caller and not freed by the
    // TLS layer.
    //
    const uint8_t* AlpnBuffer;
    uint16_t AlpnBufferLength;

    //
    // TLS Extension code type for transport parameters.
    //
    uint16_t TPType;

    //
    // Name of the server we are connecting to (client side only).
    //
    const char* ServerName;

    //
    // The optional ticket buffer the client size uses to resume a previous
    // session (client side only).
    //
    const uint8_t* ResumptionTicketBuffer;
    uint32_t ResumptionTicketLength;

    //
    // The local QUIC transport parameters to send. Buffer is freed by the TLS
    // context when it's no longer needed.
    //
    const uint8_t* LocalTPBuffer;
    uint32_t LocalTPLength;

#ifdef CXPLAT_TLS_SECRETS_SUPPORT
    //
    // Storage for TLS traffic secrets when CXPLAT_TLS_SECRETS_SUPPORT is enabled,
    // and the connection has the parameter set to enable logging.
    //
    CXPLAT_TLS_SECRETS* TlsSecrets;
#endif

} CXPLAT_TLS_CONFIG;

//
// Different possible results after writing new TLS data.
//
typedef enum CXPLAT_TLS_RESULT_FLAGS {

    CXPLAT_TLS_RESULT_CONTINUE            = 0x0001, // Needs immediate call again. (Used internally to schannel)
    CXPLAT_TLS_RESULT_PENDING             = 0x0002, // The call is pending.
    CXPLAT_TLS_RESULT_DATA                = 0x0004, // Data ready to be sent.
    CXPLAT_TLS_RESULT_READ_KEY_UPDATED    = 0x0008, // ReadKey variable has been updated.
    CXPLAT_TLS_RESULT_WRITE_KEY_UPDATED   = 0x0010, // WriteKey variable has been updated.
    CXPLAT_TLS_RESULT_EARLY_DATA_ACCEPT   = 0x0020, // The server accepted the early (0-RTT) data.
    CXPLAT_TLS_RESULT_EARLY_DATA_REJECT   = 0x0040, // The server rejected the early (0-RTT) data.
    CXPLAT_TLS_RESULT_COMPLETE            = 0x0080, // Handshake complete.
    CXPLAT_TLS_RESULT_ERROR               = 0x8000  // An error occured.

} CXPLAT_TLS_RESULT_FLAGS;

typedef enum CXPLAT_TLS_DATA_TYPE {

    CXPLAT_TLS_CRYPTO_DATA,
    CXPLAT_TLS_TICKET_DATA

} CXPLAT_TLS_DATA_TYPE;

//
// Different possible results after writing new TLS data.
//
typedef enum CXPLAT_TLS_EARLY_DATA_STATE {

    CXPLAT_TLS_EARLY_DATA_UNKNOWN,
    CXPLAT_TLS_EARLY_DATA_UNSUPPORTED,
    CXPLAT_TLS_EARLY_DATA_REJECTED,
    CXPLAT_TLS_EARLY_DATA_ACCEPTED

} CXPLAT_TLS_EARLY_DATA_STATE;

//
// The output processing state.
//
typedef struct CXPLAT_TLS_PROCESS_STATE {

    //
    // Indicates TLS has completed the handshake phase of its exchange.
    //
    BOOLEAN HandshakeComplete : 1;

    //
    // Indicates the TLS session was resumed from a previous connection.
    //
    BOOLEAN SessionResumed : 1;

    //
    // Indicates the state of early data support.
    //
    CXPLAT_TLS_EARLY_DATA_STATE EarlyDataState;

    //
    // The key that newly received data should be decrypted and read with.
    //
    QUIC_PACKET_KEY_TYPE ReadKey;

    //
    // The highest key available for writing TLS data with.
    //
    QUIC_PACKET_KEY_TYPE WriteKey;

    //
    // In case of failure, the TLS alert/error code.
    //
    uint16_t AlertCode;

    //
    // Total written length in Buffer.
    //
    uint16_t BufferLength;

    //
    // Total allocation length of Buffer.
    //
    uint16_t BufferAllocLength;

    //
    // The total length of data ever written to Buffer.
    //
    uint32_t BufferTotalLength;

    //
    // The absolute offset of the start of handshake data. A value of 0
    // indicates 'unset'.
    //
    uint32_t BufferOffsetHandshake;

    //
    // The absolute offset of the start of 1-RTT data. A value of 0 indicates
    // 'unset'.
    //
    uint32_t BufferOffset1Rtt;

    //
    // Holds the TLS data to be sent. Use CXPLAT_ALLOC_NONPAGED and CXPLAT_FREE
    // to allocate and free the memory.
    //
    uint8_t* Buffer;

    //
    // The final negotiated ALPN of the connection. The first byte is the length
    // followed by that many bytes for actual ALPN.
    //
    const uint8_t* NegotiatedAlpn;

    //
    // All the keys available for decrypting packets with.
    //
    QUIC_PACKET_KEY* ReadKeys[QUIC_PACKET_KEY_COUNT];

    //
    // All the keys available for encrypting packets with.
    //
    QUIC_PACKET_KEY* WriteKeys[QUIC_PACKET_KEY_COUNT];

} CXPLAT_TLS_PROCESS_STATE;

typedef
_IRQL_requires_max_(PASSIVE_LEVEL)
_Function_class_(CXPLAT_SEC_CONFIG_CREATE_COMPLETE)
void
(QUIC_API CXPLAT_SEC_CONFIG_CREATE_COMPLETE)(
    _In_ const QUIC_CREDENTIAL_CONFIG* CredConfig,
    _In_opt_ void* Context,
    _In_ QUIC_STATUS Status,
    _In_opt_ CXPLAT_SEC_CONFIG* SecurityConfig
    );

typedef CXPLAT_SEC_CONFIG_CREATE_COMPLETE *CXPLAT_SEC_CONFIG_CREATE_COMPLETE_HANDLER;

//
// Creates a new TLS security configuration.
//
_IRQL_requires_max_(PASSIVE_LEVEL)
QUIC_STATUS
CxPlatTlsSecConfigCreate(
    _In_ const QUIC_CREDENTIAL_CONFIG* CredConfig,
    _In_ const CXPLAT_TLS_CALLBACKS* TlsCallbacks,
    _In_opt_ void* Context,
    _In_ CXPLAT_SEC_CONFIG_CREATE_COMPLETE_HANDLER CompletionHandler
    );

//
// Deletes a TLS security configuration.
//
_IRQL_requires_max_(PASSIVE_LEVEL)
void
CxPlatTlsSecConfigDelete(
    __drv_freesMem(ServerConfig) _Frees_ptr_ _In_
        CXPLAT_SEC_CONFIG* SecurityConfig
    );

//
// Initializes a TLS context.
//
_IRQL_requires_max_(PASSIVE_LEVEL)
QUIC_STATUS
CxPlatTlsInitialize(
    _In_ const CXPLAT_TLS_CONFIG* Config,
    _Inout_ CXPLAT_TLS_PROCESS_STATE* State,
    _Out_ CXPLAT_TLS** NewTlsContext
    );

//
// Uninitializes an existing TLS context.
//
_IRQL_requires_max_(PASSIVE_LEVEL)
void
CxPlatTlsUninitialize(
    _In_opt_ CXPLAT_TLS* TlsContext
    );

//
// Called to process any data received from the peer. In the case of the client,
// the initial call is made with no input buffer to generate the initial output.
// The returned CXPLAT_TLS_RESULT_FLAGS and CXPLAT_TLS_PROCESS_STATE are update with
// any state changes as a result of the call. If the call returns
// CXPLAT_TLS_RESULT_PENDING, then the registered CXPLAT_TLS_PROCESS_COMPLETE_CALLBACK_HANDLER
// will be triggered at a later date; at which the QUIC code must then call
// QuicTlsProcessDataComplete to complete the operation and get the resulting
// flags.
//
_IRQL_requires_max_(PASSIVE_LEVEL)
CXPLAT_TLS_RESULT_FLAGS
CxPlatTlsProcessData(
    _In_ CXPLAT_TLS* TlsContext,
    _In_ CXPLAT_TLS_DATA_TYPE DataType,
    _In_reads_bytes_(*BufferLength)
        const uint8_t * Buffer,
    _Inout_ uint32_t * BufferLength,
    _Inout_ CXPLAT_TLS_PROCESS_STATE* State
    );

//
// Called when in response to receiving a process completed callback.
//
_IRQL_requires_max_(PASSIVE_LEVEL)
CXPLAT_TLS_RESULT_FLAGS
CxPlatTlsProcessDataComplete(
    _In_ CXPLAT_TLS* TlsContext,
    _Out_ uint32_t * ConsumedBuffer
    );

//
// Sets a TLS parameter.
//
_IRQL_requires_max_(PASSIVE_LEVEL)
QUIC_STATUS
CxPlatTlsParamSet(
    _In_ CXPLAT_TLS* TlsContext,
    _In_ uint32_t Param,
    _In_ uint32_t BufferLength,
    _In_reads_bytes_(BufferLength)
        const void* Buffer
    );

//
// Gets a TLS parameter.
//
_IRQL_requires_max_(PASSIVE_LEVEL)
QUIC_STATUS
CxPlatTlsParamGet(
    _In_ CXPLAT_TLS* TlsContext,
    _In_ uint32_t Param,
    _Inout_ uint32_t* BufferLength,
    _Inout_updates_bytes_opt_(*BufferLength)
        void* Buffer
    );

//
// Helper function to search a TLS ALPN encoded list for a given ALPN buffer.
// Returns a pointer in the 'AlpnList' that starts at the length field, if the
// ALPN is found. Otherwise, it returns NULL.
//
inline
const uint8_t*
CxPlatTlsAlpnFindInList(
    _In_ uint16_t AlpnListLength,
    _In_reads_(AlpnListLength)
        const uint8_t* AlpnList,
    _In_ uint8_t FindAlpnLength,
    _In_reads_(FindAlpnLength)
        const uint8_t* FindAlpn
    )
{
    while (AlpnListLength != 0) {
        CXPLAT_DBG_ASSERT(AlpnList[0] + 1 <= AlpnListLength);
        if (AlpnList[0] == FindAlpnLength &&
            memcmp(AlpnList+1, FindAlpn, FindAlpnLength) == 0) {
            return AlpnList;
        }
        AlpnListLength -= AlpnList[0] + 1;
        AlpnList += AlpnList[0] + 1;
    }
    return NULL;
}

#if defined(__cplusplus)
}
#endif
