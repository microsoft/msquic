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

typedef struct QUIC_CONNECTION QUIC_CONNECTION;
typedef struct QUIC_TLS_SESSION QUIC_TLS_SESSION;
typedef struct QUIC_TLS QUIC_TLS;

#define TLS_EXTENSION_TYPE_APPLICATION_LAYER_PROTOCOL_NEGOTIATION   0x0010  // Host Byte Order
#define TLS_EXTENSION_TYPE_QUIC_TRANSPORT_PARAMETERS                0xffa5  // Host Byte Order

//
// The size of the header required by the TLS layer.
//
extern uint16_t QuicTlsTPHeaderSize;

//
// Callback for indicating process can be completed.
//
typedef
_IRQL_requires_max_(DISPATCH_LEVEL)
void
(QUIC_TLS_PROCESS_COMPLETE_CALLBACK)(
    _In_ QUIC_CONNECTION* Connection
    );

typedef QUIC_TLS_PROCESS_COMPLETE_CALLBACK *QUIC_TLS_PROCESS_COMPLETE_CALLBACK_HANDLER;

//
// Callback for indicating received QUIC TP parameters. Callback always happens
// in the context of a QuicTlsProcessData call; not on a separate thread.
//
typedef
_IRQL_requires_max_(PASSIVE_LEVEL)
BOOLEAN
(QUIC_TLS_RECEIVE_TP_CALLBACK)(
    _In_ QUIC_CONNECTION* Connection,
    _In_ uint16_t TPLength,
    _In_reads_(TPLength) const uint8_t* TPBuffer
    );

typedef QUIC_TLS_RECEIVE_TP_CALLBACK *QUIC_TLS_RECEIVE_TP_CALLBACK_HANDLER;

//
// Callback for indicating received resumption ticket. Callback always happens
// in the context of a QuicTlsProcessData call; not on a separate thread.
//
typedef
_IRQL_requires_max_(PASSIVE_LEVEL)
BOOLEAN
(QUIC_TLS_RECEIVE_RESUMPTION_CALLBACK)(
    _In_ QUIC_CONNECTION* Connection,
    _In_ uint16_t TicketLength,
    _In_reads_(TicketLength) const uint8_t* Ticket
    );

typedef QUIC_TLS_RECEIVE_RESUMPTION_CALLBACK *QUIC_TLS_RECEIVE_RESUMPTION_CALLBACK_HANDLER;

//
// The input configuration for creation of a TLS context.
//
typedef struct QUIC_TLS_CONFIG {

    BOOLEAN IsServer;

    //
    // The TLS session.
    //
    QUIC_TLS_SESSION* TlsSession;

    //
    // The TLS configuration information and credentials.
    //
    QUIC_SEC_CONFIG* SecConfig;

    //
    // The Application Layer Protocol Negotiation TLS extension buffer to send
    // in the TLS handshake. Buffer is owned by the caller and not freed by the
    // TLS layer.
    //
    const uint8_t* AlpnBuffer;
    uint16_t AlpnBufferLength;

    //
    // The local QUIC transport parameters to send. Buffer is freed by the TLS
    // context when it's no longer needed.
    //
    const uint8_t* LocalTPBuffer;
    uint32_t LocalTPLength;

    //
    // Passed into completion callbacks.
    //
    QUIC_CONNECTION* Connection;

    //
    // Invoked for the completion of process calls that were pending.
    //
    QUIC_TLS_PROCESS_COMPLETE_CALLBACK_HANDLER ProcessCompleteCallback;

    //
    // Invoked when QUIC TP are received.
    //
    QUIC_TLS_RECEIVE_TP_CALLBACK_HANDLER ReceiveTPCallback;

    //
    // Invoked when a resumption ticket is received.
    //
    QUIC_TLS_RECEIVE_RESUMPTION_CALLBACK_HANDLER ReceiveResumptionCallback;

    //
    // Name of the server we are connecting to (client side only).
    //
    const char* ServerName;

} QUIC_TLS_CONFIG;

//
// Different possible results after writing new TLS data.
//
typedef enum QUIC_TLS_RESULT_FLAGS {

    QUIC_TLS_RESULT_CONTINUE            = 0x0001, // Needs immediate call again. (Used internally to schannel)
    QUIC_TLS_RESULT_PENDING             = 0x0002, // The call is pending.
    QUIC_TLS_RESULT_DATA                = 0x0004, // Data ready to be sent.
    QUIC_TLS_RESULT_READ_KEY_UPDATED    = 0x0008, // ReadKey variable has been updated.
    QUIC_TLS_RESULT_WRITE_KEY_UPDATED   = 0x0010, // WriteKey variable has been updated.
    QUIC_TLS_RESULT_EARLY_DATA_ACCEPT   = 0x0020, // The server accepted the early (0-RTT) data.
    QUIC_TLS_RESULT_EARLY_DATA_REJECT   = 0x0040, // The server rejected the early (0-RTT) data.
    QUIC_TLS_RESULT_COMPLETE            = 0x0080, // Handshake complete.
    QUIC_TLS_RESULT_TICKET              = 0x0100, // Ticket Ready.
    QUIC_TLS_RESULT_ERROR               = 0x8000  // An error occured.

} QUIC_TLS_RESULT_FLAGS;

typedef enum QUIC_TLS_DATA_TYPE {

    QUIC_TLS_CRYPTO_DATA,
    QUIC_TLS_TICKET_DATA

} QUIC_TLS_DATA_TYPE;

//
// Different possible results after writing new TLS data.
//
typedef enum QUIC_TLS_EARLY_DATA_STATE {

    QUIC_TLS_EARLY_DATA_UNKNOWN,
    QUIC_TLS_EARLY_DATA_UNSUPPORTED,
    QUIC_TLS_EARLY_DATA_REJECTED,
    QUIC_TLS_EARLY_DATA_ACCEPTED

} QUIC_TLS_EARLY_DATA_STATE;

//
// The output processing state.
//
typedef struct QUIC_TLS_PROCESS_STATE {

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
    QUIC_TLS_EARLY_DATA_STATE EarlyDataState;

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
    // Holds the TLS data to be sent. Use QUIC_ALLOC_NONPAGED and QUIC_FREE
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

} QUIC_TLS_PROCESS_STATE;

//
// Creates a new TLS security configuration.
//
_IRQL_requires_max_(PASSIVE_LEVEL)
QUIC_STATUS
QuicTlsServerSecConfigCreate(
    _Inout_ QUIC_RUNDOWN_REF* Rundown,
    _In_ QUIC_SEC_CONFIG_FLAGS Flags,
    _In_opt_ void* Certificate,
    _In_opt_z_ const char* Principal,
    _In_opt_ void* Context,
    _In_ QUIC_SEC_CONFIG_CREATE_COMPLETE_HANDLER CompletionHandler
    );

//
// Creates a new TLS security configuration for client use.
//
_IRQL_requires_max_(PASSIVE_LEVEL)
QUIC_STATUS
QuicTlsClientSecConfigCreate(
    _In_ uint32_t Flags,
    _Outptr_ QUIC_SEC_CONFIG** ClientConfig
    );

//
// Adds a reference to a TLS security configuration.
//
_IRQL_requires_max_(PASSIVE_LEVEL)
QUIC_SEC_CONFIG*
QuicTlsSecConfigAddRef(
    _In_ QUIC_SEC_CONFIG* SecurityConfig
    );

//
// Releases a references on a TLS security configuration and cleans it up
// if it's the last reference.
//
_IRQL_requires_max_(PASSIVE_LEVEL)
void
QUIC_API
QuicTlsSecConfigRelease(
    _In_ QUIC_SEC_CONFIG* SecurityConfig
    );

//
// Initializes a TLS session.
//
_IRQL_requires_max_(PASSIVE_LEVEL)
QUIC_STATUS
QuicTlsSessionInitialize(
    _Out_ QUIC_TLS_SESSION** NewTlsSession
    );

//
// Uninitializes a TLS session.
//
_IRQL_requires_max_(PASSIVE_LEVEL)
void
QuicTlsSessionUninitialize(
    _In_opt_ QUIC_TLS_SESSION* TlsSession
    );

//
// Configures the 0-RTT ticket key (server side).
//
_IRQL_requires_max_(PASSIVE_LEVEL)
QUIC_STATUS
QuicTlsSessionSetTicketKey(
    _In_ QUIC_TLS_SESSION* TlsSession,
    _In_reads_bytes_(44)
        const void* Buffer
    );

//
// Adds a new ticket to the ticket store, from a contiguous buffer.
//
_IRQL_requires_max_(PASSIVE_LEVEL)
QUIC_STATUS
QuicTlsSessionAddTicket(
    _In_ QUIC_TLS_SESSION* TlsSession,
    _In_ uint32_t BufferLength,
    _In_reads_bytes_(BufferLength)
        const uint8_t * const Buffer
    );

//
// Initializes a TLS context.
//
_IRQL_requires_max_(PASSIVE_LEVEL)
QUIC_STATUS
QuicTlsInitialize(
    _In_ const QUIC_TLS_CONFIG* Config,
    _Inout_ QUIC_TLS_PROCESS_STATE* State,
    _Out_ QUIC_TLS** NewTlsContext
    );

//
// Uninitializes an existing TLS context.
//
_IRQL_requires_max_(PASSIVE_LEVEL)
void
QuicTlsUninitialize(
    _In_opt_ QUIC_TLS* TlsContext
    );

//
// Resets an existing TLS interface.
//
_IRQL_requires_max_(PASSIVE_LEVEL)
void
QuicTlsReset(
    _In_ QUIC_TLS* TlsContext
    );

//
// Returns the security configuration used to initialize this TLS.
// Caller must release the ref on the QUIC_SEC_CONFIG.
//
_IRQL_requires_max_(PASSIVE_LEVEL)
QUIC_SEC_CONFIG*
QuicTlsGetSecConfig(
    _In_ QUIC_TLS* TlsContext
    );

//
// Called to process any data received from the peer. In the case of the client,
// the initial call is made with no input buffer to generate the initial output.
// The returned QUIC_TLS_RESULT_FLAGS and QUIC_TLS_PROCESS_STATE are update with
// any state changes as a result of the call. If the call returns
// QUIC_TLS_RESULT_PENDING, then the registered QUIC_TLS_PROCESS_COMPLETE_CALLBACK_HANDLER
// will be triggered at a later date; at which the QUIC code must then call
// QuicTlsProcessDataComplete to complete the operation and get the resulting
// flags.
//
_IRQL_requires_max_(PASSIVE_LEVEL)
QUIC_TLS_RESULT_FLAGS
QuicTlsProcessData(
    _In_ QUIC_TLS* TlsContext,
    _In_ QUIC_TLS_DATA_TYPE DataType,
    _In_reads_bytes_(*BufferLength)
        const uint8_t * Buffer,
    _Inout_ uint32_t * BufferLength,
    _Inout_ QUIC_TLS_PROCESS_STATE* State
    );

//
// Called when in response to receiving a process completed callback.
//
_IRQL_requires_max_(PASSIVE_LEVEL)
QUIC_TLS_RESULT_FLAGS
QuicTlsProcessDataComplete(
    _In_ QUIC_TLS* TlsContext,
    _Out_ uint32_t * ConsumedBuffer
    );

//
// Called to read a TLS ticket.
//
_IRQL_requires_max_(PASSIVE_LEVEL)
QUIC_STATUS
QuicTlsReadTicket(
    _In_ QUIC_TLS* TlsContext,
    _Inout_ uint32_t* BufferLength,
    _Out_writes_bytes_opt_(*BufferLength)
        uint8_t* Buffer
    );

//
// Sets a TLS parameter.
//
_IRQL_requires_max_(PASSIVE_LEVEL)
QUIC_STATUS
QuicTlsParamSet(
    _In_ QUIC_TLS* TlsContext,
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
QuicTlsParamGet(
    _In_ QUIC_TLS* TlsContext,
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
QuicTlsAlpnFindInList(
    _In_ uint16_t AlpnListLength,
    _In_reads_(AlpnListLength)
        const uint8_t* AlpnList,
    _In_ uint8_t FindAlpnLength,
    _In_reads_(FindAlpnLength)
        const uint8_t* FindAlpn
    )
{
    while (AlpnListLength != 0) {
        QUIC_ANALYSIS_ASSUME(AlpnList[0] + 1 <= AlpnListLength);
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
