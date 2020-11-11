/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.

Abstract:

    Private definitions for MsQuic.

--*/

#pragma once

#ifndef _MSQUICP_
#define _MSQUICP_

#include <msquic.h>

#if defined(__cplusplus)
extern "C" {
#endif

typedef struct QUIC_RECV_DATAGRAM QUIC_RECV_DATAGRAM;
typedef struct QUIC_DATAPATH_SEND_CONTEXT QUIC_DATAPATH_SEND_CONTEXT;

//
// Returns TRUE to drop the packet.
//
typedef
_IRQL_requires_max_(DISPATCH_LEVEL)
BOOLEAN
(QUIC_API * QUIC_TEST_DATAPATH_RECEIVE_HOOK)(
    _Inout_ QUIC_RECV_DATAGRAM* Datagram
    );

//
// Returns TRUE to drop the packet.
//
typedef
_IRQL_requires_max_(PASSIVE_LEVEL)
BOOLEAN
(QUIC_API * QUIC_TEST_DATAPATH_SEND_HOOK)(
    _Inout_ QUIC_ADDR* RemoteAddress,
    _Inout_opt_ QUIC_ADDR* LocalAddress,
    _Inout_ QUIC_DATAPATH_SEND_CONTEXT* SendContext
    );

typedef struct QUIC_TEST_DATAPATH_HOOKS {
    QUIC_TEST_DATAPATH_RECEIVE_HOOK Receive;
    QUIC_TEST_DATAPATH_SEND_HOOK Send;
} QUIC_TEST_DATAPATH_HOOKS;

#if DEBUG
//
// Datapath hooks are currently only enabled on debug builds for functional
// testing helpers.
//
#define QUIC_TEST_DATAPATH_HOOKS_ENABLED 1
#endif

typedef struct QUIC_PRIVATE_TRANSPORT_PARAMETER {
    uint16_t Type;
    uint16_t Length;
    _Field_size_(Length)
    const uint8_t* Buffer;
} QUIC_PRIVATE_TRANSPORT_PARAMETER;

typedef enum QUIC_SSLKEYLOG_TYPE {
    SSLKEYLOG_END = 0,
    CLIENT_EARLY_TRAFFIC_SECRET,        // The early traffic secret for the client side
    CLIENT_HANDSHAKE_TRAFFIC_SECRET,    // The handshake traffic secret for the client side
    SERVER_HANDSHAKE_TRAFFIC_SECRET,    // The handshake traffic secret for the server side
    CLIENT_TRAFFIC_SECRET_0,            // The first application traffic secret for the client side
    SERVER_TRAFFIC_SECRET_0,            // The first application traffic secret for the server side
    EARLY_EXPORTER_SECRET,              // The early exporter secret
    EXPORTER_SECRET,                    // The exporter secret
    MAX_SSLKEYLOG_TYPE
} QUIC_SSLKEYLOG_TYPE;

typedef struct QUIC_SSLKEYLOG_ENTRY {
    uint8_t Type;
    uint8_t Length;
    _Field_size_(Length)
    uint8_t TrafficSecret[0];
} QUIC_SSLKEYLOG_ENTRY;

//
// The different private parameters for QUIC_PARAM_LEVEL_GLOBAL.
//

#define QUIC_PARAM_GLOBAL_TEST_DATAPATH_HOOKS           0x80000001  // QUIC_TEST_DATAPATH_HOOKS*

//
// The different private parameters for QUIC_PARAM_LEVEL_CONNECTION.
//

#define QUIC_PARAM_CONN_FORCE_KEY_UPDATE                0x80000001  // No payload
#define QUIC_PARAM_CONN_FORCE_CID_UPDATE                0x80000002  // No payload
#define QUIC_PARAM_CONN_TEST_TRANSPORT_PARAMETER        0x80000003  // QUIC_PRIVATE_TRANSPORT_PARAMETER
#define QUIC_PARAM_CONN_SSLKEYLOG_BUFFER                0x80000004  // Set-only; uint8_t[] >=464 bytes

#if defined(__cplusplus)
}
#endif

#endif // _MSQUICP_
