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

#if defined(__cplusplus)
}
#endif

#endif // _MSQUICP_
