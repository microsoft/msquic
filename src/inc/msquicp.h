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

//
// Disables server certificate validation.
// Used with the QUIC_PARAM_CONN_CERT_VALIDATION_FLAGS parameter.
//
#define QUIC_CERTIFICATE_FLAG_DISABLE_CERT_VALIDATION   0x80000000

//
// The different private parameters for QUIC_PARAM_LEVEL_GLOBAL.
//

//
// Returns TRUE to drop the packet.
//
typedef
_IRQL_requires_max_(DISPATCH_LEVEL)
BOOLEAN
(QUIC_API * QUIC_TEST_DATAPATH_RECEIVE_HOOK)(
    _Inout_ struct QUIC_RECV_DATAGRAM* Datagram
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
    _Inout_ struct QUIC_DATAPATH_SEND_CONTEXT* SendContext
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

#define QUIC_PARAM_GLOBAL_TEST_DATAPATH_HOOKS           0x80000001  // QUIC_TEST_DATAPATH_HOOKS*

//
// The different private parameters for QUIC_PARAM_LEVEL_SESSION.
//
#define QUIC_PARAM_SESSION_ADD_RESUMPTION_STATE         0x80000001  // uint8_t*

//
// The different private parameters for QUIC_PARAM_LEVEL_CONNECTION.
//

typedef struct QUIC_PRIVATE_TRANSPORT_PARAMETER {
    uint16_t Type;
    uint16_t Length;
    _Field_size_(Length)
    const uint8_t* Buffer;
} QUIC_PRIVATE_TRANSPORT_PARAMETER;

#define QUIC_PARAM_CONN_RESUMPTION_STATE                0x80000001  // uint8_t*
#define QUIC_PARAM_CONN_FORCE_KEY_UPDATE                0x80000002  // No payload
#define QUIC_PARAM_CONN_FORCE_CID_UPDATE                0x80000003  // No payload
#define QUIC_PARAM_CONN_TEST_TRANSPORT_PARAMETER        0x80000004  // QUIC_PRIVATE_TRANSPORT_PARAMETER

#if defined(__cplusplus)
}
#endif

#endif // _MSQUICP_
