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

typedef struct CXPLAT_RECV_DATA CXPLAT_RECV_DATA;
typedef struct CXPLAT_SEND_DATA CXPLAT_SEND_DATA;

//
// Returns TRUE to drop the packet.
//
typedef
_IRQL_requires_max_(DISPATCH_LEVEL)
BOOLEAN
(QUIC_API * QUIC_TEST_DATAPATH_RECEIVE_HOOK)(
    _Inout_ CXPLAT_RECV_DATA* Datagram
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
    _Inout_ CXPLAT_SEND_DATA* SendData
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

//
// Failing test certificates are only available for debug builds
//
#define QUIC_TEST_FAILING_TEST_CERTIFICATES 1
#endif

typedef struct QUIC_PRIVATE_TRANSPORT_PARAMETER {
    uint16_t Type;
    uint16_t Length;
    _Field_size_(Length)
    const uint8_t* Buffer;
} QUIC_PRIVATE_TRANSPORT_PARAMETER;

//
// This struct enables QUIC applications to support SSLKEYLOGFILE
// for debugging packet captures with e.g. Wireshark.
//

#define CXPLAT_TLS_SECRETS_MAX_SECRET_LEN 64
typedef struct CXPLAT_TLS_SECRETS {
    uint8_t SecretLength;
    struct {
        uint8_t ClientRandom : 1;
        uint8_t ClientEarlyTrafficSecret : 1;
        uint8_t ClientHandshakeTrafficSecret : 1;
        uint8_t ServerHandshakeTrafficSecret : 1;
        uint8_t ClientTrafficSecret0 : 1;
        uint8_t ServerTrafficSecret0 : 1;
    } IsSet;
    uint8_t ClientRandom[32];
    uint8_t ClientEarlyTrafficSecret[CXPLAT_TLS_SECRETS_MAX_SECRET_LEN];
    uint8_t ClientHandshakeTrafficSecret[CXPLAT_TLS_SECRETS_MAX_SECRET_LEN];
    uint8_t ServerHandshakeTrafficSecret[CXPLAT_TLS_SECRETS_MAX_SECRET_LEN];
    uint8_t ClientTrafficSecret0[CXPLAT_TLS_SECRETS_MAX_SECRET_LEN];
    uint8_t ServerTrafficSecret0[CXPLAT_TLS_SECRETS_MAX_SECRET_LEN];
} CXPLAT_TLS_SECRETS;

//
// The different private parameters for QUIC_PARAM_LEVEL_GLOBAL.
//

#define QUIC_PARAM_GLOBAL_TEST_DATAPATH_HOOKS           0x80000001  // QUIC_TEST_DATAPATH_HOOKS*
#define QUIC_PARAM_GLOBAL_ALLOC_FAIL_DENOMINATOR        0x80000002  // uint32_t
#define QUIC_PARAM_GLOBAL_ALLOC_FAIL_CYCLE              0x80000003  // uint32_t

//
// The different private parameters for QUIC_PARAM_LEVEL_CONNECTION.
//

#define QUIC_PARAM_CONN_FORCE_KEY_UPDATE                0x80000001  // No payload
#define QUIC_PARAM_CONN_FORCE_CID_UPDATE                0x80000002  // No payload
#define QUIC_PARAM_CONN_TEST_TRANSPORT_PARAMETER        0x80000003  // QUIC_PRIVATE_TRANSPORT_PARAMETER
#define QUIC_PARAM_CONN_TLS_SECRETS                     0x80000004  // CXPLAT_TLS_SECRETS (SSLKEYLOGFILE compatible)

#if defined(__cplusplus)
}
#endif

#endif // _MSQUICP_
