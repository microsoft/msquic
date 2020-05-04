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

typedef
_IRQL_requires_max_(DISPATCH_LEVEL)
QUIC_STATUS
(QUIC_API * QUIC_TEST_DATAPATH_RECEIVE_CALLBACK)(
    _Inout_ struct QUIC_RECV_DATAGRAM* DatagramChain
    );

typedef
_IRQL_requires_max_(PASSIVE_LEVEL)
QUIC_STATUS
(QUIC_API * QUIC_TEST_DATAPATH_SEND_CALLBACK)(
    _Inout_ QUIC_ADDR* RemoteAddress,
    _Inout_opt_ QUIC_ADDR* LocalAddress,
    _Inout_ struct QUIC_DATAPATH_SEND_CONTEXT* SendContext,
    _Out_ BOOLEAN* Drop
    );

typedef struct QUIC_TEST_DATAPATH_FUNC_TABLE {
    QUIC_TEST_DATAPATH_RECEIVE_CALLBACK Receive;
    QUIC_TEST_DATAPATH_SEND_CALLBACK Send;
} QUIC_TEST_DATAPATH_FUNC_TABLE;

#define QUIC_PARAM_GLOBAL_ENCRYPTION                    0x80000001  // uint8_t (BOOLEAN)
#define QUIC_PARAM_GLOBAL_TEST_DATAPATH_FUNC_TABLE      0x80000002  // QUIC_TEST_DATAPATH_FUNC_TABLE*

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
