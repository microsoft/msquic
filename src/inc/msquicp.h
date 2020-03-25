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
// The different private parameters for QUIC_PARAM_LEVEL_REGISTRATION.
//
#define QUIC_PARAM_REGISTRATION_ENCRYPTION              0x80000001  // uint8_t (BOOLEAN)

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
