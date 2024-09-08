/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.

Abstract:

    Private definitions for MsQuic. The are not meant for general consumption
    and are subject to change without warning.

--*/

#pragma once

#ifndef _MSQUICP_
#define _MSQUICP_

#include "msquic.h"

#if defined(__cplusplus)
extern "C" {
#endif

typedef struct CXPLAT_RECV_DATA CXPLAT_RECV_DATA;
typedef struct CXPLAT_SEND_DATA CXPLAT_SEND_DATA;

typedef
_IRQL_requires_max_(DISPATCH_LEVEL)
void
(QUIC_API * QUIC_TEST_DATAPATH_CREATE_HOOK)(
    _Inout_opt_ QUIC_ADDR* RemoteAddress,
    _Inout_opt_ QUIC_ADDR* LocalAddress
    );

typedef
_IRQL_requires_max_(DISPATCH_LEVEL)
void
(QUIC_API * QUIC_TEST_DATAPATH_GET_ADDRESS_HOOK)(
    _Inout_ QUIC_ADDR* Address
    );

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
    QUIC_TEST_DATAPATH_CREATE_HOOK Create;
    QUIC_TEST_DATAPATH_GET_ADDRESS_HOOK GetLocalAddress;
    QUIC_TEST_DATAPATH_GET_ADDRESS_HOOK GetRemoteAddress;
    QUIC_TEST_DATAPATH_RECEIVE_HOOK Receive;
    QUIC_TEST_DATAPATH_SEND_HOOK Send;
} QUIC_TEST_DATAPATH_HOOKS;

#if DEBUG
//
// Datapath hooks are currently only enabled on debug builds for functional
// testing helpers.
//
#define QUIC_TEST_DATAPATH_HOOKS_ENABLED 1

#ifndef QUIC_TEST_OPENSSL_FLAGS // Not supported on OpenSSL currently
//
// Failing test certificates are only available for debug builds
//
#define QUIC_TEST_FAILING_TEST_CERTIFICATES 1
#endif

//
// Allocation failures are currently only enabled on debug builds.
//
#define QUIC_TEST_ALLOC_FAILURES_ENABLED 1

//
// Enable support to disable automatic generation of the version
// negotiation transport parameter.
//
#define QUIC_TEST_DISABLE_VNE_TP_GENERATION 1
#endif

typedef struct QUIC_PRIVATE_TRANSPORT_PARAMETER {
    uint32_t Type;
    uint16_t Length;
    _Field_size_(Length)
    const uint8_t* Buffer;
} QUIC_PRIVATE_TRANSPORT_PARAMETER;

#define QUIC_PARAM_PREFIX_PRIVATE                        0x80000000

//
// The different private parameters for Global.
//

#define QUIC_PARAM_GLOBAL_TEST_DATAPATH_HOOKS           0x81000000  // QUIC_TEST_DATAPATH_HOOKS*
#define QUIC_PARAM_GLOBAL_ALLOC_FAIL_DENOMINATOR        0x81000001  // uint32_t
#define QUIC_PARAM_GLOBAL_ALLOC_FAIL_CYCLE              0x81000002  // uint32_t
#ifdef QUIC_API_ENABLE_PREVIEW_FEATURES
#define QUIC_PARAM_GLOBAL_VERSION_NEGOTIATION_ENABLED   0x81000003  // BOOLEAN
#endif
#define QUIC_PARAM_GLOBAL_IN_USE                        0x81000004  // BOOLEAN
#define QUIC_PARAM_GLOBAL_DATAPATH_FEATURES             0x81000005  // uint32_t
#define QUIC_PARAM_GLOBAL_PLATFORM_WORKER_POOL          0x81000006  // CXPLAT_WORKER_POOL*

//
// The different private parameters for Configuration.
//

#ifdef QUIC_API_ENABLE_PREVIEW_FEATURES
#define QUIC_PARAM_CONFIGURATION_VERSION_NEG_ENABLED    0x83000001  // BOOLEAN
#endif

//
// The different private parameters for Connection.
//

#define QUIC_PARAM_CONN_FORCE_KEY_UPDATE                0x85000000  // No payload
#define QUIC_PARAM_CONN_FORCE_CID_UPDATE                0x85000001  // No payload
#define QUIC_PARAM_CONN_TEST_TRANSPORT_PARAMETER        0x85000002  // QUIC_PRIVATE_TRANSPORT_PARAMETER
#define QUIC_PARAM_CONN_KEEP_ALIVE_PADDING              0x85000003  // uint16_t
#define QUIC_PARAM_CONN_DISABLE_VNE_TP_GENERATION       0x85000004  // BOOLEAN

#ifdef QUIC_API_ENABLE_PREVIEW_FEATURES
#define QUIC_PARAM_STREAM_RELIABLE_OFFSET_RECV          0x88000000  // uint64_t
#endif

#define QUIC_ENABLE_PRIVATE_NMR_PROVIDER(...) \
do { \
    MSQUIC_NPI_ID.Data1 = 0xDEADC0DE; \
} while (FALSE)

#if defined(__cplusplus)
}
#endif

#endif // _MSQUICP_
