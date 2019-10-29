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
// Private API Version Definition.
//
#define QUIC_API_VERSION_PRIVATE            0x00008000

#define QUIC_EXEC_PROF_TYPE_LOW_LATENCY     0x00000000
#define QUIC_EXEC_PROF_TYPE_MAX_THROUGHPUT  0x00000001
#define QUIC_EXEC_PROF_TYPE_SCAVENGER       0x00000002
#define QUIC_EXEC_PROF_TYPE_REAL_TIME       0x00000003

typedef struct _QUIC_EXEC_PROFILE {
    uint8_t Type; // QUIC_EXEC_PROF_TYPE_*
} QUIC_EXEC_PROFILE;

typedef
_IRQL_requires_max_(PASSIVE_LEVEL)
QUIC_STATUS
(QUIC_API * QUIC_REGISTRATION_OPEN_FN_PRIV)(
    _In_opt_z_ const char* AppName,
    _In_opt_ const QUIC_EXEC_PROFILE* ExecProfile,
    _Outptr_ _At_(*Registration, __drv_allocatesMem(Mem)) _Pre_defensive_
        HQUIC* Registration
    );

typedef struct _QUIC_API_PRIVATE {

    uint32_t                            Version;            // QUIC_API_VERSION_1

    QUIC_SET_CONTEXT_FN                 SetContext;
    QUIC_GET_CONTEXT_FN                 GetContext;
    QUIC_SET_CALLBACK_HANDLER_FN        SetCallbackHandler;

    QUIC_SET_PARAM_FN                   SetParam;
    QUIC_GET_PARAM_FN                   GetParam;

    QUIC_REGISTRATION_OPEN_FN_PRIV      RegistrationOpen;
    QUIC_REGISTRATION_CLOSE_FN          RegistrationClose;

    QUIC_SEC_CONFIG_CREATE_FN           SecConfigCreate;
    QUIC_SEC_CONFIG_DELETE_FN           SecConfigDelete;

    QUIC_SESSION_OPEN_FN                SessionOpen;
    QUIC_SESSION_CLOSE_FN               SessionClose;
    QUIC_SESSION_SHUTDOWN_FN            SessionShutdown;

    QUIC_LISTENER_OPEN_FN               ListenerOpen;
    QUIC_LISTENER_CLOSE_FN              ListenerClose;
    QUIC_LISTENER_START_FN              ListenerStart;
    QUIC_LISTENER_STOP_FN               ListenerStop;

    QUIC_CONNECTION_OPEN_FN             ConnectionOpen;
    QUIC_CONNECTION_CLOSE_FN            ConnectionClose;
    QUIC_CONNECTION_SHUTDOWN_FN         ConnectionShutdown;
    QUIC_CONNECTION_START_FN            ConnectionStart;

    QUIC_STREAM_OPEN_FN                 StreamOpen;
    QUIC_STREAM_CLOSE_FN                StreamClose;
    QUIC_STREAM_START_FN                StreamStart;
    QUIC_STREAM_SHUTDOWN_FN             StreamShutdown;
    QUIC_STREAM_SEND_FN                 StreamSend;
    QUIC_STREAM_RECEIVE_COMPLETE_FN     StreamReceiveComplete;
    QUIC_STREAM_RECEIVE_SET_ENABLED_FN  StreamReceiveSetEnabled;

} QUIC_API_PRIVATE;

inline
QUIC_STATUS
QUIC_API
MsQuicOpenPriv(
    _Out_ QUIC_API_PRIVATE** QuicApi
    )
{
    return MsQuicOpen(QUIC_API_VERSION_PRIVATE, (void**)QuicApi);
}

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
#define QUIC_PARAM_CONN_RESUMPTION_STATE                0x80000001  // uint8_t*
#define QUIC_PARAM_CONN_FORCE_KEY_UPDATE                0x80000002  // No payload
#define QUIC_PARAM_CONN_FORCE_CID_UPDATE                0x80000003  // No payload

#if defined(__cplusplus)
}
#endif

#endif // _MSQUICP_
