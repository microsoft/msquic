/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.

Abstract:

    MsQuic Listener Wrapper

--*/

#include "precomp.h"
#ifdef QUIC_CLOG
#include "TestListener.cpp.clog.h"
#endif


volatile int64_t NextConnID = 0x10000;

TestListener::TestListener(
    _In_ HQUIC SessionHandle,
    _In_ NEW_CONNECTION_CALLBACK_HANDLER NewConnectionCallbackHandler,
    _In_ bool AsyncSecConfig,
    _In_ bool UseSendBuffer
    ) :
    QuicListener(nullptr), Context(nullptr),
    FilterConnections(false), SetSecConfig(!AsyncSecConfig),
    NewConnectionCallback(NewConnectionCallbackHandler),
    UseSendBuffer(UseSendBuffer)
{
    QUIC_STATUS Status =
        MsQuic->ListenerOpen(
            SessionHandle,
            QuicListenerHandler,
            this,
            &QuicListener);
    if (QUIC_FAILED(Status)) {
        TEST_FAILURE("MsQuic->ListenerOpen failed, 0x%x.", Status);
        QuicListener = nullptr;
    }
}

TestListener::~TestListener()
{
    MsQuic->ListenerClose(QuicListener);
}

QUIC_STATUS
TestListener::Start(
    _In_opt_ const QUIC_ADDR * LocalAddress
    )
{
    return
        MsQuic->ListenerStart(
            QuicListener,
            LocalAddress);
}

void
TestListener::Stop()
{
    MsQuic->ListenerStop(
        QuicListener);
}

//
// Listener Parameters
//

QUIC_STATUS
TestListener::GetLocalAddr(
    _Out_ QuicAddr &localAddr
    )
{
    uint32_t Size = sizeof(localAddr.SockAddr);
    return
        MsQuic->GetParam(
            QuicListener,
            QUIC_PARAM_LEVEL_LISTENER,
            QUIC_PARAM_LISTENER_LOCAL_ADDRESS,
            &Size,
            &localAddr.SockAddr);
}

QUIC_STATUS
TestListener::GetStatistics(
    _Out_ QUIC_LISTENER_STATISTICS &stats
    )
{
    uint32_t Size = sizeof(stats);
    return
        MsQuic->GetParam(
            QuicListener,
            QUIC_PARAM_LEVEL_LISTENER,
            QUIC_PARAM_LISTENER_STATS,
            &Size,
            &stats);
}

QUIC_STATUS
TestListener::HandleListenerEvent(
    _Inout_ QUIC_LISTENER_EVENT* Event
    )
{
    QUIC_STATUS Status = QUIC_STATUS_NOT_SUPPORTED;

    switch (Event->Type) {

    case QUIC_LISTENER_EVENT_NEW_CONNECTION:
        if (Event->NEW_CONNECTION.Info->ServerName != nullptr &&
            _strnicmp(
                QUIC_LOCALHOST_FOR_AF(AF_INET),
                Event->NEW_CONNECTION.Info->ServerName,
                Event->NEW_CONNECTION.Info->ServerNameLength) != 0 &&
            _strnicmp(
                QUIC_LOCALHOST_FOR_AF(AF_INET6),
                Event->NEW_CONNECTION.Info->ServerName,
                Event->NEW_CONNECTION.Info->ServerNameLength) != 0) {
            Status = QUIC_STATUS_NOT_SUPPORTED; // We don't fail the test, just reject the connection.
            break;
        }

        if (Event->NEW_CONNECTION.Connection == nullptr) {
            TEST_FAILURE("Null Connection");
            Status = QUIC_STATUS_INVALID_PARAMETER;
            break;
        }

        if (FilterConnections) {
            Status = QUIC_STATUS_CONNECTION_REFUSED;
            break;
        }

        if (SetSecConfig) {
            Event->NEW_CONNECTION.SecurityConfig = SecurityConfig;
            Status = QUIC_STATUS_SUCCESS;
        } else {
            Status = QUIC_STATUS_PENDING; // The SecConfig will be set later.
        }

        BOOLEAN Opt = UseSendBuffer;
        Status =
            MsQuic->SetParam(
                Event->NEW_CONNECTION.Connection,
                QUIC_PARAM_LEVEL_CONNECTION,
                QUIC_PARAM_CONN_SEND_BUFFERING,
                sizeof(Opt),
                &Opt);
        if (QUIC_FAILED(Status)) {
            TEST_FAILURE("MsQuic->SetParam(CONN_SEND_BUFFERING) failed, 0x%x.", Status);
        }

        if (SetSecConfig) {
            Event->NEW_CONNECTION.SecurityConfig = SecurityConfig;
            Status = QUIC_STATUS_SUCCESS;
        } else {
            Status = QUIC_STATUS_PENDING; // The SecConfig will be set later.
        }

        NewConnectionCallback(
            this,
            Event->NEW_CONNECTION.Connection);
        break;
    }

    return Status;
}