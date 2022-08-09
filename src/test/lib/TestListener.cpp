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
    _In_ HQUIC Registration,
    _In_ NEW_CONNECTION_CALLBACK_HANDLER NewConnectionCallbackHandler,
    _In_opt_ HQUIC Configuration,
    _In_ const MsQuicAlpn* NewAlpnParam
    ) :
    QuicListener(nullptr),
    QuicConfiguration(Configuration),
    FilterConnections(false),
    NewConnectionCallback(NewConnectionCallbackHandler),
    NewAlpn(NewAlpnParam),
    Context(nullptr)
{
    QUIC_STATUS Status =
        MsQuic->ListenerOpen(
            Registration,
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
    _In_reads_(AlpnBufferCount) _Pre_defensive_
        const QUIC_BUFFER* const AlpnBuffers,
    _In_range_(>, 0) uint32_t AlpnBufferCount,
    _In_opt_ const QUIC_ADDR* LocalAddress
    )
{
    return
        MsQuic->ListenerStart(
            QuicListener,
            AlpnBuffers,
            AlpnBufferCount,
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
                QUIC_TEST_LOOPBACK_FOR_AF(QUIC_ADDRESS_FAMILY_INET),
                Event->NEW_CONNECTION.Info->ServerName,
                Event->NEW_CONNECTION.Info->ServerNameLength) != 0 &&
            _strnicmp(
                QUIC_TEST_LOOPBACK_FOR_AF(QUIC_ADDRESS_FAMILY_INET6),
                Event->NEW_CONNECTION.Info->ServerName,
                Event->NEW_CONNECTION.Info->ServerNameLength) != 0 &&
            _strnicmp(
                QUIC_LOCALHOST_FOR_AF(QUIC_ADDRESS_FAMILY_INET),
                Event->NEW_CONNECTION.Info->ServerName,
                Event->NEW_CONNECTION.Info->ServerNameLength) != 0 &&
            _strnicmp(
                QUIC_LOCALHOST_FOR_AF(QUIC_ADDRESS_FAMILY_INET6),
                Event->NEW_CONNECTION.Info->ServerName,
                Event->NEW_CONNECTION.Info->ServerNameLength) != 0) {
            break; // We don't fail the test, just reject the connection.
        }

        if (Event->NEW_CONNECTION.Connection == nullptr) {
            TEST_FAILURE("Null Connection");
            Status = QUIC_STATUS_INVALID_PARAMETER;
            break;
        }

        if (NewAlpn) {
            auto& NewConn = Event->NEW_CONNECTION;
            auto Buffer = static_cast<const QUIC_BUFFER*>(*NewAlpn);
            auto Length = Buffer[0].Length;
            uint16_t AlpnListLength = NewConn.Info->ClientAlpnListLength;
            const uint8_t* AlpnList = NewConn.Info->ClientAlpnList;
            while (AlpnListLength != 0) {
                if (AlpnList[0] == Length &&
                    memcmp(AlpnList+1, Buffer[0].Buffer, Length) == 0) {
                    NewConn.NewNegotiatedAlpn = AlpnList;
                    break;
                }
                AlpnListLength -= AlpnList[0] + 1;
                AlpnList += (size_t)AlpnList[0] + (size_t)1;
            }
        }

        if (FilterConnections ||
            !NewConnectionCallback(
                this,
                Event->NEW_CONNECTION.Connection)) {
            Status = QUIC_STATUS_CONNECTION_REFUSED;
            break;
        }

        if (QuicConfiguration) {
            Status =
                MsQuic->ConnectionSetConfiguration(
                    Event->NEW_CONNECTION.Connection,
                    QuicConfiguration);
            if (QUIC_FAILED(Status)) {
                TEST_FAILURE("MsQuic->ConnectionSetConfiguration failed, 0x%x.", Status);
                break;
            }
        }

        Status = QUIC_STATUS_SUCCESS;
        break;

    default:
        break;
    }

    return Status;
}
