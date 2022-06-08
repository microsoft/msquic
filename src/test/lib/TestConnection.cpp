/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.

Abstract:

    MsQuic Connection Wrapper

--*/

#include "precomp.h"
#ifdef QUIC_CLOG
#include "TestConnection.cpp.clog.h"
#endif

TestConnection::TestConnection(
    _In_ HQUIC Handle,
    _In_opt_ NEW_STREAM_CALLBACK_HANDLER NewStreamCallbackHandler
    ) :
    QuicConnection(Handle),
    IsServer(true), IsStarted(true), IsConnected(false), Resumed(false),
    PeerAddrChanged(false), PeerClosed(false), TransportClosed(false),
    IsShutdown(false), ShutdownTimedOut(false), AutoDelete(false), AsyncCustomValidation(false),
    CustomValidationResultSet(false), ExpectedResumed(false),
    ExpectedTransportCloseStatus(QUIC_STATUS_SUCCESS), ExpectedPeerCloseErrorCode(QUIC_TEST_NO_ERROR),
    ExpectedClientCertValidationResult(QUIC_STATUS_SUCCESS), ExpectedCustomValidationResult(false),
    PeerCertEventReturnStatus(QUIC_STATUS_SUCCESS),
    EventDeleted(nullptr),
    NewStreamCallback(NewStreamCallbackHandler), ShutdownCompleteCallback(nullptr),
    DatagramsSent(0), DatagramsCanceled(0), DatagramsSuspectLost(0),
    DatagramsLost(0), DatagramsAcknowledged(0), Context(nullptr)
{
    CxPlatEventInitialize(&EventConnectionComplete, TRUE, FALSE);
    CxPlatEventInitialize(&EventPeerClosed, TRUE, FALSE);
    CxPlatEventInitialize(&EventShutdownComplete, TRUE, FALSE);
    CxPlatEventInitialize(&EventResumptionTicketReceived, TRUE, FALSE);

    if (QuicConnection == nullptr) {
        TEST_FAILURE("Invalid handle passed into TestConnection.");
    } else {
        MsQuic->SetCallbackHandler(QuicConnection, (void*)QuicConnectionHandler, this);
    }
}

TestConnection::TestConnection(
    _In_ MsQuicRegistration& Registration,
    _In_opt_ NEW_STREAM_CALLBACK_HANDLER NewStreamCallbackHandler
    ) :
    QuicConnection(nullptr),
    IsServer(false), IsStarted(false), IsConnected(false), Resumed(false),
    PeerAddrChanged(false), PeerClosed(false), TransportClosed(false),
    IsShutdown(false), ShutdownTimedOut(false), AutoDelete(false), AsyncCustomValidation(false),
    CustomValidationResultSet(false), ExpectedResumed(false),
    ExpectedTransportCloseStatus(QUIC_STATUS_SUCCESS), ExpectedPeerCloseErrorCode(QUIC_TEST_NO_ERROR),
    ExpectedClientCertValidationResult(QUIC_STATUS_SUCCESS), ExpectedCustomValidationResult(false),
    PeerCertEventReturnStatus(QUIC_STATUS_SUCCESS),
    EventDeleted(nullptr),
    NewStreamCallback(NewStreamCallbackHandler), ShutdownCompleteCallback(nullptr),
    DatagramsSent(0), DatagramsCanceled(0), DatagramsSuspectLost(0),
    DatagramsLost(0), DatagramsAcknowledged(0), Context(nullptr)
{
    CxPlatEventInitialize(&EventConnectionComplete, TRUE, FALSE);
    CxPlatEventInitialize(&EventPeerClosed, TRUE, FALSE);
    CxPlatEventInitialize(&EventShutdownComplete, TRUE, FALSE);
    CxPlatEventInitialize(&EventResumptionTicketReceived, TRUE, FALSE);

    QUIC_STATUS Status =
        MsQuic->ConnectionOpen(
            Registration,
            QuicConnectionHandler,
            this,
            &QuicConnection);
    if (QUIC_FAILED(Status)) {
        TEST_FAILURE("MsQuic->ConnectionOpen failed, 0x%x.", Status);
        QuicConnection = nullptr;
    }
}

TestConnection::~TestConnection()
{
    MsQuic->ConnectionClose(QuicConnection);
    CxPlatEventUninitialize(EventResumptionTicketReceived);
    CxPlatEventUninitialize(EventShutdownComplete);
    CxPlatEventUninitialize(EventPeerClosed);
    CxPlatEventUninitialize(EventConnectionComplete);
    if (ResumptionTicket) {
        CXPLAT_FREE(ResumptionTicket, QUIC_POOL_TEST);
    }
    if (EventDeleted) {
        CxPlatEventSet(*EventDeleted);
    }
}

QUIC_STATUS
TestConnection::Start(
    _In_ HQUIC Configuration,
    _In_ QUIC_ADDRESS_FAMILY Family,
    _In_opt_z_ const char* ServerName,
    _In_ uint16_t ServerPort // Host byte order
    )
{
    QUIC_STATUS Status;
    if (QUIC_SUCCEEDED(
        Status = MsQuic->ConnectionStart(
            QuicConnection,
            Configuration,
            Family,
            ServerName,
            ServerPort))) {
        IsStarted = true;
        return Status;
    }
    return Status;
}

void
TestConnection::Shutdown(
    _In_ QUIC_CONNECTION_SHUTDOWN_FLAGS Flags,
    _In_ QUIC_UINT62 ErrorCode
    )
{
    MsQuic->ConnectionShutdown(
        QuicConnection,
        Flags,
        ErrorCode);
}

TestStream*
TestConnection::NewStream(
    _In_opt_ STREAM_SHUTDOWN_CALLBACK_HANDLER StreamShutdownHandler,
    _In_ QUIC_STREAM_OPEN_FLAGS Flags,
    _In_ NEW_STREAM_START_TYPE StartType
    )
{
    auto Stream = TestStream::FromConnectionHandle(QuicConnection, StreamShutdownHandler, Flags);

    if (Stream == nullptr) {
        // Failure reason has already been logged by FromConnectionHandle
        return nullptr;
    }

    if (StartType != NEW_STREAM_START_NONE) {
        QUIC_STATUS Status =
            Stream->Start(QUIC_STREAM_START_FLAG_NONE);
        if (QUIC_FAILED(Status)) {
            TEST_FAILURE("MsQuic->StreamStart failed, 0x%x.", Status);
            delete Stream;
            return nullptr;
        }
    }

    return Stream;
}

bool
TestConnection::WaitForConnectionComplete()
{
    if (!CxPlatEventWaitWithTimeout(EventConnectionComplete, GetWaitTimeout())) {
        TEST_FAILURE("WaitForConnectionComplete timed out after %u ms.", GetWaitTimeout());
        return false;
    }
    return true;
}

QUIC_BUFFER*
TestConnection::WaitForResumptionTicket()
{
    if (!CxPlatEventWaitWithTimeout(EventResumptionTicketReceived, GetWaitTimeout())) {
        TEST_FAILURE("WaitForResumptionTicket timed out after %u ms.", GetWaitTimeout());
        return nullptr;
    }
    auto Ticket = ResumptionTicket;
    ResumptionTicket = nullptr;
    return Ticket;
}

bool
TestConnection::WaitForShutdownComplete()
{
    if (IsStarted) {
        if (!CxPlatEventWaitWithTimeout(EventShutdownComplete, GetWaitTimeout())) {
            TEST_FAILURE("WaitForShutdownComplete timed out after %u ms.", GetWaitTimeout());
            return false;
        }
    }
    return true;
}

bool
TestConnection::WaitForPeerClose()
{
    if (!CxPlatEventWaitWithTimeout(EventPeerClosed, GetWaitTimeout())) {
        TEST_FAILURE("WaitForPeerClose timed out after %u ms.", GetWaitTimeout());
        return false;
    }
    return true;
}

//
// Connection Parameters
//

QUIC_STATUS
TestConnection::ForceKeyUpdate()
{
    QUIC_STATUS Status;
    uint32_t Try = 0;

    do {
        //
        // Forcing a key update is only allowed when the handshake is confirmed.
        // So, even if the caller waits for connection complete, it's possible
        // the call can fail with QUIC_STATUS_INVALID_STATE. To get around this
        // we allow for a couple retries (with some sleeps).
        //
        if (Try != 0) {
            CxPlatSleep(100);
        }
        Status =
            MsQuic->SetParam(
                QuicConnection,
                QUIC_PARAM_CONN_FORCE_KEY_UPDATE,
                0,
                nullptr);

    } while (Status == QUIC_STATUS_INVALID_STATE && ++Try <= 20);

    return Status;
}

QUIC_STATUS
TestConnection::ForceCidUpdate()
{
    QUIC_STATUS Status;
    uint32_t Try = 0;

    do {
        //
        // Forcing a CID update is only allowed when the handshake is confirmed.
        // So, even if the caller waits for connection complete, it's possible
        // the call can fail with QUIC_STATUS_INVALID_STATE. To get around this
        // we allow for a couple retries (with some sleeps).
        //
        if (Try != 0) {
            CxPlatSleep(100);
        }
        Status =
            MsQuic->SetParam(
                QuicConnection,
                QUIC_PARAM_CONN_FORCE_CID_UPDATE,
                0,
                nullptr);

    } while (Status == QUIC_STATUS_INVALID_STATE && ++Try <= 20);

    return Status;
}

QUIC_STATUS
TestConnection::SetTestTransportParameter(
    _In_ const QUIC_PRIVATE_TRANSPORT_PARAMETER* TransportParameter
    )
{
    return
        MsQuic->SetParam(
            QuicConnection,
            QUIC_PARAM_CONN_TEST_TRANSPORT_PARAMETER,
            sizeof(*TransportParameter),
            TransportParameter);
}

uint32_t
TestConnection::GetQuicVersion()
{
    uint32_t value;
    uint32_t valueSize = sizeof(value);
    QUIC_STATUS Status =
        MsQuic->GetParam(
            QuicConnection,
            QUIC_PARAM_CONN_QUIC_VERSION,
            &valueSize,
            &value);
    if (QUIC_FAILED(Status)) {
        value = 0;
        TEST_FAILURE("MsQuic->GetParam(CONN_QUIC_VERSION) failed, 0x%x.", Status);
    }
    return value;
}

QUIC_STATUS
TestConnection::SetQuicVersion(
    uint32_t value
    )
{
    MsQuicVersionSettings Settings;
    Settings.AcceptableVersions = &value;
    Settings.AcceptableVersionsLength = 1;
    Settings.OfferedVersions = &value;
    Settings.OfferedVersionsLength = 1;
    Settings.FullyDeployedVersions = &value;
    Settings.FullyDeployedVersionsLength = 1;
    return
        MsQuic->SetParam(
            QuicConnection,
            QUIC_PARAM_CONN_VERSION_SETTINGS,
            sizeof(Settings),
            &Settings);
}

QUIC_STATUS
TestConnection::GetLocalAddr(
    _Out_ QuicAddr &localAddr
    )
{
    uint32_t Size = sizeof(localAddr.SockAddr);
    return
        MsQuic->GetParam(
            QuicConnection,
            QUIC_PARAM_CONN_LOCAL_ADDRESS,
            &Size,
            &localAddr.SockAddr);
}

QUIC_STATUS
TestConnection::SetLocalAddr(
    _In_ const QuicAddr &localAddr
    )
{
    QUIC_STATUS Status;
    uint32_t Try = 0;
    uint32_t Size = sizeof(localAddr.SockAddr);

    do {
        //
        // If setting the new local address right after handshake complete, it's
        // possible the handshake hasn't been confirmed yet, and this call will
        // fail with QUIC_STATUS_INVALID_STATE (because the client's not allowed
        // to change IP until handshake confirmation). To get around this we
        // allow for a couple retries (with some sleeps).
        //
        if (Try != 0) {
            CxPlatSleep(100);
        }
        Status =
            MsQuic->SetParam(
                QuicConnection,
                QUIC_PARAM_CONN_LOCAL_ADDRESS,
                Size,
                &localAddr.SockAddr);

    } while (Status == QUIC_STATUS_INVALID_STATE && ++Try <= 3);

    return Status;
}

QUIC_STATUS
TestConnection::GetRemoteAddr(
    _Out_  QuicAddr &remoteAddr
    )
{
    uint32_t Size = sizeof(remoteAddr.SockAddr);
    return
        MsQuic->GetParam(
            QuicConnection,
            QUIC_PARAM_CONN_REMOTE_ADDRESS,
            &Size,
            &remoteAddr.SockAddr);
}

QUIC_STATUS
TestConnection::SetRemoteAddr(
    _In_ const QuicAddr &remoteAddr
    )
{
    return
        MsQuic->SetParam(
            QuicConnection,
            QUIC_PARAM_CONN_REMOTE_ADDRESS,
            sizeof(remoteAddr.SockAddr),
            &remoteAddr.SockAddr);
}

QUIC_SETTINGS
TestConnection::GetSettings() const
{
    QUIC_SETTINGS value;
    uint32_t valueSize = sizeof(value);
    QUIC_STATUS Status =
        MsQuic->GetParam(
            QuicConnection,
            QUIC_PARAM_CONN_SETTINGS,
            &valueSize,
            &value);
    if (QUIC_FAILED(Status)) {
        TEST_FAILURE("MsQuic->GetParam(CONN_SETTINGS) failed, 0x%x.", Status);
    }
    return value;
}

QUIC_STATUS
TestConnection::SetSettings(
    _In_ const QUIC_SETTINGS& value
    )
{
    return
        MsQuic->SetParam(
            QuicConnection,
            QUIC_PARAM_CONN_SETTINGS,
            sizeof(value),
            &value);
}

uint64_t
TestConnection::GetIdleTimeout()
{
    return GetSettings().IdleTimeoutMs;
}

QUIC_STATUS
TestConnection::SetIdleTimeout(
    uint64_t value
    )
{
    QUIC_SETTINGS Settings{0};
    Settings.IdleTimeoutMs = value;
    Settings.IsSet.IdleTimeoutMs = TRUE;
    return SetSettings(Settings);
}

uint32_t
TestConnection::GetDisconnectTimeout()
{
    return GetSettings().DisconnectTimeoutMs;
}

QUIC_STATUS
TestConnection::SetDisconnectTimeout(
    uint32_t value
    )
{
    QUIC_SETTINGS Settings{0};
    Settings.DisconnectTimeoutMs = value;
    Settings.IsSet.DisconnectTimeoutMs = TRUE;
    return SetSettings(Settings);
}

uint16_t
TestConnection::GetPeerBidiStreamCount()
{
    return GetSettings().PeerBidiStreamCount;
}

QUIC_STATUS
TestConnection::SetPeerBidiStreamCount(
    uint16_t value
    )
{
    QUIC_SETTINGS Settings{0};
    Settings.PeerBidiStreamCount = value;
    Settings.IsSet.PeerBidiStreamCount = TRUE;
    return SetSettings(Settings);
}

uint16_t
TestConnection::GetPeerUnidiStreamCount()
{
    return GetSettings().PeerUnidiStreamCount;
}

QUIC_STATUS
TestConnection::SetPeerUnidiStreamCount(
    uint16_t value
    )
{
    QUIC_SETTINGS Settings{0};
    Settings.PeerUnidiStreamCount = value;
    Settings.IsSet.PeerUnidiStreamCount = TRUE;
    return SetSettings(Settings);
}

uint16_t
TestConnection::GetLocalBidiStreamCount()
{
    uint16_t value;
    uint32_t valueSize = sizeof(value);
    QUIC_STATUS Status =
        MsQuic->GetParam(
            QuicConnection,
            QUIC_PARAM_CONN_LOCAL_BIDI_STREAM_COUNT,
            &valueSize,
            &value);
    if (QUIC_FAILED(Status)) {
        value = 0;
        TEST_FAILURE("MsQuic->GetParam(CONN_LOCAL_BIDI_STREAM_COUNT) failed, 0x%x.", Status);
    }
    return value;
}

uint16_t
TestConnection::GetLocalUnidiStreamCount()
{
    uint16_t value;
    uint32_t valueSize = sizeof(value);
    QUIC_STATUS Status =
        MsQuic->GetParam(
            QuicConnection,
            QUIC_PARAM_CONN_LOCAL_UNIDI_STREAM_COUNT,
            &valueSize,
            &value);
    if (QUIC_FAILED(Status)) {
        value = 0;
        TEST_FAILURE("MsQuic->GetParam(CONN_LOCAL_UNIDI_STREAM_COUNT) failed, 0x%x.", Status);
    }
    return value;
}

QUIC_STATISTICS_V2
TestConnection::GetStatistics()
{
    QUIC_STATISTICS_V2 value = {};
    uint32_t valueSize = sizeof(value);
    QUIC_STATUS Status =
        MsQuic->GetParam(
            QuicConnection,
            QUIC_PARAM_CONN_STATISTICS_V2,
            &valueSize,
            &value);
    if (QUIC_FAILED(Status)) {
        TEST_FAILURE("MsQuic->GetParam(CONN_STATISTICS) failed, 0x%x.", Status);
    }
    return value;
}

bool
TestConnection::GetUseSendBuffer()
{
    return GetSettings().SendBufferingEnabled;
}

QUIC_STATUS
TestConnection::SetUseSendBuffer(
    bool value
    )
{
    QUIC_SETTINGS Settings{0};
    Settings.SendBufferingEnabled = value ? TRUE : FALSE;
    Settings.IsSet.SendBufferingEnabled = TRUE;
    return SetSettings(Settings);
}

uint32_t
TestConnection::GetKeepAlive()
{
    return GetSettings().KeepAliveIntervalMs;
}

QUIC_STATUS
TestConnection::SetKeepAlive(
    uint32_t value
    )
{
    QUIC_SETTINGS Settings{0};
    Settings.KeepAliveIntervalMs = value;
    Settings.IsSet.KeepAliveIntervalMs = TRUE;
    return SetSettings(Settings);
}

bool
TestConnection::GetShareUdpBinding()
{
    BOOLEAN value;
    uint32_t valueSize = sizeof(value);
    QUIC_STATUS Status =
        MsQuic->GetParam(
            QuicConnection,
            QUIC_PARAM_CONN_SHARE_UDP_BINDING,
            &valueSize,
            &value);
    if (QUIC_FAILED(Status)) {
        value = 0;
        TEST_FAILURE("MsQuic->GetParam(CONN_SHARE_UDP_BINDING) failed, 0x%x.", Status);
    }
    return value != FALSE;
}

QUIC_STATUS
TestConnection::SetShareUdpBinding(
    bool value
    )
{
    BOOLEAN bValue = value ? TRUE : FALSE;
    return
        MsQuic->SetParam(
            QuicConnection,
            QUIC_PARAM_CONN_SHARE_UDP_BINDING,
            sizeof(bValue),
            &bValue);
}

bool
TestConnection::GetDatagramReceiveEnabled()
{
    BOOLEAN value;
    uint32_t valueSize = sizeof(value);
    QUIC_STATUS Status =
        MsQuic->GetParam(
            QuicConnection,
            QUIC_PARAM_CONN_DATAGRAM_RECEIVE_ENABLED,
            &valueSize,
            &value);
    if (QUIC_FAILED(Status)) {
        value = 0;
        TEST_FAILURE("MsQuic->GetParam(CONN_DATAGRAM_RECEIVE_ENABLED) failed, 0x%x.", Status);
    }
    return value != FALSE;
}

QUIC_STATUS
TestConnection::SetDatagramReceiveEnabled(
    bool value
    )
{
    BOOLEAN bValue = value ? TRUE : FALSE;
    return
        MsQuic->SetParam(
            QuicConnection,
            QUIC_PARAM_CONN_DATAGRAM_RECEIVE_ENABLED,
            sizeof(bValue),
            &bValue);
}

bool
TestConnection::GetDatagramSendEnabled()
{
    BOOLEAN value;
    uint32_t valueSize = sizeof(value);
    QUIC_STATUS Status =
        MsQuic->GetParam(
            QuicConnection,
            QUIC_PARAM_CONN_DATAGRAM_SEND_ENABLED,
            &valueSize,
            &value);
    if (QUIC_FAILED(Status)) {
        value = 0;
        TEST_FAILURE("MsQuic->GetParam(CONN_DATAGRAM_SEND_ENABLED) failed, 0x%x.", Status);
    }
    return value != FALSE;
}

QUIC_STREAM_SCHEDULING_SCHEME
TestConnection::GetPriorityScheme()
{
    QUIC_STREAM_SCHEDULING_SCHEME value;
    uint32_t valueSize = sizeof(value);
    QUIC_STATUS Status =
        MsQuic->GetParam(
            QuicConnection,
            QUIC_PARAM_CONN_STREAM_SCHEDULING_SCHEME,
            &valueSize,
            &value);
    if (QUIC_FAILED(Status)) {
        value = QUIC_STREAM_SCHEDULING_SCHEME_FIFO;
        TEST_FAILURE("MsQuic->GetParam(CONN_PRIORITY_SCHEME) failed, 0x%x.", Status);
    }
    return value;
}

QUIC_STATUS
TestConnection::SetPriorityScheme(
    QUIC_STREAM_SCHEDULING_SCHEME value
    )
{
    return
        MsQuic->SetParam(
            QuicConnection,
            QUIC_PARAM_CONN_STREAM_SCHEDULING_SCHEME,
            sizeof(value),
            &value);
}

QUIC_STATUS
TestConnection::SetConfiguration(
    HQUIC value
    )
{
    return
        MsQuic->ConnectionSetConfiguration(
            QuicConnection,
            value);
}

QUIC_STATUS
TestConnection::SetResumptionTicket(
    const QUIC_BUFFER* NewResumptionTicket
    ) const
{
    return
        MsQuic->SetParam(
            QuicConnection,
            QUIC_PARAM_CONN_RESUMPTION_TICKET,
            NewResumptionTicket->Length,
            NewResumptionTicket->Buffer);
}

QUIC_STATUS
TestConnection::SetCustomValidationResult(
    bool AcceptCert
    )
{
    BOOLEAN Result = AcceptCert ? TRUE : FALSE;
    return
        MsQuic->SetParam(
            QuicConnection,
            QUIC_PARAM_CONN_PEER_CERTIFICATE_VALID,
            sizeof(Result),
            &Result);
}

QUIC_STATUS
TestConnection::HandleConnectionEvent(
    _Inout_ QUIC_CONNECTION_EVENT* Event
    )
{
    switch (Event->Type) {

    case QUIC_CONNECTION_EVENT_CONNECTED:
        IsConnected = true;
        Resumed = Event->CONNECTED.SessionResumed != FALSE;
        if (!Resumed && ExpectedResumed) {
            TEST_FAILURE("Resumption was expected!");
        }
        if (IsServer) {
            MsQuic->ConnectionSendResumptionTicket(QuicConnection, QUIC_SEND_RESUMPTION_FLAG_FINAL, 0, nullptr);
        }
        CxPlatEventSet(EventConnectionComplete);
        break;

    case QUIC_CONNECTION_EVENT_SHUTDOWN_INITIATED_BY_TRANSPORT:
        TransportClosed = true;
        TransportCloseStatus = Event->SHUTDOWN_INITIATED_BY_TRANSPORT.Status;
        if (Event->SHUTDOWN_INITIATED_BY_TRANSPORT.Status != ExpectedTransportCloseStatus) {
            bool IsTimeoutStatus =
                Event->SHUTDOWN_INITIATED_BY_TRANSPORT.Status == QUIC_STATUS_CONNECTION_TIMEOUT ||
                Event->SHUTDOWN_INITIATED_BY_TRANSPORT.Status == QUIC_STATUS_CONNECTION_IDLE;
            if (IsTimeoutStatus && HasRandomLoss) {
                //
                // Ignoring unexpected status because of random loss
                //
                QuicTraceLogInfo(
                    TestIgnoreConnectionTimeout,
                    "[test] Ignoring timeout unexpected status because of random loss");
            } else {
                TEST_FAILURE(
                    "Unexpected transport Close Error, expected=0x%x, actual=0x%x",
                    ExpectedTransportCloseStatus,
                    Event->SHUTDOWN_INITIATED_BY_TRANSPORT.Status);
            }
        }
        CxPlatEventSet(EventConnectionComplete);
        break;

    case QUIC_CONNECTION_EVENT_SHUTDOWN_INITIATED_BY_PEER:
        PeerClosed = true;
        PeerCloseErrorCode = Event->SHUTDOWN_INITIATED_BY_PEER.ErrorCode;
        if (Event->SHUTDOWN_INITIATED_BY_PEER.ErrorCode != ExpectedPeerCloseErrorCode) {
            TEST_FAILURE(
                "Unexpected App Close Error, expected=%llu, actual=%llu",
                ExpectedPeerCloseErrorCode,
                Event->SHUTDOWN_INITIATED_BY_PEER.ErrorCode);
        }
        CxPlatEventSet(EventConnectionComplete);
        CxPlatEventSet(EventPeerClosed);
        break;

    case QUIC_CONNECTION_EVENT_SHUTDOWN_COMPLETE:
        IsShutdown = TRUE;
        ShutdownTimedOut = Event->SHUTDOWN_COMPLETE.PeerAcknowledgedShutdown == FALSE;
        CxPlatEventSet(EventShutdownComplete);
        if (ShutdownCompleteCallback) {
            ShutdownCompleteCallback(this);
        }
        if (AutoDelete) {
            delete this;
        }
        break;

    case QUIC_CONNECTION_EVENT_PEER_ADDRESS_CHANGED:
        PeerAddrChanged = true;
        break;

    case QUIC_CONNECTION_EVENT_PEER_STREAM_STARTED:
        if (Event->PEER_STREAM_STARTED.Stream == nullptr) {
            TEST_FAILURE("Null Stream");
            break;
        }
        if (NewStreamCallback == nullptr) {
            //
            // Test is ignoring streams. Just close it.
            //
            MsQuic->StreamClose(Event->PEER_STREAM_STARTED.Stream);
            break;
        }
        NewStreamCallback(
            this,
            Event->PEER_STREAM_STARTED.Stream,
            Event->PEER_STREAM_STARTED.Flags);
        break;

    case QUIC_CONNECTION_EVENT_DATAGRAM_SEND_STATE_CHANGED:
        switch (Event->DATAGRAM_SEND_STATE_CHANGED.State) {
        case QUIC_DATAGRAM_SEND_UNKNOWN:
            break;
        case QUIC_DATAGRAM_SEND_SENT:
            DatagramsSent++;
            break;
        case QUIC_DATAGRAM_SEND_LOST_SUSPECT:
            DatagramsSuspectLost++;
            break;
        case QUIC_DATAGRAM_SEND_LOST_DISCARDED:
            DatagramsLost++;
            break;
        case QUIC_DATAGRAM_SEND_ACKNOWLEDGED:
        case QUIC_DATAGRAM_SEND_ACKNOWLEDGED_SPURIOUS:
            DatagramsAcknowledged++;
            break;
        case QUIC_DATAGRAM_SEND_CANCELED:
            DatagramsCanceled++;
            break;
        }
        break;

    case QUIC_CONNECTION_EVENT_DATAGRAM_STATE_CHANGED:
        // Use This
        break;

    case QUIC_CONNECTION_EVENT_RESUMPTION_TICKET_RECEIVED:
        ResumptionTicket =
            (QUIC_BUFFER*)
            CXPLAT_ALLOC_NONPAGED(
                sizeof(QUIC_BUFFER) +
                Event->RESUMPTION_TICKET_RECEIVED.ResumptionTicketLength,
                QUIC_POOL_TEST);
        if (ResumptionTicket) {
            ResumptionTicket->Buffer = (uint8_t*)(ResumptionTicket + 1);
            ResumptionTicket->Length = Event->RESUMPTION_TICKET_RECEIVED.ResumptionTicketLength;
            CxPlatCopyMemory(
                ResumptionTicket->Buffer,
                Event->RESUMPTION_TICKET_RECEIVED.ResumptionTicket,
                Event->RESUMPTION_TICKET_RECEIVED.ResumptionTicketLength);
            CxPlatEventSet(EventResumptionTicketReceived);
        }
        break;

    case QUIC_CONNECTION_EVENT_PEER_CERTIFICATE_RECEIVED:
        if (AsyncCustomValidation) {
            return QUIC_STATUS_PENDING;
        }
        if (CustomValidationResultSet && !ExpectedCustomValidationResult) {
            return QUIC_STATUS_INTERNAL_ERROR;
        }
        if (Event->PEER_CERTIFICATE_RECEIVED.DeferredStatus != ExpectedClientCertValidationResult) {
            TEST_FAILURE(
                "Unexpected Certificate Validation Status, expected=0x%x, actual=0x%x",
                ExpectedClientCertValidationResult,
                Event->PEER_CERTIFICATE_RECEIVED.DeferredStatus);
        }
        if (PeerCertEventReturnStatus != QUIC_STATUS_SUCCESS) {
            return PeerCertEventReturnStatus;
        }
        break;

    default:
        break;
    }

    return QUIC_STATUS_SUCCESS;
}
