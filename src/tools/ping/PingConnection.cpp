/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.

Abstract:

    QUIC PING Connection Implementation.

--*/

#include "QuicPing.h"

PingConnection::PingConnection(
    _In_ bool IsServer,
    _In_ HQUIC Handle,
    _In_ bool DumpResumption,
    _In_ bool ForPsci
    ) :
    QuicConnection(Handle),
    DumpResumption(DumpResumption), IsServer(IsServer), ForPsci(ForPsci),
    ConnectedSuccessfully(false), BytesSent(0), BytesReceived(0), DatagramLength(0),
    DatagramsSent(0), DatagramsAcked(0), DatagramsLost(0), DatagramsCancelled(0),
    DatagramsReceived(0), DatagramsJitterTotal(0), DatagramLastTime(0),
    TimedOut(false) {

    if (QuicConnection == nullptr) {
        if (QUIC_FAILED(
            MsQuic->ConnectionOpen(
                Session,
                QuicCallbackHandler,
                this,
                &QuicConnection))) {
            printf("Failed to open connection!\n");
        }
    } else {
        MsQuic->SetCallbackHandler(QuicConnection, (void*)QuicCallbackHandler, this);
        StartTime = QuicTimeUs64();
    }

    if (ForPsci && IsServer) {
        BOOLEAN IsServer = TRUE;
        MsQuic->SetParam(
            QuicConnection,
            QUIC_PARAM_LEVEL_CONNECTION,
            QUIC_PARAM_CONN_PRESHARED_INFO,
            sizeof(IsServer),
            &IsServer);
    }

    Initialize();
}

PingConnection::~PingConnection() {
    if (QuicConnection != nullptr) {
        MsQuic->ConnectionClose(QuicConnection);
    }
}

void PingConnection::Initialize() {

    if (!PingConfig.UseSendBuffer) {
        BOOLEAN Opt = FALSE;
        if (QUIC_FAILED(
            MsQuic->SetParam(
                QuicConnection,
                QUIC_PARAM_LEVEL_CONNECTION,
                QUIC_PARAM_CONN_SEND_BUFFERING,
                sizeof(Opt),
                &Opt))) {
            printf("MsQuic->SetParam (SEND_BUFFERING) failed!\n");
            return;
        }
    }

    if (!PingConfig.UsePacing) {
        BOOLEAN Opt = FALSE;
        if (QUIC_FAILED(
            MsQuic->SetParam(
                QuicConnection,
                QUIC_PARAM_LEVEL_CONNECTION,
                QUIC_PARAM_CONN_SEND_PACING,
                sizeof(Opt),
                &Opt))) {
            printf("MsQuic->SetParam (SEND_PACING) failed!\n");
            return;
        }
    }

    {
        BOOLEAN Enabled = TRUE;
        if (QUIC_FAILED(
            MsQuic->SetParam(
                QuicConnection,
                QUIC_PARAM_LEVEL_CONNECTION,
                QUIC_PARAM_CONN_DATAGRAM_RECEIVE_ENABLED,
                sizeof(Enabled),
                &Enabled))) {
            printf("MsQuic->SetParam (DATAGRAMS) failed!\n");
            return;
        }
    }

    if (QUIC_FAILED(
        MsQuic->SetParam(
            QuicConnection,
            QUIC_PARAM_LEVEL_CONNECTION,
            QUIC_PARAM_CONN_DISCONNECT_TIMEOUT,
            sizeof(uint32_t),
            &PingConfig.DisconnectTimeout))) {
        printf("Failed to set the disconnect timeout!\n");
        return;
    }

    if (QUIC_FAILED(
        MsQuic->SetParam(
            QuicConnection,
            QUIC_PARAM_LEVEL_CONNECTION,
            QUIC_PARAM_CONN_IDLE_TIMEOUT,
            sizeof(uint64_t),
            &PingConfig.IdleTimeout))) {
        printf("Failed to set the idle timeout!\n");
        return;
    }

    if (PingConfig.PeerBidirStreamCount != 0) {
        if (QUIC_FAILED(
            MsQuic->SetParam(
                QuicConnection,
                QUIC_PARAM_LEVEL_CONNECTION,
                QUIC_PARAM_CONN_PEER_BIDI_STREAM_COUNT,
                sizeof(uint16_t),
                &PingConfig.PeerBidirStreamCount))) {
            printf("Failed to set the peer max bidi stream count!\n");
            return;
        }
    }

    if (PingConfig.PeerUnidirStreamCount != 0) {
        if (QUIC_FAILED(
            MsQuic->SetParam(
                QuicConnection,
                QUIC_PARAM_LEVEL_CONNECTION,
                QUIC_PARAM_CONN_PEER_UNIDI_STREAM_COUNT,
                sizeof(uint16_t),
                &PingConfig.PeerUnidirStreamCount))) {
            printf("Failed to set the peer max uni stream count!\n");
            return;
        }
    }

    if (!IsServer) {

        uint32_t SecFlags = QUIC_CERTIFICATE_FLAG_DISABLE_CERT_VALIDATION;
        if (QUIC_FAILED(
            MsQuic->SetParam(
                QuicConnection,
                QUIC_PARAM_LEVEL_CONNECTION,
                QUIC_PARAM_CONN_CERT_VALIDATION_FLAGS,
                sizeof(SecFlags),
                &SecFlags))) {
            printf("Failed to set the cert validation flags!\n");
            return;
        }

        if (PingConfig.Client.ResumeToken &&
            !SetResumptionState(
                MsQuic,
                QuicConnection,
                PingConfig.Client.ResumeToken)) {
            printf("Failed to set the resumption token!\n");
            return;
        }

        if (PingConfig.Client.Version &&
            QUIC_FAILED(
            MsQuic->SetParam(
                QuicConnection,
                QUIC_PARAM_LEVEL_CONNECTION,
                QUIC_PARAM_CONN_QUIC_VERSION,
                sizeof(uint32_t),
                &PingConfig.Client.Version))) {
            printf("Failed to set the version!\n");
            return;
        }

        if (!ForPsci) {
            if (QuicAddrGetFamily(&PingConfig.LocalIpAddr) != AF_UNSPEC) {
                MsQuic->SetParam(
                    QuicConnection,
                    QUIC_PARAM_LEVEL_CONNECTION,
                    QUIC_PARAM_CONN_LOCAL_ADDRESS,
                    sizeof(PingConfig.LocalIpAddr),
                    &PingConfig.LocalIpAddr);
            }

            if (PingConfig.Client.UseExplicitRemoteAddr) {
                MsQuic->SetParam(
                    QuicConnection,
                    QUIC_PARAM_LEVEL_CONNECTION,
                    QUIC_PARAM_CONN_REMOTE_ADDRESS,
                    sizeof(PingConfig.Client.RemoteIpAddr),
                    &PingConfig.Client.RemoteIpAddr);
            }
        }
    }

    if (ForPsci) {
        MsQuic->SetParam(
            QuicConnection,
            QUIC_PARAM_LEVEL_CONNECTION,
            QUIC_PARAM_CONN_LOCAL_ADDRESS,
            sizeof(PingConfig.LocalPsciAddr),
            &PingConfig.LocalPsciAddr);

        {
            BOOLEAN ShareBinding = TRUE;
            MsQuic->SetParam(
                QuicConnection,
                QUIC_PARAM_LEVEL_CONNECTION,
                QUIC_PARAM_CONN_SHARE_UDP_BINDING,
                sizeof(ShareBinding),
                &ShareBinding);
        }
    }

    if (IsServer || !PingConfig.UseEncryption) {
        BOOLEAN value = TRUE;
        if (QUIC_FAILED(
            MsQuic->SetParam(
                QuicConnection,
                QUIC_PARAM_LEVEL_CONNECTION,
                QUIC_PARAM_CONN_DISABLE_1RTT_ENCRYPTION,
                sizeof(value),
                &value))) {
            printf("MsQuic->SetParam (CONN_DISABLE_1RTT_ENCRYPTION) failed!\n");
        }
    }

    for (uint64_t i = 0; i < PingConfig.LocalBidirStreamCount; i++) {
        auto Stream = new PingStream(this, BidiSendMode);
        if (!Stream || !Stream->Start()) {
            delete Stream;
            return;
        }
    }
    for (uint64_t i = 0; i < PingConfig.LocalUnidirStreamCount; i++) {
        auto Stream = new PingStream(this, UniSendMode);
        if (!Stream || !Stream->Start()) {
            delete Stream;
            return;
        }
    }

    while (DatagramsSent < PingConfig.LocalDatagramCount) {
        auto SendRequest = new PingSendRequest();
        SendRequest->SetLength(DatagramLength);
        if (!QueueDatagram(SendRequest)) {
            delete SendRequest;
            return;
        }
    }
}

bool
PingConnection::QueueDatagram(
    PingSendRequest* SendRequest
    )
{
    BytesSent += SendRequest->QuicBuffer.Length;
    DatagramsSent++;

    return
        QUIC_SUCCEEDED(
        MsQuic->DatagramSend(
            QuicConnection,
            &SendRequest->QuicBuffer,
            1,
            SendRequest->Flags,
            SendRequest));
}

bool
PingConnection::Connect() {
    Tracker.AddItem();
    StartTime = QuicTimeUs64();
    if (QUIC_FAILED(
        MsQuic->ConnectionStart(
            QuicConnection,
            QuicAddrGetFamily(&PingConfig.Client.RemoteIpAddr),
            PingConfig.Client.Target,
            QuicAddrGetPort(&PingConfig.Client.RemoteIpAddr)))) {
        Tracker.CompleteItem(0, 0);
        return false;
    }
    return true;
}

QUIC_PRESHARED_CONNECTION_INFORMATION*
PingConnection::GetLocalPsci(
    uint32_t &Length
    ) {
    QUIC_PRESHARED_CONNECTION_INFORMATION* Psci =
        (QUIC_PRESHARED_CONNECTION_INFORMATION*)
        new uint8_t[512];
    Length = 512;

    if (QUIC_FAILED(
        MsQuic->GetParam(
            QuicConnection,
            QUIC_PARAM_LEVEL_CONNECTION,
            QUIC_PARAM_CONN_PRESHARED_INFO,
            &Length,
            Psci))) {
        delete[] (uint8_t*)Psci;
        return nullptr;
    }

    Psci->Address = PingConfig.PublicPsciAddr;

    return Psci;
}

bool
PingConnection::SetRemotePsci(
    const QUIC_PRESHARED_CONNECTION_INFORMATION* Psci
    ) {
    return
        QUIC_SUCCEEDED(
        MsQuic->SetParam(
            QuicConnection,
            QUIC_PARAM_LEVEL_CONNECTION,
            QUIC_PARAM_CONN_PRESHARED_INFO,
            sizeof(QUIC_PRESHARED_CONNECTION_INFORMATION),
            Psci));
}

void
PingConnection::OnPingStreamShutdownComplete(
    _In_ PingStream *Stream
    ) {

    BytesSent += Stream->BytesCompleted;
    BytesReceived += Stream->BytesReceived;
}

void
PingConnection::ProcessEvent(
    _Inout_ QUIC_CONNECTION_EVENT* Event
    ) {
    switch (Event->Type) {
    case QUIC_CONNECTION_EVENT_CONNECTED: {
        ConnectedSuccessfully = true;
        ConnectTime = QuicTimeUs64();

        uint64_t ElapsedMicroseconds = ConnectTime - StartTime;

        printf("[%p] Connected in %u.%03u milliseconds.\n",
            QuicConnection,
            (uint32_t)(ElapsedMicroseconds / 1000),
            (uint32_t)(ElapsedMicroseconds % 1000));

        if (this->IsServer) {
            MsQuic->ConnectionSendResumptionTicket(
                QuicConnection,
                QUIC_SEND_RESUMPTION_FLAG_FINAL,
                0,
                nullptr);
        }
        break;
    }

    case QUIC_CONNECTION_EVENT_SHUTDOWN_INITIATED_BY_TRANSPORT: {
        if (!ConnectedSuccessfully) {
            ConnectTime = QuicTimeUs64();

            uint64_t ElapsedMicroseconds = ConnectTime - StartTime;

            printf("[%p] Failed to connect: %s (0x%x) in %u.%03u milliseconds.\n",
                QuicConnection,
                QuicStatusToString(Event->SHUTDOWN_INITIATED_BY_TRANSPORT.Status),
                Event->SHUTDOWN_INITIATED_BY_TRANSPORT.Status,
                (uint32_t)(ElapsedMicroseconds / 1000),
                (uint32_t)(ElapsedMicroseconds % 1000));
        } else {
            if (Event->SHUTDOWN_INITIATED_BY_TRANSPORT.Status != QUIC_STATUS_SUCCESS &&
                Event->SHUTDOWN_INITIATED_BY_TRANSPORT.Status != QUIC_STATUS_CONNECTION_IDLE) {
                printf("[%p] Closed with error: %s (0x%x).\n",
                    QuicConnection,
                    QuicStatusToString(Event->SHUTDOWN_INITIATED_BY_TRANSPORT.Status),
                    Event->SHUTDOWN_INITIATED_BY_TRANSPORT.Status);
            } else if (Event->SHUTDOWN_INITIATED_BY_TRANSPORT.Status == QUIC_STATUS_CONNECTION_IDLE) {
                TimedOut = true;
            }
        }
        break;
    }

    case QUIC_CONNECTION_EVENT_SHUTDOWN_INITIATED_BY_PEER: {
        if (!ConnectedSuccessfully) {
            ConnectTime = QuicTimeUs64();

            uint64_t ElapsedMicroseconds = ConnectTime - StartTime;

            printf("[%p] Failed to connect: 0x%llx in %u.%03u milliseconds.\n",
                QuicConnection,
                Event->SHUTDOWN_INITIATED_BY_PEER.ErrorCode,
                (uint32_t)(ElapsedMicroseconds / 1000),
                (uint32_t)(ElapsedMicroseconds % 1000));
        } else {
            printf("[%p] App Closed with error: 0x%llx.\n",
                QuicConnection,
                Event->SHUTDOWN_INITIATED_BY_PEER.ErrorCode);
        }
        break;
    }

    case QUIC_CONNECTION_EVENT_SHUTDOWN_COMPLETE: {
        CompleteTime = QuicTimeUs64();

        if (ConnectedSuccessfully && !Event->SHUTDOWN_COMPLETE.PeerAcknowledgedShutdown) {
            printf("[%p] Shutdown timed out.\n", QuicConnection);
        }

        if (BytesSent != 0 || BytesReceived != 0) {
            uint64_t ElapsedMicroseconds = CompleteTime - StartTime;
            if (TimedOut) {
                ElapsedMicroseconds -= DEFAULT_IDLE_TIMEOUT * 1000;
            }

            uint32_t SendRate = (uint32_t)((BytesSent * 1000 * 1000 * 8) / (1000 * ElapsedMicroseconds));
            uint32_t RecvRate = (uint32_t)((BytesReceived * 1000 * 1000 * 8) / (1000 * ElapsedMicroseconds));

            printf("[%p] Total rate after %u.%03u ms. (TX %llu bytes @ %u kbps | RX %llu bytes @ %u kbps).\n",
                QuicConnection,
                (uint32_t)(ElapsedMicroseconds / 1000),
                (uint32_t)(ElapsedMicroseconds % 1000),
                BytesSent, SendRate, BytesReceived, RecvRate);

            if (DatagramsReceived != 0) {
                uint64_t Jitter = DatagramsJitterTotal / (DatagramsReceived - 1);
                printf("[%p] Datagrams: %llu recv | %u.%03u ms jitter\n",
                    QuicConnection,
                    DatagramsReceived,
                    (uint32_t)(Jitter / 1000),
                    (uint32_t)(Jitter % 1000));
            } else if (DatagramsSent != 0) {
                printf("[%p] Datagrams: %llu sent | %llu acked | %llu lost | %llu cancelled\n",
                    QuicConnection,
                    DatagramsSent, DatagramsAcked, DatagramsLost, DatagramsCancelled);
            }
        }

        Tracker.CompleteItem(BytesSent, BytesReceived);

        if (DumpResumption && ConnectedSuccessfully) {
            uint8_t SerializedResumptionState[2048];
            uint32_t SerializedResumptionStateLength = sizeof(SerializedResumptionState);
            if (QUIC_SUCCEEDED(
                MsQuic->GetParam(
                    QuicConnection,
                    QUIC_PARAM_LEVEL_CONNECTION,
                    QUIC_PARAM_CONN_RESUMPTION_STATE,
                    &SerializedResumptionStateLength,
                    SerializedResumptionState))) {
                printf("[%p] Resumption state (%u bytes):\n", QuicConnection, SerializedResumptionStateLength);
                for (uint32_t i = 0; i < SerializedResumptionStateLength; i++) {
                    printf("%.2X", (uint8_t)SerializedResumptionState[i]);
                }
                printf("\n");
            }
        }

        if (PingConfig.PrintStats) {
            QUIC_STATISTICS Stats;
            uint32_t StatsLength = sizeof(Stats);
            MsQuic->GetParam(
                QuicConnection,
                QUIC_PARAM_LEVEL_CONNECTION,
                QUIC_PARAM_CONN_STATISTICS,
                &StatsLength,
                &Stats);
            printf("[%p] Transport Statistics:\n", QuicConnection);
            printf("[%p]   Correlation Id:           %llu\n", QuicConnection, Stats.CorrelationId);
            printf("[%p]   RTT:                      %u us (min:%u max:%u)\n", QuicConnection, Stats.Rtt, Stats.MinRtt, Stats.MaxRtt);
            printf("[%p]   Send:\n", QuicConnection);
            printf("[%p]     PMTU:                   %hu bytes\n", QuicConnection, Stats.Send.PathMtu);
            printf("[%p]     Total Packets:          %llu\n", QuicConnection, Stats.Send.TotalPackets);
            printf("[%p]     Lost Packets:           %llu\n", QuicConnection, Stats.Send.SuspectedLostPackets - Stats.Send.SpuriousLostPackets);
            printf("[%p]     Spurious Packets:       %llu\n", QuicConnection, Stats.Send.SpuriousLostPackets);
            printf("[%p]     Total Bytes:            %llu\n", QuicConnection, Stats.Send.TotalBytes);
            printf("[%p]     Stream Bytes:           %llu\n", QuicConnection, Stats.Send.TotalStreamBytes);
            printf("[%p]     Congestion Events:      %u\n", QuicConnection, Stats.Send.CongestionCount);
            printf("[%p]     Pers Congestion Events: %u\n", QuicConnection, Stats.Send.PersistentCongestionCount);
            printf("[%p]   Recv:\n", QuicConnection);
            printf("[%p]     Total Packets:          %llu\n", QuicConnection, Stats.Recv.TotalPackets);
            printf("[%p]     Reordered Packets:      %llu\n", QuicConnection, Stats.Recv.ReorderedPackets);
            printf("[%p]     Dropped Packets:        %llu\n", QuicConnection, Stats.Recv.DroppedPackets);
            printf("[%p]     Decryption Failures:    %llu\n", QuicConnection, Stats.Recv.DecryptionFailures);
            printf("[%p]     Total Bytes:            %llu\n", QuicConnection, Stats.Recv.TotalBytes);
            printf("[%p]     Stream Bytes:           %llu\n", QuicConnection, Stats.Recv.TotalStreamBytes);
            printf("[%p]   Misc:\n", QuicConnection);
            printf("[%p]     Key Updates:            %u\n", QuicConnection, Stats.Misc.KeyUpdateCount);
        }

        delete this;
        break;
    }

    case QUIC_CONNECTION_EVENT_PEER_STREAM_STARTED: {
        new PingStream(
            this,
            Event->PEER_STREAM_STARTED.Stream,
            (Event->PEER_STREAM_STARTED.Flags & QUIC_STREAM_OPEN_FLAG_UNIDIRECTIONAL) ? UniRecvMode : BidiEchoMode);
        break;
    }

    case QUIC_CONNECTION_EVENT_DATAGRAM_STATE_CHANGED: {
        DatagramLength =
            min(PingConfig.DatagramMaxLength, Event->DATAGRAM_STATE_CHANGED.MaxSendLength);
        //printf("[%p] New Datagram Length = %hu\n", QuicConnection, DatagramLength);
        break;
    }

    case QUIC_CONNECTION_EVENT_DATAGRAM_RECEIVED: {
        BytesReceived += Event->DATAGRAM_RECEIVED.Buffer->Length;
        DatagramsReceived++;
        uint64_t RecvTime = QuicTimeUs64();
        if (DatagramLastTime != 0) {
            DatagramsJitterTotal += RecvTime - DatagramLastTime;
        }
        DatagramLastTime = RecvTime;
        break;
    }

    case QUIC_CONNECTION_EVENT_DATAGRAM_SEND_STATE_CHANGED: {
        auto SendRequest = (PingSendRequest*)Event->DATAGRAM_SEND_STATE_CHANGED.ClientContext;
        Event->DATAGRAM_SEND_STATE_CHANGED.ClientContext = nullptr;

        switch (Event->DATAGRAM_SEND_STATE_CHANGED.State) {
        case QUIC_DATAGRAM_SEND_SENT:
            if (DatagramsSent != PingConfig.LocalDatagramCount) {
                SendRequest->SetLength(DatagramLength);
                if (!QueueDatagram(SendRequest)) {
                    SendRequest = nullptr;
                }
            }
            break;
        case QUIC_DATAGRAM_SEND_LOST_DISCARDED:
            DatagramsLost++;
            break;
        case QUIC_DATAGRAM_SEND_ACKNOWLEDGED:
        case QUIC_DATAGRAM_SEND_ACKNOWLEDGED_SPURIOUS:
            DatagramsAcked++;
            break;
        case QUIC_DATAGRAM_SEND_CANCELED:
            DatagramsCancelled++;
            break;
        }

        delete SendRequest;
        break;
    }

    default:
        break;
    }
}

QUIC_STATUS
QUIC_API
PingConnection::QuicCallbackHandler(
    _In_ HQUIC /* Connection */,
    _In_opt_ void* Context,
    _Inout_ QUIC_CONNECTION_EVENT* Event
    ) {
    PingConnection *pThis = (PingConnection*)Context;
    pThis->ProcessEvent(Event);
    return QUIC_STATUS_SUCCESS;
}

PingPsciConnection::PingPsciConnection(
        _In_ bool IsServer,
        _In_ HQUIC Handle
    ) :
    QuicConnection(nullptr), IsServer(IsServer)  {

    NormalConnection =
        new PingConnection(
            IsServer,
            nullptr,
            false,
            true);

    LocalPsci = NormalConnection->GetLocalPsci(SendBuffer.Length);
    if (LocalPsci == nullptr) {
        printf("Failed to query local PSCI\n");
    }
    SendBuffer.Buffer = (uint8_t*)LocalPsci;
    RemotePsci = (QUIC_PRESHARED_CONNECTION_INFORMATION*) new uint8_t[512];

    if (IsServer) {
        QuicConnection = Handle;
        MsQuic->SetCallbackHandler(QuicConnection, (void*)QuicCallbackHandler, this);
        uint16_t StreamCount = 1;
        if (QUIC_FAILED(
            MsQuic->SetParam(
                QuicConnection,
                QUIC_PARAM_LEVEL_CONNECTION,
                QUIC_PARAM_CONN_PEER_BIDI_STREAM_COUNT,
                sizeof(uint16_t),
                &StreamCount))) {
            printf("MsQuic->SetParam (CONN_PEER_BIDI_STREAM_COUNT) failed!\n");
            return;
        }
    } else {
        if (QUIC_FAILED(
            MsQuic->ConnectionOpen(
                Session,
                QuicCallbackHandler,
                this,
                &QuicConnection))) {
            printf("Failed to open connection!\n");
        }
        uint32_t SecFlags = QUIC_CERTIFICATE_FLAG_DISABLE_CERT_VALIDATION;
        if (QUIC_FAILED(
            MsQuic->SetParam(
                QuicConnection,
                QUIC_PARAM_LEVEL_CONNECTION,
                QUIC_PARAM_CONN_CERT_VALIDATION_FLAGS,
                sizeof(SecFlags),
                &SecFlags))) {
            printf("Failed to set the cert validation flags!\n");
            return;
        }
    }
}

PingPsciConnection::~PingPsciConnection() {
    if (QuicConnection != nullptr) {
        MsQuic->ConnectionClose(QuicConnection);
    }
    delete[] (uint8_t*)LocalPsci;
    delete[] (uint8_t*)RemotePsci;
}

bool
PingPsciConnection::Connect() {

    Tracker.AddItem();
    if (QUIC_FAILED(
        MsQuic->ConnectionStart(
            QuicConnection,
            QuicAddrGetFamily(&PingConfig.Client.RemoteIpAddr),
            PingConfig.Client.Target,
            QuicAddrGetPort(&PingConfig.Client.RemoteIpAddr)))) {
        Tracker.CompleteItem(0, 0);
        return false;
    }
    return true;
}

bool PingPsciConnection::SendPsci(HQUIC Stream) {
    if (Stream == nullptr) {
        if (QUIC_FAILED(
            MsQuic->StreamOpen(
                QuicConnection,
                QUIC_STREAM_OPEN_FLAG_NONE,
                QuicStreamCallbackHandler,
                this,
                &Stream))) {
            printf("Failed to open stream!\n");
            return false;
        }
        if (QUIC_FAILED(
            MsQuic->StreamStart(
                Stream,
                QUIC_STREAM_START_FLAG_NONE))) {
            printf("Failed to start stream!\n");
            return false;
        }
        //printf("Sending PSCI\n");
    } else {
        //printf("Replying with PSCI\n");
    }

    MsQuic->StreamSend(
        Stream,
        &SendBuffer,
        1,
        QUIC_SEND_FLAG_FIN,
        nullptr);

    return true;
}

QUIC_STATUS
PingPsciConnection::ProcessEvent(
    _Inout_ QUIC_CONNECTION_EVENT* Event
    ) {
    switch (Event->Type) {
    case QUIC_CONNECTION_EVENT_CONNECTED:
        //printf("PSCI Connected\n");
        if (!IsServer &&
            IsPsciAlpn(
                Event->CONNECTED.NegotiatedAlpn,
                Event->CONNECTED.NegotiatedAlpnLength)) {
            SendPsci();
        }
        break;
    case QUIC_CONNECTION_EVENT_SHUTDOWN_COMPLETE:
        delete this;
        break;
    case QUIC_CONNECTION_EVENT_PEER_STREAM_STARTED:
        MsQuic->SetCallbackHandler(
            Event->PEER_STREAM_STARTED.Stream,
            (void*)QuicStreamCallbackHandler,
            this);
        SendPsci(Event->PEER_STREAM_STARTED.Stream);
        break;
    default:
        break;
    }
    return QUIC_STATUS_SUCCESS;
}

QUIC_STATUS
PingPsciConnection::ProcessStreamEvent(
    _In_ HQUIC Stream,
    _Inout_ QUIC_STREAM_EVENT* Event
    ) {
    switch (Event->Type) {
    case QUIC_STREAM_EVENT_RECEIVE:
        if (Event->RECEIVE.AbsoluteOffset + Event->RECEIVE.TotalBufferLength <= 512) {
            uint64_t Offset = Event->RECEIVE.AbsoluteOffset;
            for (uint32_t i = 0; i < Event->RECEIVE.BufferCount; ++i) {
                memcpy(
                    ((uint8_t*)RemotePsci) + Offset,
                    Event->RECEIVE.Buffers[i].Buffer,
                    Event->RECEIVE.Buffers[i].Length);
                Offset += Event->RECEIVE.Buffers[i].Length;
            }
        }
        break;
    case QUIC_STREAM_EVENT_PEER_SEND_SHUTDOWN:
        //printf("Received PSCI\n");
        {
            uint8_t* Offset = (uint8_t*)(RemotePsci + 1);
            RemotePsci->ConnectionID.Buffer = Offset;
            Offset += RemotePsci->ConnectionID.Length;
            RemotePsci->TrafficSecret.Buffer = Offset;
            Offset += RemotePsci->TrafficSecret.Length;
            RemotePsci->TransportParameters.Buffer = Offset;
            Offset += RemotePsci->TransportParameters.Length;
        }
        RemotePsci->RttEstimateUs = 1000 * 100; // TODO - Don't hardcode
        if (NormalConnection->SetRemotePsci(RemotePsci)) {
            //printf("Connecting with PSCI\n");
            NormalConnection->Connect();
        } else {
            printf("Failed to set remote PSCI!\n");
        }
        break;
    case QUIC_STREAM_EVENT_SHUTDOWN_COMPLETE:
        MsQuic->ConnectionShutdown(Stream, QUIC_CONNECTION_SHUTDOWN_FLAG_NONE, 0);
        MsQuic->StreamClose(Stream);
        Tracker.CompleteItem(0, 0);
        break;
    default:
        break;
    }
    return QUIC_STATUS_SUCCESS;
}

QUIC_STATUS
QUIC_API
PingPsciConnection::QuicCallbackHandler(
    _In_ HQUIC /* Connection */,
    _In_opt_ void* Context,
    _Inout_ QUIC_CONNECTION_EVENT* Event
    ) {
    return ((PingPsciConnection*)Context)->ProcessEvent(Event);
}

QUIC_STATUS
QUIC_API
PingPsciConnection::QuicStreamCallbackHandler(
    _In_ HQUIC Stream,
    _In_opt_ void* Context,
    _Inout_ QUIC_STREAM_EVENT* Event
    ) {
    return ((PingPsciConnection*)Context)->ProcessStreamEvent(Stream, Event);
}
