/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.

Abstract:

    QUIC PING Connection Implementation.

--*/

#include "QuicPing.h"

PingConnection::PingConnection(
    _In_ PingTracker* Tracker,
    _In_ bool DumpResumption
    ) :
    Tracker(Tracker), QuicConnection(nullptr), DumpResumption(DumpResumption),
    IsServer(false), ConnectedSuccessfully(false), TimedOut(false),
    BytesSent(0), BytesReceived(0), DatagramLength(0), DatagramsSent(0),
    DatagramsAcked(0), DatagramsLost(0), DatagramsCancelled(0),
    DatagramsReceived(0), DatagramsJitterTotal(0), DatagramLastTime(0) {

    if (QUIC_FAILED(
        MsQuic->ConnectionOpen(
            Registration,
            QuicCallbackHandler,
            this,
            &QuicConnection))) {
        printf("Failed to open connection!\n");
    }
}

PingConnection::PingConnection(
    _In_ PingTracker* Tracker,
    _In_ HQUIC Connection
    ) :
    Tracker(Tracker), QuicConnection(Connection), DumpResumption(false),
    ConnectedSuccessfully(false), TimedOut(false), BytesSent(0),
    BytesReceived(0), DatagramLength(0), DatagramsSent(0), DatagramsAcked(0),
    DatagramsLost(0), DatagramsCancelled(0), DatagramsReceived(0),
    DatagramsJitterTotal(0), DatagramLastTime(0) {

    StartTime = QuicTimeUs64();
    MsQuic->SetCallbackHandler(Connection, (void*)QuicCallbackHandler, this);
}

PingConnection::~PingConnection() {
    if (QuicConnection != nullptr) {
        MsQuic->ConnectionClose(QuicConnection);
    }
}

bool
PingConnection::Initialize(
    bool isServer
    )
{
    this->IsServer = isServer;

    if (!IsServer) {
        /*if (PingConfig.Client.ResumeToken &&
            !SetResumptionState(
                MsQuic,
                QuicConnection,
                PingConfig.Client.ResumeToken)) {
            printf("Failed to set the resumption token!\n");
            return false;
        }*/

        if (PingConfig.Client.Version &&
            QUIC_FAILED(
            MsQuic->SetParam(
                QuicConnection,
                QUIC_PARAM_LEVEL_CONNECTION,
                QUIC_PARAM_CONN_QUIC_VERSION,
                sizeof(uint32_t),
                &PingConfig.Client.Version))) {
            printf("Failed to set the version!\n");
            return false;
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
            return false;
        }
    }
    for (uint64_t i = 0; i < PingConfig.LocalUnidirStreamCount; i++) {
        auto Stream = new PingStream(this, UniSendMode);
        if (!Stream || !Stream->Start()) {
            delete Stream;
            return false;
        }
    }

    while (DatagramsSent < PingConfig.LocalDatagramCount) {
        auto SendRequest = new PingSendRequest();
        SendRequest->SetLength(DatagramLength);
        if (!QueueDatagram(SendRequest)) {
            delete SendRequest;
            return false;
        }
    }

    return true;
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
PingConnection::Connect(_In_ HQUIC ClientConfiguration) {
    if (QuicAddrGetFamily(&PingConfig.LocalIpAddr) != QUIC_ADDRESS_FAMILY_UNSPEC) {
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

    Tracker->AddItem();
    StartTime = QuicTimeUs64();
    if (QUIC_FAILED(
        MsQuic->ConnectionStart(
            QuicConnection,
            ClientConfiguration,
            QuicAddrGetFamily(&PingConfig.Client.RemoteIpAddr),
            PingConfig.Client.Target,
            QuicAddrGetPort(&PingConfig.Client.RemoteIpAddr)))) {
        Tracker->CompleteItem(0, 0);
        return false;
    }

    return true;
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
            if (QUIC_FAILED(
                MsQuic->ConnectionSendResumptionTicket(QuicConnection, QUIC_SEND_RESUMPTION_FLAG_FINAL, 0, nullptr))) {
                printf("[%p] Failed to send 0-RTT resumption ticket!\n", QuicConnection);
            }
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
                (unsigned long long)Event->SHUTDOWN_INITIATED_BY_PEER.ErrorCode,
                (uint32_t)(ElapsedMicroseconds / 1000),
                (uint32_t)(ElapsedMicroseconds % 1000));
        } else {
            printf("[%p] App Closed with error: 0x%llx.\n",
                QuicConnection,
                (unsigned long long)Event->SHUTDOWN_INITIATED_BY_PEER.ErrorCode);
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
                (unsigned long long)BytesSent, SendRate,
                (unsigned long long)BytesReceived, RecvRate);

            if (DatagramsReceived != 0) {
                uint64_t Jitter = DatagramsJitterTotal / (DatagramsReceived - 1);
                printf("[%p] Datagrams: %llu recv | %u.%03u ms jitter\n",
                    QuicConnection,
                    (unsigned long long)DatagramsReceived,
                    (uint32_t)(Jitter / 1000),
                    (uint32_t)(Jitter % 1000));
            } else if (DatagramsSent != 0) {
                printf("[%p] Datagrams: %llu sent | %llu acked | %llu lost | %llu cancelled\n",
                    QuicConnection,
                    (unsigned long long)DatagramsSent,
                    (unsigned long long)DatagramsAcked,
                    (unsigned long long)DatagramsLost,
                    (unsigned long long)DatagramsCancelled);
            }
        }

        if (Tracker != nullptr) {
            Tracker->CompleteItem(BytesSent, BytesReceived);
        }

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
            printf("[%p]   Correlation Id:           %llu\n", QuicConnection, (unsigned long long)Stats.CorrelationId);
            printf("[%p]   RTT:                      %u us (min:%u max:%u)\n", QuicConnection, Stats.Rtt, Stats.MinRtt, Stats.MaxRtt);
            printf("[%p]   Send:\n", QuicConnection);
            printf("[%p]     PMTU:                   %hu bytes\n", QuicConnection, Stats.Send.PathMtu);
            printf("[%p]     Total Packets:          %llu\n", QuicConnection, (unsigned long long)Stats.Send.TotalPackets);
            printf("[%p]     Lost Packets:           %llu\n", QuicConnection, (unsigned long long)(Stats.Send.SuspectedLostPackets - Stats.Send.SpuriousLostPackets));
            printf("[%p]     Spurious Packets:       %llu\n", QuicConnection, (unsigned long long)Stats.Send.SpuriousLostPackets);
            printf("[%p]     Total Bytes:            %llu\n", QuicConnection, (unsigned long long)Stats.Send.TotalBytes);
            printf("[%p]     Stream Bytes:           %llu\n", QuicConnection, (unsigned long long)Stats.Send.TotalStreamBytes);
            printf("[%p]     Congestion Events:      %u\n", QuicConnection, Stats.Send.CongestionCount);
            printf("[%p]     Pers Congestion Events: %u\n", QuicConnection, Stats.Send.PersistentCongestionCount);
            printf("[%p]   Recv:\n", QuicConnection);
            printf("[%p]     Total Packets:          %llu\n", QuicConnection, (unsigned long long)Stats.Recv.TotalPackets);
            printf("[%p]     Reordered Packets:      %llu\n", QuicConnection, (unsigned long long)Stats.Recv.ReorderedPackets);
            printf("[%p]     Dropped Packets:        %llu\n", QuicConnection, (unsigned long long)Stats.Recv.DroppedPackets);
            printf("[%p]     Decryption Failures:    %llu\n", QuicConnection, (unsigned long long)Stats.Recv.DecryptionFailures);
            printf("[%p]     Total Bytes:            %llu\n", QuicConnection, (unsigned long long)Stats.Recv.TotalBytes);
            printf("[%p]     Stream Bytes:           %llu\n", QuicConnection, (unsigned long long)Stats.Recv.TotalStreamBytes);
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
        default:
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
