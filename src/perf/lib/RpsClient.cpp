/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.

Abstract:

    QUIC Perf RPS Client Implementation.

--*/

#include "RpsClient.h"

#ifdef QUIC_CLOG
#include "RpsClient.cpp.clog.h"
#endif

static
void
PrintHelp(
    ) {
    WriteOutput(
        "\n"
        "RPS Client options:\n"
        "\n"
        "  -target:<####>              The target server to connect to.\n"
        "  -runtime:<####>             The total runtime (in ms). (def:%u)\n"
        "  -port:<####>                The UDP port of the server. (def:%u)\n"
        "  -conns:<####>               The number of connections to use. (def:%u)\n"
        "  -parallel:<####>            The number of parallel requests per connection. (def:%u)\n"
        "  -request:<####>             The length of request payloads. (def:%u)\n"
        "  -response:<####>             The length of request payloads. (def:%u)\n"
        "\n",
        RPS_DEFAULT_RUN_TIME,
        PERF_DEFAULT_PORT,
        RPS_DEFAULT_CONNECTION_COUNT,
        RPS_DEFAULT_PARALLEL_REQUEST_COUNT,
        RPS_DEFAULT_REQUEST_LENGTH,
        RPS_DEFAULT_RESPONSE_LENGTH
        );
}

QUIC_STATUS
RpsClient::Init(
    _In_ int argc,
    _In_reads_(argc) _Null_terminated_ char* argv[]
    ) {
    if (argc > 0 && (IsArg(argv[0], "?") || IsArg(argv[0], "help"))) {
        PrintHelp();
        return QUIC_STATUS_INVALID_PARAMETER;
    }

    if (!Configuration.IsValid()) {
        return Configuration.GetInitStatus();
    }

    const char* target;
    if (!TryGetValue(argc, argv, "target", &target)) {
        WriteOutput("Must specify '-target' argument!\n");
        PrintHelp();
        return QUIC_STATUS_INVALID_PARAMETER;
    }

    size_t Len = strlen(target);
    Target.reset(new(std::nothrow) char[Len + 1]);
    if (!Target.get()) {
        return QUIC_STATUS_OUT_OF_MEMORY;
    }
    QuicCopyMemory(Target.get(), target, Len);
    Target[Len] = '\0';

    TryGetValue(argc, argv, "runtime", &RunTime);
    TryGetValue(argc, argv, "port", &Port);
    TryGetValue(argc, argv, "conns", &ConnectionCount);
    TryGetValue(argc, argv, "request", &RequestLength);
    TryGetValue(argc, argv, "response", &ResponseLength);

    RequestBuffer.Buffer = (QUIC_BUFFER*)QUIC_ALLOC_NONPAGED(sizeof(QUIC_BUFFER) + sizeof(uint64_t) + RequestLength);
    if (!RequestBuffer) {
        return QUIC_STATUS_OUT_OF_MEMORY;
    }
    RequestBuffer.Buffer->Length = sizeof(uint64_t) + RequestLength;
    RequestBuffer.Buffer->Buffer = (uint8_t*)(RequestBuffer.Buffer + 1);
    *(uint64_t*)(RequestBuffer.Buffer->Buffer) = QuicByteSwapUint64(ResponseLength);
    for (uint32_t i = 0; i < RequestLength; ++i) {
        RequestBuffer.Buffer->Buffer[sizeof(uint64_t) + i] = (uint8_t)i;
    }

    return QUIC_STATUS_SUCCESS;
}

QUIC_STATUS
RpsClient::Start(
    _In_ QUIC_EVENT* StopEvent
    ) {
    CompletionEvent = StopEvent;

    QUIC_CONNECTION_CALLBACK_HANDLER Handler =
        [](HQUIC Conn, void* Context, QUIC_CONNECTION_EVENT* Event) -> QUIC_STATUS {
            return ((RpsClient*)Context)->
                ConnectionCallback(
                    Conn,
                    Event);
        };

    Connections = UniquePtr<ConnectionScope[]>(new(std::nothrow) ConnectionScope[ConnectionCount]);
    if (!Connections.get()) {
        return QUIC_STATUS_OUT_OF_MEMORY;
    }

    for (uint32_t i = 0; i < ConnectionCount; i++) {
        Connections[i].Handle = nullptr;
    }

    QUIC_STATUS Status = QUIC_STATUS_SUCCESS;
    uint32_t ActiveProcCount = QuicProcActiveCount();
    if (ActiveProcCount >= 8) {
        //
        // If we have enough cores, leave 2 cores for OS overhead
        //
        ActiveProcCount -= 2;
    }
    for (uint32_t i = 0; i < ConnectionCount; ++i) {
        Status = QuicSetCurrentThreadProcessorAffinity((uint16_t)(i % ActiveProcCount));
        if (QUIC_FAILED(Status)) {
            WriteOutput("Setting Thread Group Failed 0x%x\n", Status);
            return Status;
        }

        Status =
            MsQuic->ConnectionOpen(
                Registration,
                Handler,
                this,
                &Connections[i].Handle);
        if (QUIC_FAILED(Status)) {
            WriteOutput("ConnectionOpen failed, 0x%x\n", Status);
            return Status;
        }

        BOOLEAN Opt = TRUE;
        Status =
            MsQuic->SetParam(
                Connections[i],
                QUIC_PARAM_LEVEL_CONNECTION,
                QUIC_PARAM_CONN_SHARE_UDP_BINDING,
                sizeof(Opt),
                &Opt);
        if (QUIC_FAILED(Status)) {
            WriteOutput("SetParam(CONN_SHARE_UDP_BINDING) failed, 0x%x\n", Status);
            return Status;
        }

        if (i >= RPS_MAX_CLIENT_PORT_COUNT) {
            Status =
                MsQuic->SetParam(
                    Connections[i],
                    QUIC_PARAM_LEVEL_CONNECTION,
                    QUIC_PARAM_CONN_LOCAL_ADDRESS,
                    sizeof(QUIC_ADDR),
                    &LocalAddresses[i % RPS_MAX_CLIENT_PORT_COUNT]);
            if (QUIC_FAILED(Status)) {
                WriteOutput("SetParam(CONN_LOCAL_ADDRESS) failed, 0x%x\n", Status);
                return Status;
            }
        }

        Status =
            MsQuic->ConnectionStart(
                Connections[i],
                Configuration,
                QUIC_ADDRESS_FAMILY_UNSPEC,
                Target.get(),
                Port);
        if (QUIC_FAILED(Status)) {
            WriteOutput("ConnectionStart failed, 0x%x\n", Status);
            return Status;
        }

        if (i < RPS_MAX_CLIENT_PORT_COUNT) {
            uint32_t AddrLen = sizeof(QUIC_ADDR);
            Status =
                MsQuic->GetParam(
                    Connections[i],
                    QUIC_PARAM_LEVEL_CONNECTION,
                    QUIC_PARAM_CONN_LOCAL_ADDRESS,
                    &AddrLen,
                    &LocalAddresses[i]);
            if (QUIC_FAILED(Status)) {
                WriteOutput("GetParam(CONN_LOCAL_ADDRESS) failed, 0x%x\n", Status);
                return Status;
            }
        }
    }

    if (!QuicEventWaitWithTimeout(AllConnected.Handle, RPS_ALL_CONNECT_TIMEOUT)) {
        WriteOutput("Timeout waiting for connections.\n");
        Running = false;
        return QUIC_STATUS_CONNECTION_TIMEOUT;
    }

    WriteOutput("All Connected! Waiting for idle.\n");
    QuicSleep(RPS_IDLE_WAIT);

    WriteOutput("Start sending request...\n");
    for (uint32_t i = 0; i < ParallelRequests; ++i) {
        for (uint32_t j = 0; j < ConnectionCount; ++j) {
            SendRequest(Connections[j]);
        }
    }

    uint32_t ThreadToSetAffinityTo = QuicProcActiveCount();
    if (ThreadToSetAffinityTo > 2) {
        ThreadToSetAffinityTo -= 2;
        Status =
            QuicSetCurrentThreadProcessorAffinity((uint16_t)ThreadToSetAffinityTo);
    }

    return QUIC_STATUS_SUCCESS;
}

QUIC_STATUS
RpsClient::Wait(
    _In_ int Timeout
    ) {
    if (Timeout == 0) {
        Timeout = RunTime;
    }

    QuicEventWaitWithTimeout(*CompletionEvent, Timeout);

    Running = false;

    uint32_t RPS = (uint32_t)((CompletedRequests * 1000ull) / (uint64_t)RunTime);

    if (RPS == 0) {
        WriteOutput("Error: No requests were completed\n");
    } else {
        WriteOutput("Result: %u RPS\n", RPS);
    }
    //WriteOutput("Result: %u RPS (%ull start, %ull send completed, %ull completed)\n",
    //    RPS, StartedRequests, SendCompletedRequests, CompletedRequests);

    return QUIC_STATUS_SUCCESS;
}

QUIC_STATUS
RpsClient::ConnectionCallback(
    _In_ HQUIC /* ConnectionHandle */,
    _Inout_ QUIC_CONNECTION_EVENT* Event
    ) {
    switch (Event->Type) {
    case QUIC_CONNECTION_EVENT_CONNECTED:
        if ((uint32_t)InterlockedIncrement64((int64_t*)&ActiveConnections) == ConnectionCount) {
            QuicEventSet(AllConnected.Handle);
        }
        break;
    case QUIC_CONNECTION_EVENT_SHUTDOWN_INITIATED_BY_TRANSPORT:
        //WriteOutput("Connection died, 0x%x\n", Event->SHUTDOWN_INITIATED_BY_TRANSPORT.Status);
        break;
    case QUIC_CONNECTION_EVENT_SHUTDOWN_COMPLETE:
        break;
    default:
        break;
    }
    return QUIC_STATUS_SUCCESS;
}

QUIC_STATUS
RpsClient::StreamCallback(
    _In_ HQUIC StreamHandle,
    _Inout_ QUIC_STREAM_EVENT* Event
    ) {
    switch (Event->Type) {
    case QUIC_STREAM_EVENT_RECEIVE:
        if (Event->RECEIVE.Flags & QUIC_RECEIVE_FLAG_FIN) {
            InterlockedIncrement64((int64_t*)&CompletedRequests);
        }
        break;
    case QUIC_STREAM_EVENT_SEND_COMPLETE:
        InterlockedIncrement64((int64_t*)&SendCompletedRequests);
        break;
    case QUIC_STREAM_EVENT_PEER_SEND_ABORTED:
    case QUIC_STREAM_EVENT_PEER_RECEIVE_ABORTED:
        WriteOutput("Peer stream aborted!\n");
        MsQuic->StreamShutdown(
            StreamHandle,
            QUIC_STREAM_SHUTDOWN_FLAG_ABORT,
            0);
        break;
    case QUIC_STREAM_EVENT_SHUTDOWN_COMPLETE:
        SendRequest(StreamHandle); // Starts a new stream
        MsQuic->StreamClose(StreamHandle);
        break;
    default:
        break;
    }
    return QUIC_STATUS_SUCCESS;
}

QUIC_STATUS
RpsClient::SendRequest(
    _In_ HQUIC Handle
    )
{
    if (!Running) {
        return QUIC_STATUS_SUCCESS;
    }

    QUIC_STREAM_CALLBACK_HANDLER Handler =
        [](HQUIC Stream, void* Context, QUIC_STREAM_EVENT* Event) -> QUIC_STATUS {
            return ((RpsClient*)Context)->
                StreamCallback(
                    Stream,
                    Event);
        };

    HQUIC Stream = nullptr;
    QUIC_STATUS Status =
        MsQuic->StreamOpen(
            Handle,
            QUIC_STREAM_OPEN_FLAG_NONE,
            Handler,
            this,
            &Stream);
    if (QUIC_SUCCEEDED(Status)) {
        InterlockedIncrement64((int64_t*)&StartedRequests);
        Status =
            MsQuic->StreamSend(
                Stream,
                RequestBuffer,
                1,
                QUIC_SEND_FLAG_START | QUIC_SEND_FLAG_FIN,
                nullptr);
        if (QUIC_FAILED(Status)) {
            MsQuic->StreamClose(Stream);
        }
    }

    return Status;
}
