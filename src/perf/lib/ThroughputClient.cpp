/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.

Abstract:

    QUIC Perf Throughput Client Implementation.

--*/

#include "ThroughputClient.h"

#ifdef QUIC_CLOG
#include "ThroughputClient.cpp.clog.h"
#endif

static
void
PrintHelp(
    ) {
    WriteOutput(
        "\n"
        "Throughput Client options:\n"
        "\n"
        "  -target:<####>              The target server to connect to.\n"
#if _WIN32
        "  -comp:<####>                The compartment ID to run in.\n"
        "  -core:<####>                The CPU core to use for the main thread.\n"
#endif
        "  -bind:<addr>                A local IP address to bind to.\n"
        "  -port:<####>                The UDP port of the server. (def:%u)\n"
        "  -ip:<0/4/6>                 A hint for the resolving the hostname to an IP address. (def:0)\n"
        "  -encrypt:<0/1>              Enables/disables encryption. (def:1)\n"
        "  -sendbuf:<0/1>              Whether to use send buffering. (def:1)\n"
        "  -length:<####>              The length of streams opened locally. (def:0)\n"
        "  -iosize:<####>              The size of each send request queued. (def:%u)\n"
        "\n",
        PERF_DEFAULT_PORT,
        PERF_DEFAULT_IO_SIZE
        );
}

QUIC_STATUS
ThroughputClient::Init(
    _In_ int argc,
    _In_reads_(argc) _Null_terminated_ char* argv[]
    ) {
    if (argc > 0 && (IsArg(argv[0], "?") || IsArg(argv[0], "help"))) {
        PrintHelp();
        return QUIC_STATUS_INVALID_PARAMETER;
    }

    if (!Session.IsValid()) {
        return Session.GetInitStatus();
    }

    const char* Target = nullptr;
    if (!TryGetValue(argc, argv, "target", &Target)) {
        WriteOutput("Must specify '-target' argument!\n");
        PrintHelp();
        return QUIC_STATUS_INVALID_PARAMETER;
    }

    TryGetValue(argc, argv, "port", &Port);
    TryGetValue(argc, argv, "encrypt", &UseEncryption);
    TryGetValue(argc, argv, "length", &Length);

    uint16_t Ip;
    if (TryGetValue(argc, argv, "ip", &Ip)) {
        switch (Ip) {
        case 4: RemoteFamily = AF_INET; break;
        case 6: RemoteFamily = AF_INET6; break;
        }
    }

    const char* LocalAddress = nullptr;
    if (TryGetValue(argc, argv, "bind", &LocalAddress)) {
        if (!ConvertArgToAddress(LocalAddress, 0, &LocalIpAddr)) {
            WriteOutput("Failed to decode IP address: '%s'!\nMust be *, a IPv4 or a IPv6 address.\n", LocalAddress);
            PrintHelp();
            return QUIC_STATUS_INVALID_PARAMETER;
        }
    }

    // TODO: Core, since we need to support kernel mode
#ifdef QUIC_COMPARTMENT_ID
    uint16_t CompartmentId;
    if (TryGetValue(argc, argv, "comp",  &CompartmentId)) {
        NETIO_STATUS status;
        if (!NETIO_SUCCESS(status = QuicCompartmentIdSetCurrent(CompartmentId))) {
            WriteOutput("Failed to set compartment ID = %d: 0x%x\n", CompartmentId, status);
            return QUIC_STATUS_INVALID_PARAMETER;
        } else {
            WriteOutput("Running in Compartment %d\n", CompartmentId);
        }
    }
#endif

#ifdef QuicSetCurrentThreadAffinityMask
    uint8_t CpuCore;
    if (TryGetValue(argc, argv, "core",  &CpuCore)) {
        QuicSetCurrentThreadAffinityMask((DWORD_PTR)(1ull << CpuCore));
    }
#endif

    TryGetValue(argc, argv, "sendbuf", &UseSendBuffer);

    IoSize = PERF_DEFAULT_IO_SIZE;
    TryGetValue(argc, argv, "iosize", &IoSize);

    size_t Len = strlen(Target);
    char* LocalTarget = new(std::nothrow) char[Len + 1];
    if (LocalTarget == nullptr) {
        return QUIC_STATUS_OUT_OF_MEMORY;
    }
    TargetData.reset(LocalTarget);
    QuicCopyMemory(TargetData.get(), Target, Len);
    TargetData[Len] = '\0';

    DataBuffer = (QUIC_BUFFER*)QUIC_ALLOC_NONPAGED(sizeof(QUIC_BUFFER) + IoSize);
    if (!DataBuffer) {
        return QUIC_STATUS_OUT_OF_MEMORY;
    }
    DataBuffer->Length = IoSize;
    DataBuffer->Buffer = (uint8_t*)(DataBuffer + 1);
    *(uint64_t*)(DataBuffer->Buffer) = QuicByteSwapUint64(0); // Zero-length request right now
    for (uint32_t i = 0; i < IoSize - sizeof(uint64_t); ++i) {
        DataBuffer->Buffer[sizeof(uint64_t) + i] = (uint8_t)i;
    }

    return QUIC_STATUS_SUCCESS;
}

struct ShutdownWrapper {
    HQUIC ConnHandle {nullptr};
    ~ShutdownWrapper() {
        if (ConnHandle) {
            MsQuic->ConnectionShutdown(ConnHandle, QUIC_CONNECTION_SHUTDOWN_FLAG_NONE, 0);
        }
    }
};

QUIC_STATUS
ThroughputClient::Start(
    _In_ QUIC_EVENT* StopEvnt
    ) {
    ShutdownWrapper Shutdown;
    this->StopEvent = StopEvnt;

    ConnectionData* ConnData = ConnectionDataAllocator.Alloc(this);
    if (!ConnData) {
        return QUIC_STATUS_OUT_OF_MEMORY;
    }
    QUIC_STATUS Status =
        MsQuic->ConnectionOpen(
            Session,
            [](HQUIC Handle, void* Context, QUIC_CONNECTION_EVENT* Event) -> QUIC_STATUS {
                ConnectionData* ConnData = (ConnectionData*)Context;
                return ConnData->Client->
                    ConnectionCallback(
                        Handle,
                        Event,
                        ConnData);
            },
            ConnData,
            &ConnData->Connection.Handle);
    if (QUIC_FAILED(Status)) {
        WriteOutput("Failed ConnectionOpen 0x%x\n", Status);
        ConnectionDataAllocator.Free(ConnData);
        return Status;
    }

    Shutdown.ConnHandle = ConnData->Connection.Handle;

    uint32_t SecFlags = QUIC_CERTIFICATE_FLAG_DISABLE_CERT_VALIDATION;
    Status =
        MsQuic->SetParam(
            ConnData->Connection,
            QUIC_PARAM_LEVEL_CONNECTION,
            QUIC_PARAM_CONN_CERT_VALIDATION_FLAGS,
            sizeof(SecFlags),
            &SecFlags);
    if (QUIC_FAILED(Status)) {
        WriteOutput("Failed Cert Validation Disable 0x%x\n", Status);
        return Status;
    }

    if (!UseSendBuffer) {
        BOOLEAN Opt = FALSE;
        Status =
            MsQuic->SetParam(
                ConnData->Connection,
                QUIC_PARAM_LEVEL_CONNECTION,
                QUIC_PARAM_CONN_SEND_BUFFERING,
                sizeof(Opt),
                &Opt);
        if (QUIC_FAILED(Status)) {
            WriteOutput("Failed Disable Send Buffering 0x%x\n", Status);
            return Status;
        }
    }

    if (!UseEncryption) {
        BOOLEAN value = TRUE;
        Status =
            MsQuic->SetParam(
                ConnData->Connection,
                QUIC_PARAM_LEVEL_CONNECTION,
                QUIC_PARAM_CONN_DISABLE_1RTT_ENCRYPTION,
                sizeof(value),
                &value);
        if (QUIC_FAILED(Status)) {
            WriteOutput("MsQuic->SetParam (CONN_DISABLE_1RTT_ENCRYPTION) failed!\n");
            return Status;
        }
    }

    if (QuicAddrGetFamily(&LocalIpAddr) != AF_UNSPEC) {
        MsQuic->SetParam(
            ConnData->Connection,
            QUIC_PARAM_LEVEL_CONNECTION,
            QUIC_PARAM_CONN_LOCAL_ADDRESS,
            sizeof(LocalIpAddr),
            &LocalIpAddr);
    }

    StreamContext* StrmContext = StreamContextAllocator.Alloc(this, ConnData->Connection);
    if (UseSendBuffer) {
        StrmContext->IdealSendBuffer = 1; // Hack to use only 1 send buffer
    }

    Status =
        MsQuic->StreamOpen(
            ConnData->Connection,
            QUIC_STREAM_OPEN_FLAG_UNIDIRECTIONAL,
            [](HQUIC Handle, void* Context, QUIC_STREAM_EVENT* Event) -> QUIC_STATUS {
                return ((StreamContext*)Context)->Client->
                    StreamCallback(
                        Handle,
                        Event,
                        (StreamContext*)Context);
            },
            StrmContext,
            &StrmContext->Stream.Handle);
    if (QUIC_FAILED(Status)) {
        WriteOutput("Failed StreamOpen 0x%x\n", Status);
        StreamContextAllocator.Free(StrmContext);
        return Status;
    }

    Status =
        MsQuic->StreamStart(
            StrmContext->Stream.Handle,
            QUIC_STREAM_START_FLAG_NONE);
    if (QUIC_FAILED(Status)) {
        WriteOutput("Failed StreamStart 0x%x\n", Status);
        StreamContextAllocator.Free(StrmContext);
        return Status;
    }

    StrmContext->StartTime = QuicTimeUs64();

    if (Length == 0) {
        Status =
            MsQuic->StreamShutdown(
                StrmContext->Stream.Handle,
                QUIC_STREAM_SHUTDOWN_FLAG_GRACEFUL,
                0);
        return Status;
    }

    SendData(StrmContext);

    Status =
        MsQuic->ConnectionStart(
            ConnData->Connection,
            RemoteFamily,
            TargetData.get(),
            Port);
    if (QUIC_FAILED(Status)) {
        WriteOutput("Failed ConnectionStart 0x%x\n", Status);
        return Status;
    }

    Shutdown.ConnHandle = nullptr;
    return Status;
}

QUIC_STATUS
ThroughputClient::Wait(
    _In_ int Timeout
    ) {
    if (Timeout > 0) {
        QuicEventWaitWithTimeout(*StopEvent, Timeout);
    } else {
        QuicEventWaitForever(*StopEvent);
    }
    return QUIC_STATUS_SUCCESS;
}

QUIC_STATUS
ThroughputClient::ConnectionCallback(
    _In_ HQUIC /*ConnectionHandle*/,
    _Inout_ QUIC_CONNECTION_EVENT* Event,
    _Inout_ ConnectionData* ConnData
    ) {
    switch (Event->Type) {
    case QUIC_CONNECTION_EVENT_SHUTDOWN_COMPLETE:
        ConnectionDataAllocator.Free(ConnData);
        QuicEventSet(*StopEvent);
        break;
    default:
        break;
    }
    return QUIC_STATUS_SUCCESS;
}

QUIC_STATUS
ThroughputClient::StreamCallback(
    _In_ HQUIC StreamHandle,
    _Inout_ QUIC_STREAM_EVENT* Event,
    _Inout_ StreamContext* StrmContext
    ) {
    switch (Event->Type) {
    case QUIC_STREAM_EVENT_SEND_COMPLETE:
        StrmContext->OutstandingBytes -= ((QUIC_BUFFER*)Event->SEND_COMPLETE.ClientContext)->Length;
        if (!Event->SEND_COMPLETE.Canceled) {
            StrmContext->BytesCompleted += ((QUIC_BUFFER*)Event->SEND_COMPLETE.ClientContext)->Length;
            SendData(StrmContext);
        }
        break;
    case QUIC_STREAM_EVENT_PEER_SEND_ABORTED:
    case QUIC_STREAM_EVENT_PEER_RECEIVE_ABORTED:
        MsQuic->StreamShutdown(
            StreamHandle,
            QUIC_STREAM_SHUTDOWN_FLAG_ABORT_SEND | QUIC_STREAM_SHUTDOWN_FLAG_ABORT_RECEIVE,
            0);
        break;
    case QUIC_STREAM_EVENT_SHUTDOWN_COMPLETE: {
        StrmContext->EndTime = QuicTimeUs64();
        uint64_t ElapsedMicroseconds = StrmContext->EndTime - StrmContext->StartTime;
        uint32_t SendRate = (uint32_t)((StrmContext->BytesCompleted * 1000 * 1000 * 8) / (1000 * ElapsedMicroseconds));

        WriteOutput("[%p][%llu] Closed [%s] after %u.%u ms. (TX %llu bytes @ %u kbps).\n",
            StrmContext->Connection,
            (unsigned long long)GetStreamID(MsQuic, StreamHandle),
            "Complete",
            (uint32_t)(ElapsedMicroseconds / 1000),
            (uint32_t)(ElapsedMicroseconds % 1000),
            (unsigned long long)StrmContext->BytesCompleted, SendRate);

        StreamContextAllocator.Free(StrmContext);
        break;
    }
    case QUIC_STREAM_EVENT_IDEAL_SEND_BUFFER_SIZE:
        if (!UseSendBuffer &&
            StrmContext->IdealSendBuffer < Event->IDEAL_SEND_BUFFER_SIZE.ByteCount) {
            StrmContext->IdealSendBuffer = Event->IDEAL_SEND_BUFFER_SIZE.ByteCount;
            SendData(StrmContext);
        }
        break;
    default:
        break;
    }
    return QUIC_STATUS_SUCCESS;
}

void
ThroughputClient::SendData(
    _In_ StreamContext* Context
    )
{
    while (Context->BytesSent < Length &&
           Context->OutstandingBytes < Context->IdealSendBuffer) {

        uint64_t BytesLeftToSend = Length - Context->BytesSent;
        uint32_t DataLength = IoSize;
        QUIC_BUFFER* Buffer = DataBuffer;
        QUIC_SEND_FLAGS Flags = QUIC_SEND_FLAG_NONE;

        if ((uint64_t)DataLength >= BytesLeftToSend) {
            DataLength = (uint32_t)BytesLeftToSend;
            Context->LastBuffer.Buffer = Buffer->Buffer;
            Context->LastBuffer.Length = DataLength;
            Buffer = &Context->LastBuffer;
            Flags = QUIC_SEND_FLAG_FIN;
        }

        Context->BytesSent += DataLength;
        Context->OutstandingBytes += DataLength;

        MsQuic->StreamSend(Context->Stream.Handle, Buffer, 1, Flags, Buffer);
    }
}
