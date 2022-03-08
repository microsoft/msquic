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
        "  -target:<####>               The target server to connect to.\n"
#if _WIN32
        "  -comp:<####>                 The compartment ID to run in.\n"
        "  -core:<####>                 The CPU core to use for the main thread.\n"
#endif
        "  -bind:<addr>                 A local IP address to bind to.\n"
        "  -port:<####>                 The UDP port of the server. (def:%u)\n"
        "  -ip:<0/4/6>                  A hint for the resolving the hostname to an IP address. (def:0)\n"
        "  -cibir:<hex_bytes>           A CIBIR well-known idenfitier.\n"
        "  -encrypt:<0/1>               Enables/disables encryption. (def:1)\n"
        "  -sendbuf:<0/1>               Whether to use send buffering. (def:0)\n"
        "  -pacing:<0/1>                Whether to use pacing. (def:1)\n"
        "  -timed:<0/1>                 Indicates the upload/download arg time (ms). (def:0)\n"
        "  -upload:<####>               The length of data (or time with -timed:1 arg) to send. (def:0)\n"
        "  -download:<####>             The length of data (or time with -timed:1 arg) to request/receive. (def:0)\n"
        "  -iosize:<####>               The size of each send request queued. (def:%u)\n"
        "  -tcp:<0/1>                   Indicates TCP/TLS should be used instead of QUIC. (def:0)\n"
        "  -stats:<0/1>                 Indicates connection stats should be printed at the end of the run. (def:0)\n"
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

    if (!Configuration.IsValid()) {
        return Configuration.GetInitStatus();
    }

    const char* Target = nullptr;
    if (!TryGetValue(argc, argv, "target", &Target) &&
        !TryGetValue(argc, argv, "server", &Target)) {
        WriteOutput("Must specify '-target' argument!\n");
        PrintHelp();
        return QUIC_STATUS_INVALID_PARAMETER;
    }

    TryGetValue(argc, argv, "tcp", &UseTcp);
    TryGetValue(argc, argv, "port", &Port);
    TryGetValue(argc, argv, "encrypt", &UseEncryption);
    TryGetValue(argc, argv, "upload", &UploadLength);
    TryGetValue(argc, argv, "download", &DownloadLength);
    TryGetValue(argc, argv, "stats", &PrintStats);

    if (UploadLength && DownloadLength) {
        WriteOutput("Must specify only one of '-upload' or '-download' argument!\n");
        return QUIC_STATUS_INVALID_PARAMETER;
    }

    if (UploadLength == 0 && DownloadLength == 0) {
        WriteOutput("Must specify non 0 length for either '-upload' or '-download' argument!\n");
        return QUIC_STATUS_INVALID_PARAMETER;
    }

    uint16_t Ip;
    if (TryGetValue(argc, argv, "ip", &Ip)) {
        switch (Ip) {
        case 4: RemoteFamily = QUIC_ADDRESS_FAMILY_INET; break;
        case 6: RemoteFamily = QUIC_ADDRESS_FAMILY_INET6; break;
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

    const char* CibirBytes = nullptr;
    if (TryGetValue(argc, argv, "cibir", &CibirBytes)) {
        CibirId[0] = 0; // offset
        if ((CibirIdLength = DecodeHexBuffer(CibirBytes, 6, CibirId+1)) == 0) {
            WriteOutput("Cibir ID must be a hex string <= 6 bytes.\n");
            return QUIC_STATUS_INVALID_PARAMETER;
        }
    }

    QUIC_STATUS Status;

    if (QUIC_FAILED(Status = CxPlatSetCurrentThreadGroupAffinity(0))) {
        WriteOutput("Failed to set thread group affinity\n");
        return Status;
    }

    uint16_t CpuCore;
    if (TryGetValue(argc, argv, "core", &CpuCore)) {
        if (QUIC_FAILED(Status = CxPlatSetCurrentThreadProcessorAffinity(CpuCore))) {
            WriteOutput("Failed to set core\n");
            return Status;
        }
    }

    TryGetValue(argc, argv, "sendbuf", &UseSendBuffer);
    TryGetValue(argc, argv, "pacing", &UsePacing);
    TryGetValue(argc, argv, "timed", &TimedTransfer);

    IoSize = PERF_DEFAULT_IO_SIZE;
    TryGetValue(argc, argv, "iosize", &IoSize);

    size_t Len = strlen(Target);
    char* LocalTarget = new(std::nothrow) char[Len + 1];
    if (LocalTarget == nullptr) {
        return QUIC_STATUS_OUT_OF_MEMORY;
    }
    TargetData.reset(LocalTarget);
    CxPlatCopyMemory(TargetData.get(), Target, Len);
    TargetData[Len] = '\0';

    DataBuffer = (QUIC_BUFFER*)CXPLAT_ALLOC_NONPAGED(sizeof(QUIC_BUFFER) + IoSize, QUIC_POOL_PERF);
    if (!DataBuffer) {
        return QUIC_STATUS_OUT_OF_MEMORY;
    }
    DataBuffer->Buffer = (uint8_t*)(DataBuffer + 1);

    if (DownloadLength) {
        DataBuffer->Length = sizeof(uint64_t);
        *(uint64_t*)(DataBuffer->Buffer) =
            TimedTransfer ? UINT64_MAX : CxPlatByteSwapUint64(DownloadLength);
    } else {
        DataBuffer->Length = IoSize;
        *(uint64_t*)(DataBuffer->Buffer) = CxPlatByteSwapUint64(0); // Zero-length request
        for (uint32_t i = 0; i < IoSize - sizeof(uint64_t); ++i) {
            DataBuffer->Buffer[sizeof(uint64_t) + i] = (uint8_t)i;
        }
    }

    return QUIC_STATUS_SUCCESS;
}

QUIC_STATUS
ThroughputClient::Start(
    _In_ CXPLAT_EVENT* StopEvnt
    ) {
    this->StopEvent = StopEvnt;
    QuicTraceLogVerbose(
        PerfRpsStart,
        "[perf] RPS Client start");
    return UseTcp ? StartTcp() : StartQuic();
}

QUIC_STATUS
ThroughputClient::Wait(
    _In_ int Timeout
    ) {
    if (Timeout > 0) {
        if (!CxPlatEventWaitWithTimeout(*StopEvent, Timeout)) {
            QuicTraceLogVerbose(
                PerfRpsTimeout,
                "[perf] RPS Client timeout");
        }
    } else {
        CxPlatEventWaitForever(*StopEvent);
    }
    QuicTraceLogVerbose(
        PerfRpsComplete,
        "[perf] RPS Client complete");
    Registration.Shutdown(QUIC_CONNECTION_SHUTDOWN_FLAG_NONE, 1);
    OnTcpConnectionComplete();
    return QUIC_STATUS_SUCCESS;
}

void
ThroughputClient::GetExtraDataMetadata(
    _Out_ PerfExtraDataMetadata* Result
    )
{
    Result->TestType = PerfTestType::ThroughputClient;
    Result->ExtraDataLength = 0;
}

QUIC_STATUS
ThroughputClient::GetExtraData(
    _Out_writes_bytes_(*Length) uint8_t*,
    _Inout_ uint32_t* Length
    )
{
    *Length = 0;
    return QUIC_STATUS_SUCCESS;
}

QUIC_STATUS
ThroughputClient::StartQuic()
{
    struct QuicShutdownWrapper {
        HQUIC ConnHandle {nullptr};
        ~QuicShutdownWrapper() {
            if (ConnHandle) {
                MsQuic->ConnectionShutdown(ConnHandle, QUIC_CONNECTION_SHUTDOWN_FLAG_NONE, 0);
            }
        }
    } Shutdown;

    QUIC_STATUS Status =
        MsQuic->ConnectionOpen(
            Registration,
            [](HQUIC Handle, void* Context, QUIC_CONNECTION_EVENT* Event) -> QUIC_STATUS {
                ThroughputClient* This = (ThroughputClient*)Context;
                return This->ConnectionCallback(Handle, Event);
            },
            this,
            &Shutdown.ConnHandle);
    if (QUIC_FAILED(Status)) {
        WriteOutput("Failed ConnectionOpen 0x%x\n", Status);
        return Status;
    }

    if (!UseSendBuffer || !UsePacing) {
        QUIC_SETTINGS Settings{0};
        if (!UseSendBuffer) {
            Settings.SendBufferingEnabled = FALSE;
            Settings.IsSet.SendBufferingEnabled = TRUE;
        }
        if (!UsePacing) {
            Settings.PacingEnabled = FALSE;
            Settings.IsSet.PacingEnabled = TRUE;
        }
        Status =
            MsQuic->SetParam(
                Shutdown.ConnHandle,
                QUIC_PARAM_CONN_SETTINGS,
                sizeof(Settings),
                &Settings);
        if (QUIC_FAILED(Status)) {
            WriteOutput("MsQuic->SetParam (CONN_SETTINGS) failed! 0x%x\n", Status);
            return Status;
        }
    }

    if (!UseEncryption) {
        BOOLEAN value = TRUE;
        Status =
            MsQuic->SetParam(
                Shutdown.ConnHandle,
                QUIC_PARAM_CONN_DISABLE_1RTT_ENCRYPTION,
                sizeof(value),
                &value);
        if (QUIC_FAILED(Status)) {
            WriteOutput("MsQuic->SetParam (CONN_DISABLE_1RTT_ENCRYPTION) failed!\n");
            return Status;
        }
    }

    if (QuicAddrGetFamily(&LocalIpAddr) != QUIC_ADDRESS_FAMILY_UNSPEC) {
        MsQuic->SetParam(
            Shutdown.ConnHandle,
            QUIC_PARAM_CONN_LOCAL_ADDRESS,
            sizeof(LocalIpAddr),
            &LocalIpAddr);
    }

    if (CibirIdLength) {
        BOOLEAN Opt = TRUE;
        Status =
            MsQuic->SetParam(
                Shutdown.ConnHandle,
                QUIC_PARAM_CONN_SHARE_UDP_BINDING,
                sizeof(Opt),
                &Opt);
        if (QUIC_FAILED(Status)) {
            WriteOutput("SetParam(CONN_SHARE_UDP_BINDING) failed, 0x%x\n", Status);
            return Status;
        }

        Status =
            MsQuic->SetParam(
                Shutdown.ConnHandle,
                QUIC_PARAM_CONN_CIBIR_ID,
                CibirIdLength+1,
                CibirId);
        if (QUIC_FAILED(Status)) {
            WriteOutput("SetParam(CONN_CIBIR_ID) failed, 0x%x\n", Status);
            return Status;
        }
    }

    StreamContext* StrmContext = StreamContextAllocator.Alloc(this);
    if (UseSendBuffer) {
        StrmContext->IdealSendBuffer = 1; // Hack to use only 1 send buffer
    }

    Status =
        MsQuic->StreamOpen(
            Shutdown.ConnHandle,
            QUIC_STREAM_OPEN_FLAG_NONE,
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

    if (DownloadLength) {
        MsQuic->StreamSend(
            StrmContext->Stream.Handle,
            DataBuffer,
            1,
            QUIC_SEND_FLAG_FIN,
            DataBuffer);
    } else {
        CXPLAT_DBG_ASSERT(UploadLength != 0);
        SendQuicData(StrmContext);
    }

    Status =
        MsQuic->ConnectionStart(
            Shutdown.ConnHandle,
            Configuration,
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

void
ThroughputClient::SendQuicData(
    _In_ StreamContext* Context
    )
{
    while (!Context->Complete && Context->OutstandingBytes < Context->IdealSendBuffer) {

        uint64_t BytesLeftToSend =
            TimedTransfer ? UINT64_MAX : (UploadLength - Context->BytesSent);
        uint32_t DataLength = IoSize;
        QUIC_BUFFER* Buffer = DataBuffer;
        QUIC_SEND_FLAGS Flags = QUIC_SEND_FLAG_NONE;

        if ((uint64_t)DataLength >= BytesLeftToSend) {
            DataLength = (uint32_t)BytesLeftToSend;
            Context->LastBuffer.Buffer = Buffer->Buffer;
            Context->LastBuffer.Length = DataLength;
            Buffer = &Context->LastBuffer;
            Flags = QUIC_SEND_FLAG_FIN;
            Context->Complete = TRUE;

        } else if (TimedTransfer &&
                   CxPlatTimeDiff64(Context->StartTime, CxPlatTimeUs64()) >= MS_TO_US(UploadLength)) {
            Flags = QUIC_SEND_FLAG_FIN;
            Context->Complete = TRUE;
        }

        Context->BytesSent += DataLength;
        Context->OutstandingBytes += DataLength;

        MsQuic->StreamSend(Context->Stream.Handle, Buffer, 1, Flags, Buffer);
    }
}

QUIC_STATUS
ThroughputClient::StartTcp()
{
    MsQuicCredentialConfig CredConfig(QUIC_CREDENTIAL_FLAG_CLIENT | QUIC_CREDENTIAL_FLAG_NO_CERTIFICATE_VALIDATION);
    TcpConn =
        new(std::nothrow) TcpConnection(
            &Engine,
            &CredConfig,
            RemoteFamily,
            TargetData.get(),
            Port,
            (QuicAddrGetFamily(&LocalIpAddr) != QUIC_ADDRESS_FAMILY_UNSPEC) ? &LocalIpAddr : nullptr,
            this);
    if (!TcpConn || !TcpConn->IsInitialized()) {
        if (TcpConn) {
            TcpConn->Close();
            TcpConn = nullptr;
        }
        return QUIC_STATUS_OUT_OF_MEMORY;
    }

    TcpStrmContext = StreamContextAllocator.Alloc(this);
    TcpStrmContext->IdealSendBuffer = 1; // TCP uses send buffering, so just set to 1.

    if (DownloadLength) {
        auto SendData = new(std::nothrow) TcpSendData();
        SendData->StreamId = 0;
        SendData->Open = TRUE;
        SendData->Fin = TRUE;
        SendData->Buffer = DataBuffer->Buffer;
        SendData->Length = DataBuffer->Length;
        TcpConn->Send(SendData);
    } else {
        CXPLAT_DBG_ASSERT(UploadLength != 0);
        SendTcpData(TcpConn, TcpStrmContext);
    }

    return QUIC_STATUS_SUCCESS;
}

void
ThroughputClient::SendTcpData(
    _In_ TcpConnection* Connection,
    _In_ StreamContext* Context
    )
{
    while (!Context->Complete && Context->OutstandingBytes < Context->IdealSendBuffer) {

        uint64_t BytesLeftToSend =
            TimedTransfer ? UINT64_MAX : (UploadLength - Context->BytesSent);

        auto SendData = new(std::nothrow) TcpSendData();
        SendData->StreamId = 0;
        SendData->Open = Context->BytesSent == 0 ? TRUE : FALSE;
        SendData->Buffer = DataBuffer->Buffer;
        SendData->Length = IoSize;
        if ((uint64_t)IoSize >= BytesLeftToSend) {
            SendData->Length = (uint32_t)BytesLeftToSend;
            SendData->Fin = TRUE;
            Context->Complete = TRUE;

        } else if (TimedTransfer &&
                   CxPlatTimeDiff64(Context->StartTime, CxPlatTimeUs64()) >= MS_TO_US(UploadLength)) {
            SendData->Fin = TRUE;
            Context->Complete = TRUE;

        } else {
            SendData->Fin = FALSE;
        }

        Context->BytesSent += SendData->Length;
        Context->OutstandingBytes += SendData->Length;

        Connection->Send(SendData);
    }
}

void
ThroughputClient::OnStreamShutdownComplete(
    _In_ StreamContext* StrmContext
    )
{
    StrmContext->EndTime = CxPlatTimeUs64();
    uint64_t ElapsedMicroseconds = StrmContext->EndTime - StrmContext->StartTime;
    uint32_t SendRate = (uint32_t)((StrmContext->BytesCompleted * 1000 * 1000 * 8) / (1000 * ElapsedMicroseconds));

    if (!StrmContext->Complete && StrmContext->BytesCompleted == 0) {
        WriteOutput("Error: Did not complete any bytes! Failed to connect?\n");
    } else {
        WriteOutput(
            "Result: %llu bytes @ %u kbps (%u.%03u ms).\n",
            (unsigned long long)StrmContext->BytesCompleted,
            SendRate,
            (uint32_t)(ElapsedMicroseconds / 1000),
            (uint32_t)(ElapsedMicroseconds % 1000));
        if (!StrmContext->Complete) {
            WriteOutput(
                "Warning: Did not complete all bytes (sent: %llu, completed: %llu).\n",
                (unsigned long long)StrmContext->BytesSent,
                (unsigned long long)StrmContext->BytesCompleted);
        }
    }

    StreamContextAllocator.Free(StrmContext);
}

QUIC_STATUS
ThroughputClient::ConnectionCallback(
    _In_ HQUIC ConnectionHandle,
    _Inout_ QUIC_CONNECTION_EVENT* Event
    ) {
    switch (Event->Type) {
    case QUIC_CONNECTION_EVENT_SHUTDOWN_COMPLETE:
        if (PrintStats) {
            QuicPrintConnectionStatistics(MsQuic, ConnectionHandle);
        }
        MsQuic->ConnectionClose(ConnectionHandle);
        CxPlatEventSet(*StopEvent);
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
    case QUIC_STREAM_EVENT_RECEIVE:
        StrmContext->BytesCompleted += Event->RECEIVE.TotalBufferLength;
        if (StrmContext->Client->TimedTransfer) {
            if (CxPlatTimeDiff64(StrmContext->StartTime, CxPlatTimeUs64()) >= MS_TO_US(DownloadLength)) {
                MsQuic->StreamShutdown(StreamHandle, QUIC_STREAM_SHUTDOWN_FLAG_ABORT_RECEIVE, 0);
                StrmContext->Complete = true;
            }
        } else if (StrmContext->BytesCompleted == DownloadLength) {
            StrmContext->Complete = true;
        }
        break;
    case QUIC_STREAM_EVENT_SEND_COMPLETE:
        if (UploadLength) {
            StrmContext->OutstandingBytes -= ((QUIC_BUFFER*)Event->SEND_COMPLETE.ClientContext)->Length;
            if (!Event->SEND_COMPLETE.Canceled) {
                StrmContext->BytesCompleted += ((QUIC_BUFFER*)Event->SEND_COMPLETE.ClientContext)->Length;
                SendQuicData(StrmContext);
            }
        }
        break;
    case QUIC_STREAM_EVENT_PEER_SEND_ABORTED:
    case QUIC_STREAM_EVENT_PEER_RECEIVE_ABORTED:
        if (!StrmContext->Complete) {
            WriteOutput("Stream aborted\n");
        }
        MsQuic->StreamShutdown(StreamHandle, QUIC_STREAM_SHUTDOWN_FLAG_ABORT, 0);
        break;
    case QUIC_STREAM_EVENT_SHUTDOWN_COMPLETE:
        OnStreamShutdownComplete(StrmContext);
        break;
    case QUIC_STREAM_EVENT_IDEAL_SEND_BUFFER_SIZE:
        if (UploadLength &&
            !UseSendBuffer &&
            StrmContext->IdealSendBuffer < Event->IDEAL_SEND_BUFFER_SIZE.ByteCount) {
            StrmContext->IdealSendBuffer = Event->IDEAL_SEND_BUFFER_SIZE.ByteCount;
            SendQuicData(StrmContext);
        }
        break;
    default:
        break;
    }
    return QUIC_STATUS_SUCCESS;
}

_IRQL_requires_max_(DISPATCH_LEVEL)
void
ThroughputClient::OnTcpConnectionComplete(
    )
{
    CxPlatLockAcquire(&TcpLock);
    auto Connection = TcpConn;
    TcpConn = nullptr;
    auto Stream = TcpStrmContext;
    TcpStrmContext = nullptr;
    CxPlatLockRelease(&TcpLock);

    if (Stream) {
        OnStreamShutdownComplete(Stream);
    }
    if (Connection) {
        Connection->Close();
    }
    CxPlatEventSet(*StopEvent);
}

_IRQL_requires_max_(DISPATCH_LEVEL)
_Function_class_(TcpConnectCallback)
void
ThroughputClient::TcpConnectCallback(
    _In_ TcpConnection* Connection,
    bool IsConnected
    )
{
    auto This = (ThroughputClient*)Connection->Context;
    if (!IsConnected) {
        This->OnTcpConnectionComplete();
    }
}

_IRQL_requires_max_(DISPATCH_LEVEL)
_Function_class_(TcpReceiveCallback)
void
ThroughputClient::TcpReceiveCallback(
    _In_ TcpConnection* Connection,
    uint32_t /* StreamID */,
    bool /* Open */,
    bool Fin,
    bool Abort,
    uint32_t Length,
    uint8_t* /* Buffer */
    )
{
    auto This = (ThroughputClient*)Connection->Context;
    auto StrmContext = This->TcpStrmContext;
    if (!StrmContext) return;
    if (Length) {
        StrmContext->BytesCompleted += Length;
        if (This->TimedTransfer) {
            if (CxPlatTimeDiff64(StrmContext->StartTime, CxPlatTimeUs64()) >= MS_TO_US(This->DownloadLength)) {
                auto SendData = new(std::nothrow) TcpSendData();
                SendData->StreamId = 0;
                SendData->Abort = TRUE;
                SendData->Buffer = This->DataBuffer->Buffer;
                SendData->Length = 0;
                Connection->Send(SendData);
                StrmContext->Complete = true;
            }
        } else if (StrmContext->BytesCompleted == This->DownloadLength) {
            StrmContext->Complete = true;
        }
    }
    if ((Fin || Abort) && !StrmContext->RecvShutdown) {
        StrmContext->RecvShutdown = true;
        if (StrmContext->SendShutdown) {
            This->OnTcpConnectionComplete();
        }
    }
}

_IRQL_requires_max_(DISPATCH_LEVEL)
_Function_class_(TcpSendCompleteCallback)
void
ThroughputClient::TcpSendCompleteCallback(
    _In_ TcpConnection* Connection,
    TcpSendData* SendDataChain
    )
{
    auto This = (ThroughputClient*)Connection->Context;
    while (SendDataChain) {
        auto Data = SendDataChain;
        SendDataChain = Data->Next;
        if (This->TcpStrmContext) {
            if (This->UploadLength) {
                This->TcpStrmContext->OutstandingBytes -= Data->Length;
                This->TcpStrmContext->BytesCompleted += Data->Length;
                This->SendTcpData(Connection, This->TcpStrmContext);
            }
            if ((Data->Fin || Data->Abort) && !This->TcpStrmContext->SendShutdown) {
                This->TcpStrmContext->SendShutdown = true;
                if (This->TcpStrmContext->RecvShutdown) {
                    This->OnTcpConnectionComplete();
                }
            }
        }
        delete Data;
    }
}
