/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.

Abstract:

    QUIC Perf Server Implementation.

--*/

#include "PerfServer.h"

#ifdef QUIC_CLOG
#include "PerfServer.cpp.clog.h"
#endif

const uint8_t SecNetPerfShutdownGuid[16] = { // {ff15e657-4f26-570e-88ab-0796b258d11c}
    0x57, 0xe6, 0x15, 0xff, 0x26, 0x4f, 0x0e, 0x57,
    0x88, 0xab, 0x07, 0x96, 0xb2, 0x58, 0xd1, 0x1c};

QUIC_STATUS
PerfServer::Init(
    _In_ int argc,
    _In_reads_(argc) _Null_terminated_ char* argv[]
    ) {
    if (QUIC_FAILED(InitStatus)) {
        WriteOutput("PerfServer failed to initialize\n");
        return InitStatus;
    }

    TryGetValue(argc, argv, "stats", &PrintStats);

    const char* LocalAddress = nullptr;
    uint16_t Port = 0;
    if (TryGetValue(argc, argv, "bind", &LocalAddress)) {
        if (!ConvertArgToAddress(LocalAddress, PERF_DEFAULT_PORT, &LocalAddr)) {
            WriteOutput("Failed to decode IP address: '%s'!\nMust be *, a IPv4 or a IPv6 address.\n", LocalAddress);
            return QUIC_STATUS_INVALID_PARAMETER;
        }
    } else if (TryGetValue(argc, argv, "port", &Port)) {
        QuicAddrSetPort(&LocalAddr, Port);
    }

    uint32_t ServerId = 0;
    if (TryGetValue(argc, argv, "serverid", &ServerId)) {
        MsQuicGlobalSettings GlobalSettings;
        GlobalSettings.SetFixedServerID(ServerId);
        GlobalSettings.SetLoadBalancingMode(QUIC_LOAD_BALANCING_SERVER_ID_FIXED);

        QUIC_STATUS Status;
        if (QUIC_FAILED(Status = GlobalSettings.Set())) {
            WriteOutput("Failed to set global settings %d\n", Status);
            return Status;
        }
    }

    const char* CibirBytes = nullptr;
    if (TryGetValue(argc, argv, "cibir", &CibirBytes)) {
        uint32_t CibirIdLength;
        uint8_t CibirId[7] = {0}; // {offset, values}
        if ((CibirIdLength = DecodeHexBuffer(CibirBytes, 6, CibirId+1)) == 0) {
            WriteOutput("Cibir ID must be a hex string <= 6 bytes.\n");
            return QUIC_STATUS_INVALID_PARAMETER;
        }

        QUIC_STATUS Status;
        if (QUIC_FAILED(Status = Listener.SetCibirId(CibirId, (uint8_t)CibirIdLength+1))) {
            WriteOutput("Failed to set CibirId!\n");
            return Status;
        }
    }

    if (TryGetVariableUnitValue(argc, argv, "delay", &DelayMicroseconds, nullptr) &&
        (0 != DelayMicroseconds)) {
        const char* DelayTypeString = nullptr;
        DelayType = SYNTHETIC_DELAY_FIXED;

        if (TryGetValue(argc, argv, "delayType", &DelayTypeString)) {
#ifndef _KERNEL_MODE
            if (IsValue(DelayTypeString, "variable")) {
                DelayType = SYNTHETIC_DELAY_VARIABLE;
                //
                // DelayMicroseconds represents the mean delay for the exponential distribution
                // used in generating random variable delay values
                //
                Lambda = ((double)1) / DelayMicroseconds;
                //
                // MaxFixedDelayUs is in the range [1000us, 4x mean delay) and <3% of values
                // in a random exponential distribution typically are larger than this value.
                // If the randomly generated delay value is in the range [0,MaxFixedDelayUs),
                // the delay thread busy-waits. Outside this range, background thread sleeps
                // for a rounded up ms delay duration. This is intended to simulate worker threads
                // that are mostly processing in-memory resources but occassionally have to wait
                // a longer duration to fulfil a request.
                //
                MaxFixedDelayUs = static_cast<uint32_t>(4 * (uint64_t)DelayMicroseconds);
                if (MaxFixedDelayUs < 1000) MaxFixedDelayUs = 1000;
            } else if (!IsValue(DelayTypeString, "fixed")) {
                WriteOutput("Failed to parse DelayType[%s] parameter. Using fixed DelayType.\n", DelayTypeString);
            }
#else
            WriteOutput("Kernel mode supports only the fixed delay type\n");
#endif // !_KERNEL_MODE
        }

        ProcCount = (uint16_t)CxPlatProcCount();
        DelayWorkers = new (std::nothrow) DelayWorker[ProcCount];
        if (!DelayWorkers) {
            WriteOutput("Failed to allocate delay workers.\n");
            return QUIC_STATUS_OUT_OF_MEMORY;
        }
        for (uint16_t i = 0; i < ProcCount; ++i) {
            if (!DelayWorkers[i].Initialize(this, i)) {
                for (uint16_t j = 0; j < i; ++j) {
                    DelayWorkers[j].Shutdown();
                }
                delete[] DelayWorkers;
                DelayWorkers = nullptr;
                WriteOutput("Failed to init delay workers.\n");
                return QUIC_STATUS_INTERNAL_ERROR;
            }
        }
    }

    //
    // Set up the special UDP listener to allow remote tear down.
    //
    QuicAddr TeardownLocalAddress {QUIC_ADDRESS_FAMILY_INET, (uint16_t)9999};
    CXPLAT_UDP_CONFIG UdpConfig = {&TeardownLocalAddress.SockAddr, 0};
    UdpConfig.CallbackContext = this;
#ifdef QUIC_OWNING_PROCESS
    UdpConfig.OwningProcess = QuicProcessGetCurrentProcess();
#endif

    QUIC_STATUS Status = CxPlatSocketCreateUdp(Datapath, &UdpConfig, &TeardownBinding);
    if (QUIC_FAILED(Status)) {
        TeardownBinding = nullptr;
        WriteOutput("Failed to initialize teardown binding: %d\n", Status);
        return Status;
    }

    return QUIC_STATUS_SUCCESS;
}

QUIC_STATUS
PerfServer::Start(
    _In_ CXPLAT_EVENT* _StopEvent
    ) {
    StopEvent = _StopEvent;
    if (!Server.Start(&LocalAddr)) {
        WriteOutput("Warning: TCP Server failed to start!\n");
    }
    return Listener.Start(PERF_ALPN, &LocalAddr);
}

QUIC_STATUS
PerfServer::Wait(
    _In_ int Timeout
    ) {
    if (Timeout > 0) {
        CxPlatEventWaitWithTimeout(*StopEvent, Timeout);
    } else {
        CxPlatEventWaitForever(*StopEvent);
    }
    Registration.Shutdown(QUIC_CONNECTION_SHUTDOWN_FLAG_NONE, 0);
    return QUIC_STATUS_SUCCESS;
}

void
PerfServer::DatapathReceive(
    _In_ CXPLAT_SOCKET*,
    _In_ void* Context,
    _In_ CXPLAT_RECV_DATA* Data
    )
{
    if (Data->BufferLength != sizeof(SecNetPerfShutdownGuid) ||
        memcmp(Data->Buffer, SecNetPerfShutdownGuid, sizeof(SecNetPerfShutdownGuid))) {
        return;
    }
    auto Server = (PerfServer*)Context;
    if (Server->StopEvent) {
        CxPlatEventSet(*Server->StopEvent);
    }
}

QUIC_STATUS
PerfServer::ListenerCallback(
    _Inout_ QUIC_LISTENER_EVENT* Event
    ) {
    QUIC_STATUS Status = QUIC_STATUS_NOT_SUPPORTED;
    if (Event->Type == QUIC_LISTENER_EVENT_NEW_CONNECTION) {
        BOOLEAN value = TRUE;
        MsQuic->SetParam(Event->NEW_CONNECTION.Connection, QUIC_PARAM_CONN_DISABLE_1RTT_ENCRYPTION, sizeof(value), &value);
        if (PerfDefaultDscpValue != 0) {
            MsQuic->SetParam(
                Event->NEW_CONNECTION.Connection,
                QUIC_PARAM_CONN_SEND_DSCP,
                sizeof(PerfDefaultDscpValue),
                &PerfDefaultDscpValue);
        }
        QUIC_CONNECTION_CALLBACK_HANDLER Handler =
            [](HQUIC Conn, void* Context, QUIC_CONNECTION_EVENT* Event) -> QUIC_STATUS {
                return ((PerfServer*)Context)->ConnectionCallback(Conn, Event);
            };
        MsQuic->SetCallbackHandler(Event->NEW_CONNECTION.Connection, (void*)Handler, this);
        Status = MsQuic->ConnectionSetConfiguration(Event->NEW_CONNECTION.Connection, Configuration);
    }
    return Status;
}

QUIC_STATUS
PerfServer::ConnectionCallback(
    _In_ HQUIC ConnectionHandle,
    _Inout_ QUIC_CONNECTION_EVENT* Event
    ) {
    switch (Event->Type) {
    case QUIC_CONNECTION_EVENT_SHUTDOWN_COMPLETE:
        if (!Event->SHUTDOWN_COMPLETE.AppCloseInProgress) {
            if (PrintStats) {
                QuicPrintConnectionStatistics(MsQuic, ConnectionHandle);
            }
            MsQuic->ConnectionClose(ConnectionHandle);
        }
        break;
    case QUIC_CONNECTION_EVENT_PEER_STREAM_STARTED: {
        bool Unidirectional = Event->PEER_STREAM_STARTED.Flags & QUIC_STREAM_OPEN_FLAG_UNIDIRECTIONAL;
        auto Context = StreamContextAllocator.Alloc(this, Unidirectional, false,
                                                    (void*)Event->PEER_STREAM_STARTED.Stream, false); // TODO - Support buffered IO
        if (!Context) { return QUIC_STATUS_OUT_OF_MEMORY; }
        QUIC_STREAM_CALLBACK_HANDLER Handler =
            [](HQUIC Stream, void* Context, QUIC_STREAM_EVENT* Event) -> QUIC_STATUS {
                return ((StreamContext*)Context)->Server->StreamCallback((StreamContext*)Context, Stream, Event);
            };
        MsQuic->SetCallbackHandler(Event->PEER_STREAM_STARTED.Stream, (void*)Handler, Context);
        break;
    }
    default:
        break;
    }
    return QUIC_STATUS_SUCCESS;
}

void
PerfServer::IntroduceFixedDelay(uint32_t DelayUs)
{
    if (0 == DelayUs) {
        return;
    }

    uint64_t Start = CxPlatTimeUs64();
    while (CxPlatTimeDiff64(Start, CxPlatTimeUs64()) <= DelayUs) { /* busy wait*/ }
}

#ifndef _KERNEL_MODE

#include <random>

double
PerfServer::CalculateVariableDelay(double DistributionParam)
{
    std::mt19937 random_generator(CxPlatTimeUs32());
    std::exponential_distribution<> distribution(abs(DistributionParam));
    return distribution(random_generator);
}

void
PerfServer::IntroduceVariableDelay(uint32_t DelayUs)
{
    if (0 == DelayUs) {
        return;
    }

    //
    // Mean value of VariableDelay is expected to be DelayUs
    //
    double VariableDelay = CalculateVariableDelay(Lambda);

    if ((VariableDelay + 1) < MaxFixedDelayUs) {
        //
        // Introduce a fixed delay up to a certain maximum value
        //
        IntroduceFixedDelay(static_cast<uint32_t>(VariableDelay));
    } else {
        //
        // If the variable delay exceeds the maximum value,
        // yield the thread for the max delay
        //
        CxPlatSleep(static_cast<uint32_t>(MaxFixedDelayUs/1000));
    }
}
#endif // !_KERNEL_MODE

void
PerfServer::SimulateDelay()
{
    if (DelayMicroseconds == 0) {
        return;
    }

    switch (DelayType) {
#ifndef _KERNEL_MODE
    case SYNTHETIC_DELAY_VARIABLE:
        IntroduceVariableDelay(DelayMicroseconds);
        break;
#endif // !_KERNEL_MODE
    case SYNTHETIC_DELAY_FIXED: // fall through
    default:
        IntroduceFixedDelay(DelayMicroseconds);
        break;
    }
}

QUIC_STATUS
PerfServer::StreamCallback(
    _In_ StreamContext* Context,
    _In_ HQUIC StreamHandle,
    _Inout_ QUIC_STREAM_EVENT* Event
    ) {
    switch (Event->Type) {
    case QUIC_STREAM_EVENT_RECEIVE:
        if (!Context->ResponseSizeSet) {
            uint8_t* Dest = (uint8_t*)&Context->ResponseSize;
            uint64_t Offset = Event->RECEIVE.AbsoluteOffset;
            for (uint32_t i = 0; Offset < sizeof(uint64_t) && i < Event->RECEIVE.BufferCount; ++i) {
                uint32_t Length = CXPLAT_MIN((uint32_t)(sizeof(uint64_t) - Offset), Event->RECEIVE.Buffers[i].Length);
                memcpy(Dest + Offset, Event->RECEIVE.Buffers[i].Buffer, Length);
                Offset += Length;
            }
            if (Offset == sizeof(uint64_t)) {
                Context->ResponseSize = CxPlatByteSwapUint64(Context->ResponseSize);
                Context->ResponseSizeSet = true;
            }
        }
        break;
    case QUIC_STREAM_EVENT_SEND_COMPLETE:
        Context->OutstandingBytes -= ((QUIC_BUFFER*)Event->SEND_COMPLETE.ClientContext)->Length;
        if (!Event->SEND_COMPLETE.Canceled) {
            SendResponse(Context, StreamHandle, false);
        }
        break;
    case QUIC_STREAM_EVENT_PEER_SEND_SHUTDOWN:
        if (!Context->ResponseSizeSet) {
            MsQuic->StreamShutdown(StreamHandle, QUIC_STREAM_SHUTDOWN_FLAG_ABORT, 0);
        } else if (Context->ResponseSize != 0) {
            if (Context->Unidirectional) {
                // TODO - Not supported right now
                MsQuic->StreamShutdown(StreamHandle, QUIC_STREAM_SHUTDOWN_FLAG_ABORT, 0);
            } else {
                CXPLAT_DBG_ASSERT(Context->Handle == (void*)StreamHandle);
                CXPLAT_DBG_ASSERT(!Context->IsTcp);
                if (DelayWorkers) {
                    SendDelayedResponse(Context);
                } else {
                    SendResponse(Context, StreamHandle, false);
                }
            }
        } else if (!Context->Unidirectional) {
            MsQuic->StreamShutdown(StreamHandle, QUIC_STREAM_SHUTDOWN_FLAG_GRACEFUL, 0);
        }
        break;
    case QUIC_STREAM_EVENT_PEER_SEND_ABORTED:
    case QUIC_STREAM_EVENT_PEER_RECEIVE_ABORTED:
        MsQuic->StreamShutdown(StreamHandle, QUIC_STREAM_SHUTDOWN_FLAG_ABORT, 0);
        break;
    case QUIC_STREAM_EVENT_SHUTDOWN_COMPLETE:
        Context->InactivateAndRelease();
        break;
    case QUIC_STREAM_EVENT_IDEAL_SEND_BUFFER_SIZE:
        if (!Context->BufferedIo &&
            Context->IdealSendBuffer < Event->IDEAL_SEND_BUFFER_SIZE.ByteCount) {
            Context->IdealSendBuffer = Event->IDEAL_SEND_BUFFER_SIZE.ByteCount;
            SendResponse(Context, StreamHandle, false);
        }
        break;
    default:
        break;
    }
    return QUIC_STATUS_SUCCESS;
}

void
PerfServer::SendResponse(
    _In_ StreamContext* Context,
    _In_ void* Handle,
    _In_ bool IsTcp
    )
{
    while (Context->BytesSent < Context->ResponseSize &&
           Context->OutstandingBytes < Context->IdealSendBuffer) {

        uint64_t BytesLeftToSend = Context->ResponseSize - Context->BytesSent;
        uint32_t IoSize = PERF_DEFAULT_IO_SIZE;
        QUIC_BUFFER* Buffer = ResponseBuffer;
        QUIC_SEND_FLAGS Flags = QUIC_SEND_FLAG_NONE;

        if ((uint64_t)IoSize >= BytesLeftToSend) {
            IoSize = (uint32_t)BytesLeftToSend;
            Context->LastBuffer.Buffer = Buffer->Buffer;
            Context->LastBuffer.Length = IoSize;
            Buffer = &Context->LastBuffer;
            Flags = QUIC_SEND_FLAG_FIN;
        }

        Context->BytesSent += IoSize;
        Context->OutstandingBytes += IoSize;

        if (IsTcp) {
            auto SendData = TcpSendDataAllocator.Alloc();
            SendData->StreamId = (uint32_t)Context->Entry.Signature;
            SendData->Open = Context->BytesSent == 0 ? 1 : 0;
            SendData->Buffer = Buffer->Buffer;
            SendData->Length = IoSize;
            SendData->Fin = (Flags & QUIC_SEND_FLAG_FIN) ? TRUE : FALSE;
            ((TcpConnection*)Handle)->Send(SendData);
        } else {
            MsQuic->StreamSend((HQUIC)Handle, Buffer, 1, Flags, Buffer);
        }
    }
}

void
PerfServer::SendDelayedResponse(_In_ StreamContext* Context)
{
    uint16_t WorkerNumber = (uint16_t)CxPlatProcCurrentNumber();
    CXPLAT_DBG_ASSERT(WorkerNumber < ProcCount);
    Context->AddRef();
    if (Context->IsTcp) {
        //
        // TcpConnection object is separately reference counted
        //
        CXPLAT_FRE_ASSERT(((TcpConnection*)Context->Handle)->TryAddRef());
    }
    DelayWorkers[WorkerNumber].QueueWork(Context);
}

_IRQL_requires_max_(DISPATCH_LEVEL)
_Function_class_(TcpAcceptCallback)
void
PerfServer::TcpAcceptCallback(
    _In_ TcpServer* Server,
    _In_ TcpConnection* Connection
    )
{
    auto This = (PerfServer*)Server->Context;
    Connection->Context = This->TcpConnectionContextAllocator.Alloc(This);
}

_IRQL_requires_max_(DISPATCH_LEVEL)
_Function_class_(TcpConnectCallback)
void
PerfServer::TcpConnectCallback(
    _In_ TcpConnection* Connection,
    bool IsConnected
    )
{
    if (!IsConnected) {
        auto This = (TcpConnectionContext*)Connection->Context;
        auto Server = This->Server;
        if (Server->PrintStats) {
            TcpPrintConnectionStatistics(Connection);
        }
        Connection->Close();
        Server->TcpConnectionContextAllocator.Free(This);
    }
}

PerfServer::TcpConnectionContext::~TcpConnectionContext()
{
    // Clean up leftover TCP streams
    CXPLAT_HASHTABLE_ENUMERATOR Enum;
    StreamTable.EnumBegin(&Enum);
    for (;;) {
        auto Stream = (StreamContext*)StreamTable.EnumNext(&Enum);
        if (Stream == NULL) {
            break;
        }
        StreamTable.Remove(&Stream->Entry);
        Stream->Release();
    }
    StreamTable.EnumEnd(&Enum);
}

_IRQL_requires_max_(DISPATCH_LEVEL)
_Function_class_(TcpReceiveCallback)
void
PerfServer::TcpReceiveCallback(
    _In_ TcpConnection* Connection,
    uint32_t StreamID,
    bool Open,
    bool Fin,
    bool Abort,
    uint32_t Length,
    uint8_t* Buffer
    )
{
    auto This = (TcpConnectionContext*)Connection->Context;
    auto Server = This->Server;
    StreamContext* Stream;
    if (Open) {
        if ((Stream = Server->StreamContextAllocator.Alloc(Server, false, false, (void *)Connection, true)) != nullptr) {
            Stream->Entry.Signature = StreamID;
            Stream->IdealSendBuffer = 1; // TCP uses send buffering, so just set to 1.
            This->StreamTable.Insert(&Stream->Entry);
            CXPLAT_FRE_ASSERT(Connection->TryAddRef());
        }
    } else {
        auto Entry = This->StreamTable.Lookup(StreamID);
        Stream = CXPLAT_CONTAINING_RECORD(Entry, StreamContext, Entry);
    }
    if (!Stream) return;
    if (!Stream->ResponseSizeSet && Length != 0) {
        CXPLAT_DBG_ASSERT(Length >= sizeof(uint64_t));
        CxPlatCopyMemory(&Stream->ResponseSize, Buffer, sizeof(uint64_t));
        Stream->ResponseSize = CxPlatByteSwapUint64(Stream->ResponseSize);
        Stream->ResponseSizeSet = true;
    }
    if (Abort) {
        Stream->ResponseSize = 0; // Reset to make sure we stop sending more
        auto SendData = Server->TcpSendDataAllocator.Alloc();
        SendData->StreamId = StreamID;
        SendData->Open = Open ? TRUE : FALSE;
        SendData->Abort = TRUE;
        SendData->Buffer = Server->ResponseBuffer.Raw();
        SendData->Length = 0;
        Connection->Send(SendData);

    } else if (Fin) {
        if (Stream->ResponseSizeSet && Stream->ResponseSize != 0) {
            CXPLAT_DBG_ASSERT(Stream->Handle == (void*)Connection);
            CXPLAT_DBG_ASSERT(Stream->IsTcp);
            if (Server->DelayWorkers) {
                Server->SendDelayedResponse(Stream);
            } else {
                Server->SendResponse(Stream, Connection, true);
            }
        } else {
            auto SendData = Server->TcpSendDataAllocator.Alloc();
            SendData->StreamId = StreamID;
            SendData->Open = TRUE;
            SendData->Fin = TRUE;
            SendData->Buffer = Server->ResponseBuffer.Raw();
            SendData->Length = 0;
            Connection->Send(SendData);
        }
        Stream->RecvShutdown = true;
        if (Stream->SendShutdown) {
            This->StreamTable.Remove(&Stream->Entry);
            Stream->Release();
        }
    }
}

_IRQL_requires_max_(DISPATCH_LEVEL)
_Function_class_(TcpSendCompleteCallback)
void
PerfServer::TcpSendCompleteCallback(
    _In_ TcpConnection* Connection,
    TcpSendData* SendDataChain
    )
{
    auto This = (TcpConnectionContext*)Connection->Context;
    auto Server = This->Server;
    while (SendDataChain) {
        auto Data = SendDataChain;
        auto Entry = This->StreamTable.Lookup(Data->StreamId);
        if (Entry) {
            auto Stream = CXPLAT_CONTAINING_RECORD(Entry, StreamContext, Entry);
            Stream->OutstandingBytes -= Data->Length;
            Server->SendResponse(Stream, Connection, true);
            if ((Data->Fin || Data->Abort) && !Stream->SendShutdown) {
                Stream->SendShutdown = true;
                if (Stream->RecvShutdown) {
                    This->StreamTable.Remove(&Stream->Entry);
                    Stream->Release();
                }
            }
        }
        SendDataChain = SendDataChain->Next;
        Server->TcpSendDataAllocator.Free(Data);
    }
}

bool DelayWorker::Initialize(PerfServer* GivenServer, uint16_t PartitionIndex)
{
    Server = GivenServer;

    //
    // Pin the delay thread to the given partition/processor
    //
    uint16_t ThreadFlags = CXPLAT_THREAD_FLAG_SET_IDEAL_PROC | CXPLAT_THREAD_FLAG_SET_AFFINITIZE;
    CXPLAT_THREAD_CONFIG Config = { ThreadFlags, PartitionIndex, "DelayWorker", WorkerThread, this };
    if (QUIC_FAILED(Thread.Create(&Config))) {
        WriteOutput("CxPlatThreadCreate FAILED\n");
        return false;
    }

    Initialized = true;
    return true;
}

void DelayWorker::Shutdown()
{
    Shuttingdown = true;

    if (Initialized) {
        WakeWorkerThread();
        Initialized = false;
        //
        // delete any pending work items
        //
        Lock.Acquire();
        StreamContext* CurrentWorkItem = WorkItems;
        while (nullptr != CurrentWorkItem) {
            StreamContext* NextWorkItem;
            if (WorkItemsTail == &CurrentWorkItem->DelayNext) {
                NextWorkItem = nullptr;
            } else {
                NextWorkItem = CurrentWorkItem->DelayNext;
            }
            CurrentWorkItem->Release();
            CurrentWorkItem = NextWorkItem;
        }
        WorkItems = nullptr;
        Lock.Release();
    }
}

CXPLAT_THREAD_CALLBACK(DelayWorker::WorkerThread, Worker)
{
    DelayWorker* This = (DelayWorker*)Worker;
    while (DelayedWork(This)) {
        This->WakeEvent.WaitForever();
    }
    CXPLAT_THREAD_RETURN(0);
}

BOOLEAN
DelayWorker::DelayedWork(_Inout_ void* Worker)
{
    DelayWorker* This = (DelayWorker*)Worker;
    StreamContext* WorkItem;
    StreamContext* NextWorkItem;

    do {
        if (This->Shuttingdown) {
            This->DoneEvent.Set();
            return FALSE;
        }

        WorkItem = nullptr;
        NextWorkItem = nullptr;

        This->Lock.Acquire();
        if (nullptr != This->WorkItems) {
            WorkItem = This->WorkItems;
            if (nullptr != WorkItem) {
                NextWorkItem = This->WorkItems = WorkItem->DelayNext;
                if (This->WorkItemsTail == &WorkItem->DelayNext) {
                    This->WorkItemsTail = &This->WorkItems;
                }
                WorkItem->DelayNext = nullptr;
            }
        }
        This->Lock.Release();

        if (nullptr != WorkItem) {
            This->Server->SimulateDelay();
            if (WorkItem->IsActive()) {
                This->Server->SendResponse(WorkItem, WorkItem->Handle, WorkItem->IsTcp);
            }
            WorkItem->Release();
        }
    } while (nullptr != NextWorkItem);

    return TRUE;
}

void
DelayWorker::QueueWork(_In_ StreamContext* Context)
{
    Lock.Acquire();
    *WorkItemsTail = Context;
    WorkItemsTail = &Context->DelayNext;
    Lock.Release();

    WakeWorkerThread();
}
