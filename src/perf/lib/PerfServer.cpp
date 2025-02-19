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

extern CXPLAT_WORKER_POOL DelayPool;

_Success_(return != false)
template <typename T>
bool
TryGetVariableUnitValue(
    _In_ int argc,
    _In_reads_(argc) _Null_terminated_ char* argv[],
    _In_z_ const char* name,
    _Out_ T * pValue,
    _Out_opt_ bool* isTimed = nullptr
);

/// <summary>
/// Explicit template instantiation
/// </summary>
_Success_(return != false)
template
bool
TryGetVariableUnitValue<uint32_t>(
    _In_ int argc,
    _In_reads_(argc) _Null_terminated_ char* argv[],
    _In_z_ const char* name,
    _Out_ uint32_t * pValue,
    _Out_opt_ bool* isTimed
);

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

    if (TryGetVariableUnitValue(argc, argv, "delay", &DelayMicroseconds, nullptr)) {
        const char* DelayTypeString = nullptr;
        DelayType = SYNTHETIC_DELAY_FIXED;
        Lambda = ((double)1) / DelayMicroseconds;
        MaxFixedDelayUs = static_cast<uint32_t>(4 * (uint64_t)DelayMicroseconds);
        if (MaxFixedDelayUs < 1000) MaxFixedDelayUs = 1000;

        if (TryGetValue(argc, argv, "delayType", &DelayTypeString)) {
#ifndef _KERNEL_MODE
            if (IsValue(DelayTypeString, "variable")) {
                DelayType = SYNTHETIC_DELAY_VARIABLE;
            } else if (!IsValue(DelayTypeString, "fixed")) {
                WriteOutput("Failed to parse DelayType[%s] parameter. Using fixed DelayType.\n", DelayTypeString);
            }
#else
            WriteOutput("Kernel mode supports fixed delay only\n");
#endif // !_KERNEL_MODE
        }

        ProcCount = (uint16_t)CxPlatProcCount();
        DelayWorkers = new (std::nothrow) DelayWorker[ProcCount];
        for (uint16_t i = 0; i < ProcCount; ++i) {
            if (!DelayWorkers[i].Initialize(this, i)) {
                WriteOutput("Failed to init delay workers.\n");
                return QUIC_STATUS_INTERNAL_ERROR;
            }
        }
        DelayPoolUsed = TRUE;
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
        auto Context = StreamContextAllocator.Alloc(this, Unidirectional, false); // TODO - Support buffered IO
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
    uint64_t Start = CxPlatTimeUs64();
    uint64_t Now = Start;
    do {
        //
        // Get the current time and check if time has elapsed
        //
        Now = CxPlatTimeUs64();
    } while (CxPlatTimeDiff64(Start, Now) <= DelayUs);
}

#ifndef _KERNEL_MODE

#include <random>

double
PerfServer::CalculateVariableDelay(double lambda)
{
    lambda = abs(lambda);
    std::mt19937 random_generator(CxPlatTimeUs32());
    std::exponential_distribution<> distribution(lambda);
    return distribution(random_generator);
}

#else

double
PerfServer::CalculateVariableDelay(double lambda)
{
    if (0 == lambda) {
        lambda = 1;
    }
    if (lambda < 0) {
        lambda = -lambda;
    }
    //
    // Only a fixed delay is supported in the Kernel mode
    //
    return 1/lambda;
}

#endif // !_KERNEL_MODE

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

void
PerfServer::SimulateDelay()
{
    if (DelayMicroseconds == 0) {
        //
        // no delay introduced
        //
        return;
    }

    switch (DelayType) {
    case SYNTHETIC_DELAY_VARIABLE:
        IntroduceVariableDelay(DelayMicroseconds);
        break;
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
                if (DelayPoolUsed) {
                    //
                    // Send a delayed response using the background worker thread
                    //
                    uint16_t workerNumber = (uint16_t)CxPlatProcCurrentNumber();
                    CXPLAT_DBG_ASSERT(workerNumber < ProcCount);
                    DelayWorkers[workerNumber].QueueWork(Context, StreamHandle, false);
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
        MsQuic->StreamClose(StreamHandle);
        StreamContextAllocator.Free(Context);
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
        Server->StreamContextAllocator.Free(Stream);
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
        if ((Stream = Server->StreamContextAllocator.Alloc(Server, false, false)) != nullptr) {
            Stream->Entry.Signature = StreamID;
            Stream->IdealSendBuffer = 1; // TCP uses send buffering, so just set to 1.
            This->StreamTable.Insert(&Stream->Entry);
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
            if (Server->DelayPoolUsed) {
                //
                // Send a delayed response using the background worker thread
                //
                uint16_t workerNumber = (uint16_t)CxPlatProcCurrentNumber();
                CXPLAT_DBG_ASSERT(workerNumber < Server->ProcCount);
                Server->DelayWorkers[workerNumber].QueueWork(Stream, Connection, true);
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
            Server->StreamContextAllocator.Free(Stream);
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
                    Server->StreamContextAllocator.Free(Stream);
                }
            }
        }
        SendDataChain = SendDataChain->Next;
        Server->TcpSendDataAllocator.Free(Data);
    }
}

DelayWorker::DelayWorker()
{
    CxPlatEventInitialize(&WakeEvent, FALSE, FALSE);
    CxPlatEventInitialize(&DoneEvent, TRUE, FALSE);
    CxPlatDispatchLockInitialize(&Lock);
}

DelayWorker::~DelayWorker()
{
    CXPLAT_FRE_ASSERT(!WorkItems);
    CXPLAT_FRE_ASSERT(!Initialized);
    CxPlatDispatchLockUninitialize(&Lock);
    CxPlatEventUninitialize(DoneEvent);
    CxPlatEventUninitialize(WakeEvent);
}

bool DelayWorker::Initialize(PerfServer* Server, uint16_t PartitionIndex)
{
    m_Server = Server;
    ExecutionContext.Callback = DelayedWork;
    ExecutionContext.Context = this;
    InterlockedFetchAndSetBoolean(&ExecutionContext.Ready);
    ExecutionContext.NextTimeUs = UINT64_MAX;

    uint16_t ThreadFlags = CXPLAT_THREAD_FLAG_SET_IDEAL_PROC;
    //
    // Not using the high priority flag for delay threads
    //
    CXPLAT_THREAD_CONFIG Config = { ThreadFlags, PartitionIndex, "DelayWorker", WorkerThread, this };
    if (QUIC_FAILED(
        CxPlatThreadCreate(
            &Config,
            &Thread))) {
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
        CxPlatThreadWait(&Thread);
        Initialized = false;
        //
        // delete any pending work items
        //
        CxPlatDispatchLockAcquire(&Lock);
        DelayedWorkContext* CurrentWorkItem = WorkItems;
        while (nullptr != CurrentWorkItem) {
            DelayedWorkContext* NextWorkItem;
            if (WorkItemsTail == &CurrentWorkItem->Next) {
                NextWorkItem = nullptr;
            }
            else {
                NextWorkItem = CurrentWorkItem->Next;
            }
            delete CurrentWorkItem;
            CurrentWorkItem = NextWorkItem;
        }
        WorkItems = nullptr;
        CxPlatDispatchLockRelease(&Lock);
    }
}

void DelayWorker::WakeWorkerThread() {
    if (!InterlockedFetchAndSetBoolean(&ExecutionContext.Ready)) {
            CxPlatEventSet(WakeEvent);
    }
}

CXPLAT_THREAD_CALLBACK(DelayWorker::WorkerThread, Context)
{
    DelayWorker* This = (DelayWorker*)Context;
    CXPLAT_EXECUTION_STATE DummyState = {
        0, 0, 0, UINT32_MAX, 0, CxPlatCurThreadID()
    };
    while (DelayedWork(This, &DummyState)) {
        if (!InterlockedFetchAndClearBoolean(&This->ExecutionContext.Ready)) {
            CxPlatEventWaitForever(This->WakeEvent); // Wait for more work
        }
    }
    CXPLAT_THREAD_RETURN(0);
}

BOOLEAN
DelayWorker::DelayedWork(
    _Inout_ void* Context,
    _Inout_ CXPLAT_EXECUTION_STATE* State
)
{
    DelayWorker* This = (DelayWorker*)Context;
    if (This->Shuttingdown) {
        CxPlatEventSet(This->DoneEvent);
        return FALSE;
    }

    DelayedWorkContext* WorkItem = nullptr;
    CxPlatDispatchLockAcquire(&This->Lock);
    if (This->WorkItems) {
        WorkItem = This->WorkItems;
        This->WorkItems = WorkItem->Next;
        if (This->WorkItemsTail == &WorkItem->Next) {
            This->WorkItemsTail = &This->WorkItems;
        }
        WorkItem->Next = nullptr;
    }
    CxPlatDispatchLockRelease(&This->Lock);

    if (nullptr != WorkItem) {
        This->m_Server->SimulateDelay();
        This->m_Server->SendResponse(WorkItem->Context, WorkItem->Handle, WorkItem->IsTcp);
        delete WorkItem;
        InterlockedFetchAndSetBoolean(&This->ExecutionContext.Ready); // We just did work, let's keep this thread hot.
        State->NoWorkCount = 0;
    }

    return TRUE;
}

bool DelayWorker::QueueWork(
    _In_ StreamContext* Context,
    _In_ void* Handle,
    _In_ bool IsTcp)
{
    DelayedWorkContext* Work = new (std::nothrow) DelayedWorkContext();
    if (nullptr == Work) {
        return false;
    }

    Work->Context = Context;
    Work->Handle = Handle;
    Work->IsTcp = IsTcp;

    CxPlatDispatchLockAcquire(&Lock);
    *WorkItemsTail = Work;
    WorkItemsTail = &Work->Next;
    WakeWorkerThread();
    CxPlatDispatchLockRelease(&Lock);
    return true;
}
