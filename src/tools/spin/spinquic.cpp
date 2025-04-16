/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.

--*/

#include <time.h>
#include <stdio.h>

#include <vector>
#include <map>
#include <mutex>
#include <algorithm>

#define QUIC_TEST_APIS 1 // Needed for self signed cert API
#define QUIC_API_ENABLE_INSECURE_FEATURES 1 // Needed for disabling 1-RTT encryption
#define QUIC_API_ENABLE_PREVIEW_FEATURES // Needed for VN
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include "msquichelper.h"

#define ASSERT_ON_FAILURE(x) \
    do { \
        QUIC_STATUS _STATUS; \
        CXPLAT_FRE_ASSERT(QUIC_SUCCEEDED((_STATUS = x))); \
    } while (0)
#define ASSERT_ON_NOT(x) CXPLAT_FRE_ASSERT(x)

QUIC_EXECUTION_CONFIG* ExecConfig = nullptr;
uint32_t ExecConfigSize = 0;

class FuzzingData {
    const uint8_t* data;
    size_t size;
    std::vector<size_t> EachSize;
    std::mutex mux;
    // TODO: support bit level pointers
    std::vector<size_t> Ptrs;
    std::vector<size_t> NumIterated;
    bool Cyclic;

    bool CheckBoundary(uint16_t ThreadId, size_t Adding) {
        // TODO: efficient cyclic access
        if (EachSize[ThreadId] < Ptrs[ThreadId] + Adding) {
            if (!Cyclic) {
                return false;
            }
            Ptrs[ThreadId] = 0;
            NumIterated[ThreadId]++;
        }
        return true;
    }
public:
    // 128 for main data, 20 for callback's issue workaround
    static const size_t MinDataSize = 148;
    static const size_t UtilityDataSize = 20;
    // hard code for determinisity
    static const uint16_t NumSpinThread = 2;

    FuzzingData() : data(nullptr), size(0), Ptrs({}), NumIterated({}), Cyclic(true) {}
    FuzzingData(const uint8_t* data, size_t size) : data(data), size(size - UtilityDataSize), Ptrs({}), NumIterated({}), Cyclic(true) {}
    bool Initialize() {
        // TODO: support non divisible size
        if (size % (size_t)NumSpinThread != 0 || size < (size_t)NumSpinThread * 8) {
            return false;
        }

        EachSize.resize(NumSpinThread + 1);
        std::fill(EachSize.begin(), EachSize.end(), size / (size_t)NumSpinThread);
        EachSize.back() = UtilityDataSize;
        Ptrs.resize(NumSpinThread + 1);
        std::fill(Ptrs.begin(), Ptrs.end(), 0);
        NumIterated.resize(NumSpinThread + 1);
        std::fill(NumIterated.begin(), NumIterated.end(), 0);
        return true;
    }
    bool TryGetByte(uint8_t* Val, uint16_t ThreadId = 0) {
        if (!CheckBoundary(ThreadId, 1)) {
            return false;
        }
        *Val = data[Ptrs[ThreadId]++ + EachSize[ThreadId] * ThreadId];
        return true;
    }
    bool TryGetBool(bool* Flag, uint16_t ThreadId = 0) {
        uint8_t Val = 0;
        if (TryGetByte(&Val, ThreadId)) {
            *Flag = (bool)(Val & 0b1);
            return true;
        }
        return false;
    }
    template<typename T>
    bool TryGetRandom(T UpperBound, T* Val, uint16_t ThreadId = 0) {
        if (ThreadId == NumSpinThread) {
            // utility area access from Connection/Stream callbacks
            mux.lock();
        }
        int type_size = sizeof(T);
        if (!CheckBoundary(ThreadId, type_size)) {
            return false;
        }
        memcpy(Val, &data[Ptrs[ThreadId]] + EachSize[ThreadId] * ThreadId, type_size);
        *Val = (T)(*Val % UpperBound);
        Ptrs[ThreadId] += type_size;
        if (ThreadId == NumSpinThread) {
            mux.unlock();
        }
        return true;
    }
    size_t GetIterateCount(uint16_t ThreadId) {
        return NumIterated[ThreadId];
    }
};

static FuzzingData* FuzzData = nullptr;

template<typename T>
T GetRandom(T UpperBound, uint16_t ThreadID = UINT16_MAX) {
    if (!FuzzData || ThreadID == UINT16_MAX) {
        return (T)(rand() % (int)UpperBound);
    }
    uint64_t out = 0;

    if ((uint64_t)UpperBound <= 0xff) {
        (void)FuzzData->TryGetRandom((uint8_t)UpperBound, (uint8_t*)&out, ThreadID);
    } else if ((uint64_t)UpperBound <= 0xffff) {
        (void)FuzzData->TryGetRandom((uint16_t)UpperBound, (uint16_t*)&out, ThreadID);
    } else if ((uint64_t)UpperBound <= 0xffffffff) {
        (void)FuzzData->TryGetRandom((uint32_t)UpperBound, (uint32_t*)&out, ThreadID);
    } else {
        (void)FuzzData->TryGetRandom((uint64_t)UpperBound, &out, ThreadID);
    }
    return (T)out;
}
#define GetRandom(UpperBound) GetRandom(UpperBound, ThreadID)

template<typename T>
T& GetRandomFromVector(std::vector<T> &vec, uint16_t ThreadID) {
    return vec.at(GetRandom(vec.size()));
}
#define GetRandomFromVector(Vec) GetRandomFromVector(Vec, ThreadID)

template<typename T>
class LockableVector : public std::vector<T>, public std::mutex {
    uint16_t ThreadID = UINT16_MAX;
public:
    T TryGetRandom(bool Erase = false) {
        std::lock_guard<std::mutex> Lock(*this);
        if (this->size() > 0) {
            auto idx = GetRandom(this->size());
            auto obj = this->at(idx);
            if (Erase) {
                this->erase(this->begin() + idx);
            }
            return obj;
        }
        return nullptr;
    }
    void SetThreadID(uint16_t threadID) {
        ThreadID = threadID;
    }
};

//
// The amount of extra time (in milliseconds) to give the watchdog before
// actually firing.
//
#define WATCHDOG_WIGGLE_ROOM 10000

class SpinQuicWatchdog {
    CXPLAT_THREAD WatchdogThread;
    CXPLAT_EVENT ShutdownEvent;
    uint32_t TimeoutMs;
    CXPLAT_THREAD_ID OriginThread;
    static
    CXPLAT_THREAD_CALLBACK(WatchdogThreadCallback, Context) {
        auto This = (SpinQuicWatchdog*)Context;
        if (!CxPlatEventWaitWithTimeout(This->ShutdownEvent, This->TimeoutMs)) {
            printf("Watchdog timeout fired while waiting on thread 0x%x!\n", (int)This->OriginThread);
            CXPLAT_FRE_ASSERTMSG(FALSE, "Watchdog timeout fired!");
        }
        CXPLAT_THREAD_RETURN(0);
    }
public:
    SpinQuicWatchdog(uint32_t WatchdogTimeoutMs) :
        TimeoutMs(WatchdogTimeoutMs), OriginThread(CxPlatCurThreadID()) {
        CxPlatEventInitialize(&ShutdownEvent, TRUE, FALSE);
        CXPLAT_THREAD_CONFIG Config = { 0 };
        Config.Name = "spin_watchdog";
        Config.Callback = WatchdogThreadCallback;
        Config.Context = this;
        ASSERT_ON_FAILURE(CxPlatThreadCreate(&Config, &WatchdogThread));
    }
    ~SpinQuicWatchdog() {
        CxPlatEventSet(ShutdownEvent);
        CxPlatThreadWait(&WatchdogThread);
        CxPlatThreadDelete(&WatchdogThread);
        CxPlatEventUninitialize(ShutdownEvent);
    }
};

static QUIC_API_TABLE MsQuic;
// This locks MsQuicOpen2 in RunThread when statically linked with libmsquic
CXPLAT_LOCK RunThreadLock;

const uint32_t MaxBufferSizes[] = { 0, 1, 2, 32, 50, 256, 500, 1000, 1024, 1400, 5000, 10000, 64000, 10000000 };
static const size_t BufferCount = ARRAYSIZE(MaxBufferSizes);

struct SpinQuicGlobals {
    uint64_t StartTimeMs;
    const QUIC_API_TABLE* MsQuic {nullptr};
    HQUIC Registration {nullptr};
    HQUIC ServerConfiguration {nullptr};
    std::vector<HQUIC> ClientConfigurations;
    QUIC_BUFFER* Alpns {nullptr};
    uint32_t AlpnCount {0};
    const size_t SendBufferSize { MaxBufferSizes[BufferCount - 1] + UINT8_MAX };
    uint8_t* SendBuffer;
    SpinQuicGlobals() {
        SendBuffer = new uint8_t[SendBufferSize];
        for (size_t i = 0; i < SendBufferSize; i++) {
            SendBuffer[i] = (uint8_t)i;
        }
    }
    ~SpinQuicGlobals() {
        while (ClientConfigurations.size() > 0) {
            auto Configuration = ClientConfigurations.back();
            ClientConfigurations.pop_back();
            MsQuic->ConfigurationClose(Configuration);
        }
        if (Alpns) {
            for (uint32_t j = 0; j < AlpnCount; j++) {
                free(Alpns[j].Buffer);
            }
            free(Alpns);
        }
        if (Registration) {
            MsQuic->RegistrationClose(Registration);
        }
        if (MsQuic) {
#ifndef FUZZING
            DumpMsQuicPerfCounters(MsQuic);
#endif
            MsQuicClose(MsQuic);
        }
        delete [] SendBuffer;
    }
};

typedef SpinQuicGlobals Gbs;

typedef enum {
    SpinQuicAPICallConnectionOpen = 0,
    SpinQuicAPICallConnectionStart,
    SpinQuicAPICallConnectionShutdown,
    SpinQuicAPICallConnectionClose,
    SpinQuicAPICallStreamOpen,
    SpinQuicAPICallStreamStart,
    SpinQuicAPICallStreamSend,
    SpinQuicAPICallStreamShutdown,
    SpinQuicAPICallStreamClose,
    SpinQuicAPICallSetParamConnection,
    SpinQuicAPICallGetParamConnection,
    SpinQuicAPICallSetParamStream,
    SpinQuicAPICallGetParamStream,
    SpinQuicAPICallDatagramSend,
    SpinQuicAPICallCompleteTicketValidation,
    SpinQuicAPICallCompleteCertificateValidation,
    SpinQuicAPICallStreamReceiveSetEnabled,
    SpinQuicAPICallStreamReceiveComplete,
    SpinQuicAPICallCount    // Always the last element
} SpinQuicAPICall;

struct SpinQuicStream {
    struct SpinQuicConnection& Connection;
    HQUIC Handle;
    uint8_t SendOffset {0};
    bool Deleting {false};
    uint64_t PendingRecvLength {UINT64_MAX}; // UINT64_MAX means no pending receive
    SpinQuicStream(SpinQuicConnection& Connection, HQUIC Handle = nullptr) :
        Connection(Connection), Handle(Handle) {}
    ~SpinQuicStream() { Deleting = true; MsQuic.StreamClose(Handle); }
    static SpinQuicStream* Get(HQUIC Stream) {
        return (SpinQuicStream*)MsQuic.GetContext(Stream);
    }
};

struct SpinQuicConnection {
public:
    std::mutex Lock;
    HQUIC Connection = nullptr;
    std::vector<HQUIC> Streams;
    bool IsShutdownComplete = false;
    bool IsDeleting = false;
    uint16_t ThreadID;
    static SpinQuicConnection* Get(HQUIC Connection) {
        return (SpinQuicConnection*)MsQuic.GetContext(Connection);
    }
    SpinQuicConnection(uint16_t threadID) : ThreadID(threadID) { }
    SpinQuicConnection(HQUIC Connection, uint16_t threadID) : ThreadID(threadID) {
        Set(Connection);
    }
    ~SpinQuicConnection() {
        bool CloseStreamsNow;
        {
            std::lock_guard<std::mutex> LockScope(Lock);
            CloseStreamsNow = IsShutdownComplete; // Already shutdown complete, so clean up now.
            IsDeleting = true;
        }
        if (CloseStreamsNow) CloseStreams();
        MsQuic.ConnectionClose(Connection);
    }
    void Set(HQUIC _Connection) {
        Connection = _Connection;
        MsQuic.SetContext(Connection, this);
    }
    void OnShutdownComplete() {
        bool CloseStreamsNow;
        {
            std::lock_guard<std::mutex> LockScope(Lock);
            CloseStreamsNow = IsDeleting; // This is happening as a result of deleting, so clean up now.
            IsShutdownComplete = true;
        }
        if (CloseStreamsNow) CloseStreams();
    }
    void CloseStreams() {
        std::vector<HQUIC> StreamsCopy;
        {
            std::lock_guard<std::mutex> LockScope(Lock);
            StreamsCopy = Streams;
            Streams.clear();
        }
        while (StreamsCopy.size() > 0) {
            HQUIC Stream = StreamsCopy.back();
            StreamsCopy.pop_back();
            delete SpinQuicStream::Get(Stream);
        }
    }
    void AddStream(HQUIC Stream) {
        std::lock_guard<std::mutex> LockScope(Lock);
        Streams.push_back(Stream);
    }
    // Requires Lock to be held
    HQUIC TryGetStream(bool Remove = false) {
        if (Streams.size() != 0) {
            auto idx = GetRandom(Streams.size());
            HQUIC Stream = Streams[idx];
            if (Remove) {
                Streams.erase(Streams.begin() + idx);
            }
            return Stream;
        }
        return nullptr;
    }
};

static struct {
    bool RunServer {false};
    bool RunClient {false};
    uint32_t SessionCount {4};
    uint64_t RunTimeMs;
    uint64_t MaxOperationCount;
    uint64_t MaxFuzzIterationCount;
    const char* AlpnPrefix;
    std::vector<uint16_t> Ports;
    const char* ServerName;
    uint8_t LossPercent;
    int32_t AllocFailDenominator;
    uint32_t RepeatCount;
} SpinSettings;

void SpinQuicGetRandomParam(HQUIC Handle, uint16_t ThreadID);
void SpinQuicSetRandomStreamParam(HQUIC Stream, uint16_t ThreadID);

QUIC_STATUS QUIC_API SpinQuicHandleStreamEvent(HQUIC Stream, void* , QUIC_STREAM_EVENT *Event)
{
    auto ctx = SpinQuicStream::Get(Stream);
    auto ThreadID = ctx->Connection.ThreadID;

    if (GetRandom(5) == 0) {
        SpinQuicGetRandomParam(Stream, ThreadID);
    }

    if (GetRandom(10) == 0) {
        SpinQuicSetRandomStreamParam(Stream, ThreadID);
    }

    if (!ctx->Deleting && GetRandom(20) == 0) {
        MsQuic.StreamShutdown(Stream, (QUIC_STREAM_SHUTDOWN_FLAGS)GetRandom(16), 0);
        goto Exit;
    }

    switch (Event->Type) {
    case QUIC_STREAM_EVENT_PEER_SEND_SHUTDOWN:
        MsQuic.StreamShutdown(Stream, (QUIC_STREAM_SHUTDOWN_FLAGS)GetRandom(16), 0);
        break;
    case QUIC_STREAM_EVENT_PEER_SEND_ABORTED: {
        std::lock_guard<std::mutex> Lock(ctx->Connection.Lock);
        ctx->PendingRecvLength = UINT64_MAX;
        break;
    }
    case QUIC_STREAM_EVENT_RECEIVE: {
        if (Event->RECEIVE.TotalBufferLength == 0) {
            ctx->PendingRecvLength = UINT64_MAX; // TODO - Add more complex handling
            break;
        }
        auto Offset = Event->RECEIVE.AbsoluteOffset;
        for (uint32_t i = 0; i < Event->RECEIVE.BufferCount; ++i) {
            for (uint32_t j = 0; j < Event->RECEIVE.Buffers[i].Length; ++j) {
                if (Event->RECEIVE.Buffers[i].Buffer[j] != (uint8_t)(Offset + j)) {
                    CXPLAT_FRE_ASSERT(FALSE); // Value is corrupt!
                }
            }
            Offset += Event->RECEIVE.Buffers[i].Length;
        }
        int Random = GetRandom(5);
        std::lock_guard<std::mutex> Lock(ctx->Connection.Lock);
        CXPLAT_DBG_ASSERT(ctx->PendingRecvLength == UINT64_MAX);
        if (Random == 0) {
            ctx->PendingRecvLength = Event->RECEIVE.TotalBufferLength;
            return QUIC_STATUS_PENDING; // Pend the receive, to be completed later.
        } else if (Random == 1 && Event->RECEIVE.TotalBufferLength > 0) {
            Event->RECEIVE.TotalBufferLength = GetRandom(Event->RECEIVE.TotalBufferLength + 1); // Partially (or fully) consume the data.
            if (GetRandom(10) == 0) {
                return QUIC_STATUS_CONTINUE; // Don't pause receive callbacks.
            }
        }
        break;
    }
    default:
        break;
    }

Exit:
    if (Event->Type == QUIC_STREAM_EVENT_SEND_COMPLETE) {
        delete (QUIC_BUFFER*)Event->SEND_COMPLETE.ClientContext;
    }

    return QUIC_STATUS_SUCCESS;
}

QUIC_STATUS QUIC_API SpinQuicHandleConnectionEvent(HQUIC Connection, void* , QUIC_CONNECTION_EVENT *Event)
{
    auto ctx = SpinQuicConnection::Get(Connection);
    auto ThreadID = ctx->ThreadID;

    switch (Event->Type) {
    case QUIC_CONNECTION_EVENT_CONNECTED: {
        int Selector = GetRandom(3);
        uint16_t DataLength = 0;
        uint8_t* Data = nullptr;
        if (Selector == 1) {
            //
            // Send ticket with some data
            //
            DataLength = (uint16_t)(GetRandom(999) + 1);
        } else if (Selector == 2) {
            //
            // Send ticket with too much data
            //
            DataLength = QUIC_MAX_RESUMPTION_APP_DATA_LENGTH + 1;
        } else {
            //
            // Send ticket with no app data (no-op)
            //
        }
        if (DataLength) {
            Data = (uint8_t*)malloc(DataLength);
            if (Data == nullptr) {
                DataLength = 0;
            }
        }
        QUIC_SEND_RESUMPTION_FLAGS Flags = (GetRandom(2) == 0) ? QUIC_SEND_RESUMPTION_FLAG_NONE : QUIC_SEND_RESUMPTION_FLAG_FINAL;
        MsQuic.ConnectionSendResumptionTicket(Connection, Flags, DataLength, Data);
        free(Data);
        break;
    }
    case QUIC_CONNECTION_EVENT_SHUTDOWN_COMPLETE:
        SpinQuicConnection::Get(Connection)->OnShutdownComplete();
        break;
    case QUIC_CONNECTION_EVENT_PEER_STREAM_STARTED: {
        if (GetRandom(10) == 0) {
            return QUIC_STATUS_NOT_SUPPORTED;
        }
        if (GetRandom(10) == 0) {
            MsQuic.StreamClose(Event->PEER_STREAM_STARTED.Stream);
            return QUIC_STATUS_SUCCESS;
        }
        if (GetRandom(2) == 0) {
            Event->PEER_STREAM_STARTED.Flags |= QUIC_STREAM_OPEN_FLAG_DELAY_ID_FC_UPDATES;
        }
        auto StreamCtx = new SpinQuicStream(*ctx, Event->PEER_STREAM_STARTED.Stream);
        MsQuic.SetCallbackHandler(Event->PEER_STREAM_STARTED.Stream, (void *)SpinQuicHandleStreamEvent, StreamCtx);
        ctx->AddStream(Event->PEER_STREAM_STARTED.Stream);
        break;
    }
    case QUIC_CONNECTION_EVENT_DATAGRAM_SEND_STATE_CHANGED:
        if (QUIC_DATAGRAM_SEND_STATE_IS_FINAL(Event->DATAGRAM_SEND_STATE_CHANGED.State)) {
            delete (QUIC_BUFFER*)Event->DATAGRAM_SEND_STATE_CHANGED.ClientContext;
        }
        break;
    default:
        break;
    }

    return QUIC_STATUS_SUCCESS;
}

struct ListenerContext {
    HQUIC ServerConfiguration;
    LockableVector<HQUIC>* Connections;
    uint16_t ThreadID;
};

QUIC_STATUS QUIC_API SpinQuicServerHandleListenerEvent(HQUIC /* Listener */, void* Context , QUIC_LISTENER_EVENT* Event)
{
    HQUIC ServerConfiguration = ((ListenerContext*)Context)->ServerConfiguration;
    auto& Connections = *((ListenerContext*)Context)->Connections;
    uint16_t ThreadID = ((ListenerContext*)Context)->ThreadID;

    switch (Event->Type) {
    case QUIC_LISTENER_EVENT_NEW_CONNECTION: {
        if (!GetRandom(20)) {
            return QUIC_STATUS_CONNECTION_REFUSED;
        }
        MsQuic.SetCallbackHandler(Event->NEW_CONNECTION.Connection, (void*)SpinQuicHandleConnectionEvent, &((ListenerContext*)Context)->ThreadID);
        QUIC_STATUS Status =
            MsQuic.ConnectionSetConfiguration(
                Event->NEW_CONNECTION.Connection,
                ServerConfiguration);
        if (QUIC_FAILED(Status)) {
            return Status;
        }
        auto ctx = new SpinQuicConnection(Event->NEW_CONNECTION.Connection, ThreadID);
        if (ctx == nullptr) {
            return QUIC_STATUS_OUT_OF_MEMORY;
        }
        {
            std::lock_guard<std::mutex> Lock(Connections);
            Connections.push_back(Event->NEW_CONNECTION.Connection);
        }
        break;
    }
    default:
        break;
    }

    return QUIC_STATUS_SUCCESS;
}

struct SetParamHelper {
    union {
        uint64_t u64;
        uint32_t u32;
        uint16_t u16;
        uint8_t  u8;
        const void *ptr;
    } Param;
    bool IsPtr;
    uint32_t Size = 0;
    int Type;
    SetParamHelper() {
        Param.u64 = 0;
        IsPtr = false;
        Size = 0;
        Type = -1;
    }
    void SetPtr(uint32_t _Type, const void* _Ptr, uint32_t _Size) {
        Type = _Type; Param.ptr = _Ptr; Size = _Size; IsPtr = true;
    }
    void SetUint8(uint32_t _Type, uint8_t Value) {
        Type = _Type; Param.u8 = Value; Size = sizeof(Value);
    }
    void SetUint16(uint32_t _Type, uint16_t Value) {
        Type = _Type; Param.u16 = Value; Size = sizeof(Value);
    }
    void SetUint32(uint32_t _Type, uint32_t Value) {
        Type = _Type; Param.u32= Value; Size = sizeof(Value);
    }
    void SetUint64(uint32_t _Type, uint64_t Value) {
        Type = _Type; Param.u64 = Value; Size = sizeof(Value);
    }
    void Apply(HQUIC Handle) {
        if (Type != -1) {
            MsQuic.SetParam(Handle, Type, Size, IsPtr ? Param.ptr : &Param);
        }
    }
};

void SpinQuicRandomizeSettings(QUIC_SETTINGS& Settings, uint16_t ThreadID)
{
    switch (GetRandom(38)) {
    case 0:
        //Settings.MaxBytesPerKey = GetRandom(UINT64_MAX);
        //Settings.IsSet.MaxBytesPerKey = TRUE;
        break;
    case 1:
        //Settings.HandshakeIdleTimeoutMs = GetRandom(UINT64_MAX);
        //Settings.IsSet.HandshakeIdleTimeoutMs = TRUE;
        break;
    case 2:
        //Settings.IdleTimeoutMs = GetRandom(UINT64_MAX);
        //Settings.IsSet.IdleTimeoutMs = TRUE;
        break;
    case 3:
        //Settings.MtuDiscoverySearchCompleteTimeoutUs = GetRandom(UINT64_MAX);
        //Settings.IsSet.MtuDiscoverySearchCompleteTimeoutUs = TRUE;
        break;
    case 4:
        //Settings.TlsClientMaxSendBuffer = GetRandom(UINT32_MAX);
        //Settings.IsSet.TlsClientMaxSendBuffer = TRUE;
        break;
    case 5:
        //Settings.TlsServerMaxSendBuffer = GetRandom(UINT32_MAX);
        //Settings.IsSet.TlsServerMaxSendBuffer = TRUE;
        break;
    case 6:
        //Settings.StreamRecvWindowDefault = GetRandom(UINT32_MAX);
        //Settings.IsSet.StreamRecvWindowDefault = TRUE;
        break;
    case 7:
        //Settings.StreamRecvBufferDefault = GetRandom(UINT32_MAX);
        //Settings.IsSet.StreamRecvBufferDefault = TRUE;
        break;
    case 8:
        //Settings.ConnFlowControlWindow = GetRandom(UINT32_MAX);
        //Settings.IsSet.ConnFlowControlWindow = TRUE;
        break;
    case 9:
        //Settings.MaxWorkerQueueDelayUs = GetRandom(UINT32_MAX);
        //Settings.IsSet.MaxWorkerQueueDelayUs = TRUE;
        break;
    case 10:
        //Settings.MaxStatelessOperations = GetRandom(UINT32_MAX);
        //Settings.IsSet.MaxStatelessOperations = TRUE;
        break;
    case 11:
        //Settings.InitialWindowPackets = GetRandom(UINT32_MAX);
        //Settings.IsSet.InitialWindowPackets = TRUE;
        break;
    case 12:
        //Settings.SendIdleTimeoutMs = GetRandom(UINT32_MAX);
        //Settings.IsSet.SendIdleTimeoutMs = TRUE;
        break;
    case 13:
        //Settings.InitialRttMs = GetRandom(UINT32_MAX);
        //Settings.IsSet.InitialRttMs = TRUE;
        break;
    case 14:
        //Settings.MaxAckDelayMs = GetRandom(UINT32_MAX);
        //Settings.IsSet.MaxAckDelayMs = TRUE;
        break;
    case 15:
        //Settings.DisconnectTimeoutMs = GetRandom(UINT32_MAX);
        //Settings.IsSet.DisconnectTimeoutMs = TRUE;
        break;
    case 16:
        //Settings.KeepAliveIntervalMs = GetRandom(UINT32_MAX);
        //Settings.IsSet.KeepAliveIntervalMs = TRUE;
        break;
    case 17:
        Settings.CongestionControlAlgorithm = GetRandom((uint16_t)QUIC_CONGESTION_CONTROL_ALGORITHM_MAX);
        Settings.IsSet.CongestionControlAlgorithm = TRUE;
        break;
    case 18:
        //Settings.PeerBidiStreamCount = GetRandom(UINT16_MAX);
        //Settings.IsSet.PeerBidiStreamCount = TRUE;
        break;
    case 19:
        //Settings.PeerUnidiStreamCount = GetRandom(UINT16_MAX);
        //Settings.IsSet.PeerUnidiStreamCount = TRUE;
        break;
    case 20:
        //Settings.MaxBindingStatelessOperations = GetRandom(UINT16_MAX);
        //Settings.IsSet.MaxBindingStatelessOperations = TRUE;
        break;
    case 21:
        //Settings.StatelessOperationExpirationMs = GetRandom(UINT16_MAX);
        //Settings.IsSet.StatelessOperationExpirationMs = TRUE;
        break;
    case 22:
        //Settings.MinimumMtu = GetRandom(UINT16_MAX);
        //Settings.IsSet.MinimumMtu = TRUE;
        break;
    case 23:
        //Settings.MaximumMtu = GetRandom(UINT16_MAX);
        //Settings.IsSet.MaximumMtu = TRUE;
        break;
    case 24:
        //Settings.SendBufferingEnabled = GetRandom((uint8_t)1);
        //Settings.IsSet.SendBufferingEnabled = TRUE;
        break;
    case 25:
        Settings.PacingEnabled = GetRandom((uint8_t)1);
        Settings.IsSet.PacingEnabled = TRUE;
        break;
    case 26:
        Settings.MigrationEnabled = GetRandom((uint8_t)1);
        Settings.IsSet.MigrationEnabled = TRUE;
        break;
    case 27:
        Settings.DatagramReceiveEnabled = GetRandom((uint8_t)1);
        Settings.IsSet.DatagramReceiveEnabled = TRUE;
        break;
    case 28:
        Settings.ServerResumptionLevel = GetRandom((uint8_t)3);
        Settings.IsSet.ServerResumptionLevel = TRUE;
        break;
    case 29:
        Settings.GreaseQuicBitEnabled = GetRandom((uint8_t)1);
        Settings.IsSet.GreaseQuicBitEnabled = TRUE;
        break;
    case 30:
        Settings.EcnEnabled = GetRandom((uint8_t)1);
        Settings.IsSet.EcnEnabled = TRUE;
        break;
    case 31:
        //Settings.MaxOperationsPerDrain = GetRandom(UINT8_MAX);
        //Settings.IsSet.MaxOperationsPerDrain = TRUE;
        break;
    case 32:
        //Settings.MtuDiscoveryMissingProbeCount = GetRandom(UINT8_MAX);
        //Settings.IsSet.MtuDiscoveryMissingProbeCount = TRUE;
        break;
    case 33:
        //Settings.DestCidUpdateIdleTimeoutMs = GetRandom(UINT32_MAX);
        //Settings.IsSet.DestCidUpdateIdleTimeoutMs = TRUE;
        break;
    case 34:
        Settings.HyStartEnabled = GetRandom((uint8_t)1);
        Settings.IsSet.HyStartEnabled = TRUE;
        break;
    case 35:
        Settings.EncryptionOffloadAllowed = GetRandom((uint8_t)1);
        Settings.IsSet.EncryptionOffloadAllowed = TRUE;
        break;
    case 36:
        Settings.ReliableResetEnabled = GetRandom((uint8_t)1);
        Settings.IsSet.ReliableResetEnabled = TRUE;
        break;
    case 37:
        Settings.OneWayDelayEnabled = GetRandom((uint8_t)1);
        Settings.IsSet.OneWayDelayEnabled = TRUE;
        break;
    default:
        break;
    }
}

void SpinQuicSetRandomConnectionParam(HQUIC Connection, uint16_t ThreadID)
{
    uint8_t RandomBuffer[8];
    QUIC_SETTINGS Settings = {0};
    SetParamHelper Helper;

    switch (0x05000000 | (GetRandom(24))) {
    case QUIC_PARAM_CONN_QUIC_VERSION:                              // uint32_t
        // QUIC_VERSION is get-only
        break;
    case QUIC_PARAM_CONN_LOCAL_ADDRESS:                             // QUIC_ADDR
        break; // TODO - Add support here
    case QUIC_PARAM_CONN_REMOTE_ADDRESS:                            // QUIC_ADDR
        break; // Get Only
    case QUIC_PARAM_CONN_IDEAL_PROCESSOR:                           // uint16_t
        break; // Get Only
    case QUIC_PARAM_CONN_SETTINGS:                                  // QUIC_SETTINGS
        SpinQuicRandomizeSettings(Settings, ThreadID);
        Helper.SetPtr(QUIC_PARAM_CONN_SETTINGS, &Settings, sizeof(Settings));
        break;
    case QUIC_PARAM_CONN_STATISTICS:                                // QUIC_STATISTICS
        break; // Get Only
    case QUIC_PARAM_CONN_STATISTICS_PLAT:                           // QUIC_STATISTICS
        break; // Get Only
    case QUIC_PARAM_CONN_SHARE_UDP_BINDING:                         // uint8_t (BOOLEAN)
        Helper.SetUint8(QUIC_PARAM_CONN_SHARE_UDP_BINDING, (uint8_t)GetRandom(2));
        break;
    case QUIC_PARAM_CONN_LOCAL_BIDI_STREAM_COUNT:                   // uint16_t
        break; // Get Only
    case QUIC_PARAM_CONN_LOCAL_UNIDI_STREAM_COUNT:                  // uint16_t
        break; // Get Only
    case QUIC_PARAM_CONN_MAX_STREAM_IDS:                            // uint64_t[4]
        break; // Get Only
    case QUIC_PARAM_CONN_CLOSE_REASON_PHRASE:                       // char[]
        Helper.SetPtr(QUIC_PARAM_CONN_CLOSE_REASON_PHRASE, "ABCDEFGHI\x00\x00\x00\x00\x00", 10);
        break;
    case QUIC_PARAM_CONN_STREAM_SCHEDULING_SCHEME:                  // QUIC_STREAM_SCHEDULING_SCHEME
        Helper.SetUint32(QUIC_PARAM_CONN_STREAM_SCHEDULING_SCHEME, GetRandom(QUIC_STREAM_SCHEDULING_SCHEME_COUNT));
        break;
    case QUIC_PARAM_CONN_DATAGRAM_RECEIVE_ENABLED:                  // uint8_t (BOOLEAN)
        Helper.SetUint8(QUIC_PARAM_CONN_DATAGRAM_RECEIVE_ENABLED, (uint8_t)GetRandom(2));
        break;
    case QUIC_PARAM_CONN_DATAGRAM_SEND_ENABLED:                     // uint8_t (BOOLEAN)
        break; // Get Only
    //case QUIC_PARAM_CONN_DISABLE_1RTT_ENCRYPTION:                   // uint8_t (BOOLEAN)
    //    Helper.SetUint8(QUIC_PARAM_CONN_DISABLE_1RTT_ENCRYPTION, (uint8_t)GetRandom(2));
    //    break;
    case QUIC_PARAM_CONN_RESUMPTION_TICKET:                         // uint8_t[]
        // TODO
        break;
    case QUIC_PARAM_CONN_PEER_CERTIFICATE_VALID:                    // uint8_t (BOOLEAN)
        Helper.SetUint8(QUIC_PARAM_CONN_PEER_CERTIFICATE_VALID, (uint8_t)GetRandom(2));
        break;
    case QUIC_PARAM_CONN_LOCAL_INTERFACE:                           // uint32_t
        // TODO
        break;
    case QUIC_PARAM_CONN_TLS_SECRETS:                               // QUIC_TLS_SECRETS
        // TODO
        break;
    case QUIC_PARAM_CONN_VERSION_SETTINGS:                          // uint32_t[]
        break; // Get-only
    case QUIC_PARAM_CONN_CIBIR_ID:                       // bytes[]
        if (FuzzData) {
            // assume 8 byte buffer for now
            uint64_t Buffer = GetRandom(UINT64_MAX);
            memcpy(RandomBuffer, &Buffer, sizeof(RandomBuffer));
        } else {
            CxPlatRandom(sizeof(RandomBuffer), RandomBuffer);
        }
        Helper.SetPtr(QUIC_PARAM_CONN_CIBIR_ID, RandomBuffer, 1 + (uint8_t)GetRandom(sizeof(RandomBuffer)));
        break;
    case QUIC_PARAM_CONN_STATISTICS_V2:                             // QUIC_STATISTICS_V2
        break; // Get Only
    case QUIC_PARAM_CONN_STATISTICS_V2_PLAT:                        // QUIC_STATISTICS_V2
        break; // Get Only
    default:
        break;
    }

    Helper.Apply(Connection);
}

void SpinQuicSetRandomStreamParam(HQUIC Stream, uint16_t ThreadID)
{
    SetParamHelper Helper;

    switch (0x08000000 | (GetRandom(6))) {
    case QUIC_PARAM_STREAM_ID:                                      // QUIC_UINT62
        break; // Get Only
    case QUIC_PARAM_STREAM_0RTT_LENGTH:                             // QUIC_ADDR
        break; // Get Only
    case QUIC_PARAM_STREAM_IDEAL_SEND_BUFFER_SIZE:                  // QUIC_ADDR
        break; // Get Only
    case QUIC_PARAM_STREAM_PRIORITY:                                // uint16_t
        Helper.SetUint16(QUIC_PARAM_STREAM_PRIORITY, (uint16_t)GetRandom(UINT16_MAX));
        break;
    case QUIC_PARAM_STREAM_STATISTICS:
        break; // Get Only
    case QUIC_PARAM_STREAM_RELIABLE_OFFSET:
        Helper.SetUint64(QUIC_PARAM_STREAM_RELIABLE_OFFSET, (uint64_t)GetRandom(UINT64_MAX));
    default:
        break;
    }

    Helper.Apply(Stream);
}

const uint32_t ParamCounts[] = {
    QUIC_PARAM_GLOBAL_LIBRARY_GIT_HASH + 1,
    0,
    QUIC_PARAM_CONFIGURATION_SCHANNEL_CREDENTIAL_ATTRIBUTE_W + 1,
    QUIC_PARAM_LISTENER_CIBIR_ID + 1,
    QUIC_PARAM_CONN_STATISTICS_V2_PLAT + 1,
    QUIC_PARAM_TLS_NEGOTIATED_ALPN + 1,
#ifdef WIN32 // Schannel specific TLS parameters
    QUIC_PARAM_TLS_SCHANNEL_SECURITY_CONTEXT_TOKEN + 1,
#else
    0,
#endif
    QUIC_PARAM_STREAM_STATISTICS + 1
};

#define GET_PARAM_LOOP_COUNT 10

void SpinQuicGetRandomParam(HQUIC Handle, uint16_t ThreadID)
{
    for (uint32_t i = 0; i < GET_PARAM_LOOP_COUNT; ++i) {
        uint32_t Level = (uint32_t)GetRandom(ARRAYSIZE(ParamCounts));
        uint32_t Param = (uint32_t)GetRandom(((ParamCounts[Level] & 0xFFFFFFF)) + 1);
        uint32_t Combined = ((Level+1) << 28) + Param;
        Combined &= ~QUIC_PARAM_HIGH_PRIORITY; // TODO: enable high priority GetParam

        uint8_t OutBuffer[200];
        uint32_t OutBufferLength = (uint32_t)GetRandom(sizeof(OutBuffer) + 1);

        MsQuic.GetParam(
            (GetRandom(10) == 0) ? nullptr : Handle,
            Combined,
            &OutBufferLength,
            (GetRandom(10) == 0) ? nullptr : OutBuffer);
    }
}

void Spin(Gbs& Gb, LockableVector<HQUIC>& Connections, std::vector<HQUIC>* Listeners = nullptr, uint16_t ThreadID = UINT16_MAX)
{
    Connections.SetThreadID(ThreadID);
    bool IsServer = Listeners != nullptr;

    uint64_t OpCount = 0;
    while (++OpCount != SpinSettings.MaxOperationCount &&
#ifdef FUZZING
        (SpinSettings.MaxFuzzIterationCount != FuzzData->GetIterateCount(ThreadID)) &&
#endif
        CxPlatTimeDiff64(Gb.StartTimeMs, CxPlatTimeMs64()) < SpinSettings.RunTimeMs) {

        if (Listeners) {
            auto Value = GetRandom(100);
            if (Value >= 90) {
                for (auto &Listener : *Listeners) {
                    MsQuic.ListenerStop(Listener);
                }
            } else if (Value >= 40) {
                for (auto &Listener : *Listeners) {
                    QUIC_ADDR sockAddr = { 0 };
                    QuicAddrSetFamily(&sockAddr, GetRandom(2) ? QUIC_ADDRESS_FAMILY_INET : QUIC_ADDRESS_FAMILY_UNSPEC);
                    QuicAddrSetPort(&sockAddr, GetRandomFromVector(SpinSettings.Ports));
                    MsQuic.ListenerStart(Listener, &Gb.Alpns[GetRandom(Gb.AlpnCount)], 1, &sockAddr);
                }
            } else {
                for (auto &Listener : *Listeners) {
                    SpinQuicGetRandomParam(Listener, ThreadID);
                }
            }
        }

    #define BAIL_ON_NULL_CONNECTION(Connection) \
        if (Connection == nullptr) { \
            if (IsServer) { \
                CxPlatSleep(100); \
            } \
            continue; \
        }

        switch (GetRandom(SpinQuicAPICallCount)) {
        case SpinQuicAPICallConnectionOpen:
            if (!IsServer) {
                auto ctx = new SpinQuicConnection(ThreadID);
                if (ctx == nullptr) continue;

                HQUIC Connection;
                QUIC_STATUS Status = MsQuic.ConnectionOpen(Gb.Registration, SpinQuicHandleConnectionEvent, &ThreadID, &Connection);
                if (QUIC_SUCCEEDED(Status)) {
                    ctx->Set(Connection);
                    Connections.push_back(Connection);
                } else {
                    delete ctx;
                }
            }
            break;
        case SpinQuicAPICallConnectionStart: {
            auto Connection = Connections.TryGetRandom();
            BAIL_ON_NULL_CONNECTION(Connection);
            HQUIC Configuration = GetRandomFromVector(Gb.ClientConfigurations);
            MsQuic.ConnectionStart(Connection, Configuration, QUIC_ADDRESS_FAMILY_INET, SpinSettings.ServerName, GetRandomFromVector(SpinSettings.Ports));
            break;
        }
        case SpinQuicAPICallConnectionShutdown: {
            auto Connection = Connections.TryGetRandom();
            BAIL_ON_NULL_CONNECTION(Connection);
            MsQuic.ConnectionShutdown(Connection, (QUIC_CONNECTION_SHUTDOWN_FLAGS)GetRandom(2), 0);
            break;
        }
        case SpinQuicAPICallConnectionClose: {
            auto Connection = Connections.TryGetRandom(true);
            BAIL_ON_NULL_CONNECTION(Connection);
            delete SpinQuicConnection::Get(Connection);
            break;
        }
        case SpinQuicAPICallStreamOpen: {
            auto Connection = Connections.TryGetRandom();
            BAIL_ON_NULL_CONNECTION(Connection);
            HQUIC Stream;
            auto ctx = new SpinQuicStream(*SpinQuicConnection::Get(Connection));
            QUIC_STATUS Status = MsQuic.StreamOpen(Connection, (QUIC_STREAM_OPEN_FLAGS)GetRandom(8), SpinQuicHandleStreamEvent, ctx, &Stream);
            if (QUIC_SUCCEEDED(Status)) {
                ctx->Handle = Stream;
                SpinQuicGetRandomParam(Stream, ThreadID);
                SpinQuicSetRandomStreamParam(Stream, ThreadID);
                SpinQuicConnection::Get(Connection)->AddStream(Stream);
            } else {
                delete ctx;
            }
            break;
        }
        case SpinQuicAPICallStreamStart: {
            auto Connection = Connections.TryGetRandom();
            BAIL_ON_NULL_CONNECTION(Connection);
            auto ctx = SpinQuicConnection::Get(Connection);
            {
                std::lock_guard<std::mutex> Lock(ctx->Lock);
                auto Stream = ctx->TryGetStream();
                if (Stream == nullptr) continue;
                MsQuic.StreamStart(Stream, (QUIC_STREAM_START_FLAGS)GetRandom(16));
            }
            break;
        }
        case SpinQuicAPICallStreamSend: {
            auto Connection = Connections.TryGetRandom();
            BAIL_ON_NULL_CONNECTION(Connection);
            auto ctx = SpinQuicConnection::Get(Connection);
            {
                std::lock_guard<std::mutex> Lock(ctx->Lock);
                auto Stream = ctx->TryGetStream();
                if (Stream == nullptr) continue;
                auto StreamCtx = SpinQuicStream::Get(Stream);
                auto Buffer = new(std::nothrow) QUIC_BUFFER;
                if (Buffer) {
                    const uint32_t Length = MaxBufferSizes[GetRandom(BufferCount)];
                    Buffer->Buffer = Gb.SendBuffer + StreamCtx->SendOffset;
                    Buffer->Length = Length;
                    if (QUIC_SUCCEEDED(
                        MsQuic.StreamSend(Stream, Buffer, 1, (QUIC_SEND_FLAGS)GetRandom(16), Buffer))) {
                        StreamCtx->SendOffset = (uint8_t)(StreamCtx->SendOffset + Length);
                    } else {
                        delete Buffer;
                    }
                }
            }
            break;
        }
        case SpinQuicAPICallStreamReceiveSetEnabled: {
            auto Connection = Connections.TryGetRandom();
            BAIL_ON_NULL_CONNECTION(Connection);
            auto ctx = SpinQuicConnection::Get(Connection);
            {
                std::lock_guard<std::mutex> Lock(ctx->Lock);
                auto Stream = ctx->TryGetStream();
                if (Stream == nullptr) continue;
                MsQuic.StreamReceiveSetEnabled(Stream, GetRandom(2) == 0);
            }
            break;
        }
        case SpinQuicAPICallStreamReceiveComplete: {
            auto Connection = Connections.TryGetRandom();
            BAIL_ON_NULL_CONNECTION(Connection);
            auto ctx = SpinQuicConnection::Get(Connection);
            {
                std::lock_guard<std::mutex> Lock(ctx->Lock);
                auto Stream = ctx->TryGetStream();
                if (Stream == nullptr) continue;
                auto StreamCtx = SpinQuicStream::Get(Stream);
                if (StreamCtx->PendingRecvLength == UINT64_MAX) continue; // Nothing to complete (yet
                auto BytesRemaining = StreamCtx->PendingRecvLength;
                StreamCtx->PendingRecvLength = UINT64_MAX;
                if (BytesRemaining != 0 && GetRandom(10) == 0) {
                    auto BytesConsumed = GetRandom(BytesRemaining);
                    MsQuic.StreamReceiveComplete(Stream, BytesConsumed);
                } else {
                    MsQuic.StreamReceiveComplete(Stream, BytesRemaining);
                }
            }
            break;
        }
        case SpinQuicAPICallStreamShutdown: {
            auto Connection = Connections.TryGetRandom();
            BAIL_ON_NULL_CONNECTION(Connection);
            auto ctx = SpinQuicConnection::Get(Connection);
            {
                std::lock_guard<std::mutex> Lock(ctx->Lock);
                auto Stream = ctx->TryGetStream();
                if (Stream == nullptr) continue;
                auto Flags = (QUIC_STREAM_SHUTDOWN_FLAGS)GetRandom(16);
                if (Flags & QUIC_STREAM_SHUTDOWN_FLAG_ABORT_RECEIVE) {
                    auto StreamCtx = SpinQuicStream::Get(Stream);
                    StreamCtx->PendingRecvLength = UINT64_MAX;
                }
                MsQuic.StreamShutdown(Stream, Flags, 0);
            }
            break;
        }
        case SpinQuicAPICallStreamClose: {
            auto Connection = Connections.TryGetRandom();
            BAIL_ON_NULL_CONNECTION(Connection);
            auto ctx = SpinQuicConnection::Get(Connection);
            HQUIC Stream;
            {
                std::lock_guard<std::mutex> Lock(ctx->Lock);
                Stream = ctx->TryGetStream(true);
            }
            if (Stream == nullptr) continue;
            delete SpinQuicStream::Get(Stream);
            break;
        }
        case SpinQuicAPICallSetParamConnection: {
            auto Connection = Connections.TryGetRandom();
            BAIL_ON_NULL_CONNECTION(Connection);
            SpinQuicSetRandomConnectionParam(Connection, ThreadID);
            break;
        }
        case SpinQuicAPICallGetParamConnection: {
            auto Connection = Connections.TryGetRandom();
            BAIL_ON_NULL_CONNECTION(Connection);
            SpinQuicGetRandomParam(Connection, ThreadID);
            break;
        }
        case SpinQuicAPICallSetParamStream: {
            auto Connection = Connections.TryGetRandom();
            BAIL_ON_NULL_CONNECTION(Connection);
            auto ctx = SpinQuicConnection::Get(Connection);
            {
                std::lock_guard<std::mutex> Lock(ctx->Lock);
                auto Stream = ctx->TryGetStream();
                if (Stream == nullptr) continue;
                /* TODO:

                    Currently deadlocks because it makes a blocking call to wait
                    on the QUIC worker thread, but the worker thread tries to
                    grab the same lock when cleaning up the connections' streams.

                    We're going to need some kind of ref counting solution on
                    the stream handle instead of a lock in order to do this.

                SpinQuicSetRandomStreamParam(Stream);
                */
            }
            break;
        }
        case SpinQuicAPICallGetParamStream: {
            auto Connection = Connections.TryGetRandom();
            BAIL_ON_NULL_CONNECTION(Connection);
            auto ctx = SpinQuicConnection::Get(Connection);
            {
                std::lock_guard<std::mutex> Lock(ctx->Lock);
                auto Stream = ctx->TryGetStream();
                if (Stream == nullptr) continue;
                /* TODO:

                    Currently deadlocks because it makes a blocking call to wait
                    on the QUIC worker thread, but the worker thread tries to
                    grab the same lock when cleaning up the connections' streams.

                    We're going to need some kind of ref counting solution on
                    the stream handle instead of a lock in order to do this.

                SpinQuicGetRandomParam(Stream);
                */
            }
            break;
        }
        case SpinQuicAPICallDatagramSend: {
            auto Connection = Connections.TryGetRandom();
            BAIL_ON_NULL_CONNECTION(Connection);
            auto Buffer = new(std::nothrow) QUIC_BUFFER;
            if (Buffer) {
                Buffer->Buffer = Gb.SendBuffer;
                Buffer->Length = MaxBufferSizes[GetRandom(BufferCount)];
                if (QUIC_FAILED(MsQuic.DatagramSend(Connection, Buffer, 1, (QUIC_SEND_FLAGS)GetRandom(8), Buffer))) {
                    delete Buffer;
                }
            }
            break;
        }
        case SpinQuicAPICallCompleteTicketValidation: {
            auto Connection = Connections.TryGetRandom();
            BAIL_ON_NULL_CONNECTION(Connection);
            MsQuic.ConnectionResumptionTicketValidationComplete(Connection, GetRandom(2) == 0);
            break;
        }
        case SpinQuicAPICallCompleteCertificateValidation: {
            auto Connection = Connections.TryGetRandom();
            BAIL_ON_NULL_CONNECTION(Connection);
            MsQuic.ConnectionCertificateValidationComplete(Connection, GetRandom(2) == 0, QUIC_TLS_ALERT_CODE_BAD_CERTIFICATE);
            break;
        }
        default:
            break;
        }
    }
}

CXPLAT_THREAD_CALLBACK(ServerSpin, Context)
{
    uint16_t ThreadID = UINT16_MAX;
    if (FuzzData) {
        ThreadID = 1;
    }

    Gbs& Gb = *(Gbs*)Context;
    bool InitializeSuccess = false;
    do {
        LockableVector<HQUIC> Connections;
        std::vector<HQUIC> Listeners;
        ListenerContext ListenerCtx = { nullptr, &Connections, ThreadID };

        //
        // Setup
        //

        QUIC_SETTINGS QuicSettings{0};
        QuicSettings.PeerBidiStreamCount = GetRandom((uint16_t)10);
        QuicSettings.IsSet.PeerBidiStreamCount = TRUE;
        QuicSettings.PeerUnidiStreamCount = GetRandom((uint16_t)10);
        QuicSettings.IsSet.PeerUnidiStreamCount = TRUE;
        // TODO - Randomize more of the settings.

        auto CredConfig = CxPlatGetSelfSignedCert(CXPLAT_SELF_SIGN_CERT_USER, FALSE, NULL);
        if (!CredConfig) {
            continue;
        }

        if (!QUIC_SUCCEEDED(
            MsQuic.ConfigurationOpen(
                Gb.Registration,
                Gb.Alpns,
                Gb.AlpnCount,
                &QuicSettings,
                sizeof(QuicSettings),
                nullptr,
                &Gb.ServerConfiguration))) {
            goto ConfigOpenFail;
        }

        ASSERT_ON_NOT(Gb.ServerConfiguration);
        ListenerCtx.ServerConfiguration = Gb.ServerConfiguration;

        if (!QUIC_SUCCEEDED(
            MsQuic.ConfigurationLoadCredential(
                Gb.ServerConfiguration,
                CredConfig))) {
            goto CredLoadFail;
        }

        for (uint32_t i = 0; i < Gb.AlpnCount; ++i) {
            for (auto &pt : SpinSettings.Ports) {
                HQUIC Listener;
                if (!QUIC_SUCCEEDED(
                    (MsQuic.ListenerOpen(Gb.Registration, SpinQuicServerHandleListenerEvent, &ListenerCtx, &Listener)))) {
                    goto CleanupListeners;
                }

                QUIC_ADDR sockAddr = { 0 };
                QuicAddrSetFamily(&sockAddr, GetRandom(2) ? QUIC_ADDRESS_FAMILY_INET : QUIC_ADDRESS_FAMILY_UNSPEC);
                QuicAddrSetPort(&sockAddr, pt);

                if (!QUIC_SUCCEEDED(MsQuic.ListenerStart(Listener, &Gb.Alpns[i], 1, &sockAddr))) {
                    MsQuic.ListenerClose(Listener);
                    goto CleanupListeners;
                }
                Listeners.push_back(Listener);
            }
        }

        //
        // Run
        //

        InitializeSuccess = true;
        Spin(Gb, Connections, &Listeners, ThreadID);

        //
        // Clean up
        //
CleanupListeners:
        while (Listeners.size() > 0) {
            auto Listener = Listeners.back();
            Listeners.pop_back();
            MsQuic.ListenerClose(Listener);
        }

        for (auto &Connection : Connections) {
            MsQuic.ConnectionShutdown(Connection, QUIC_CONNECTION_SHUTDOWN_FLAG_SILENT, 0);
        }

        while (Connections.size() > 0) {
            auto Connection = Connections.back();
            Connections.pop_back();
            delete SpinQuicConnection::Get(Connection);
        }

CredLoadFail:
        MsQuic.ConfigurationClose(Gb.ServerConfiguration);
ConfigOpenFail:
        CxPlatFreeSelfSignedCert(CredConfig);
    } while (!InitializeSuccess);

    CXPLAT_THREAD_RETURN(0);
}

CXPLAT_THREAD_CALLBACK(ClientSpin, Context)
{
    uint16_t ThreadID = UINT16_MAX;
    if (FuzzData) {
        ThreadID = 0;
    }

    Gbs& Gb = *(Gbs*)Context;
    LockableVector<HQUIC> Connections;

    //
    // Run
    //

    Spin(Gb, Connections, nullptr, ThreadID);

    //
    // Clean up
    //

    for (auto &Connection : Connections) {
        MsQuic.ConnectionShutdown(Connection, QUIC_CONNECTION_SHUTDOWN_FLAG_SILENT, 0);
    }

    while (Connections.size() > 0) {
        auto Connection = Connections.back();
        Connections.pop_back();
        delete SpinQuicConnection::Get(Connection);
    }

    CXPLAT_THREAD_RETURN(0);
}

void QUIC_API DatapathHookCreateCallback(_Inout_opt_ QUIC_ADDR* /* RemoteAddress */, _Inout_opt_ QUIC_ADDR* /* LocalAddress */)
{
}

void QUIC_API DatapathHookGetAddressCallback(_Inout_ QUIC_ADDR* /* Address */)
{
}

// TODO
BOOLEAN QUIC_API DatapathHookReceiveCallback(struct CXPLAT_RECV_DATA* /* Datagram */)
{
    uint8_t RandomValue;
    CxPlatRandom(sizeof(RandomValue), &RandomValue);
    return (RandomValue % 100) < SpinSettings.LossPercent;
}

BOOLEAN QUIC_API DatapathHookSendCallback(QUIC_ADDR* /* RemoteAddress */, QUIC_ADDR* /* LocalAddress */, struct CXPLAT_SEND_DATA* /* SendData */)
{
    return FALSE; // Don't drop
}

QUIC_TEST_DATAPATH_HOOKS DataPathHooks = {
    DatapathHookCreateCallback,
    DatapathHookGetAddressCallback,
    DatapathHookGetAddressCallback,
    DatapathHookReceiveCallback,
    DatapathHookSendCallback
};

void PrintHelpText(void)
{
    printf("Usage: spinquic.exe [client/server/both] [options]\n" \
          "\n" \
          "  -alpn:<alpn>           default: 'spin'\n" \
          "  -dstport:<port>        default: 9999\n" \
          "  -loss:<percent>        default: 1\n" \
          "  -max_ops:<count>       default: UINT64_MAX\n"
          "  -seed:<seed>           default: 6\n" \
          "  -sessions:<count>      default: 4\n" \
          "  -target:<ip>           default: '127.0.0.1'\n" \
          "  -timeout:<count_ms>    default: 60000\n" \
          "  -repeat_count:<count>  default: 1\n" \
          );
    exit(1);
}

CXPLAT_THREAD_CALLBACK(RunThread, Context)
{
    UNREFERENCED_PARAMETER(Context);
    SpinQuicWatchdog Watchdog((uint32_t)SpinSettings.RunTimeMs + WATCHDOG_WIGGLE_ROOM);
    uint16_t ThreadID = FuzzData ? FuzzingData::NumSpinThread : UINT16_MAX;
    do {
        Gbs Gb;

#ifdef QUIC_BUILD_STATIC
        CxPlatLockAcquire(&RunThreadLock);
        QUIC_STATUS Status = MsQuicOpen2(&Gb.MsQuic);
        CxPlatLockRelease(&RunThreadLock);
#else
        QUIC_STATUS Status = MsQuicOpen2(&Gb.MsQuic);
#endif
        if (QUIC_FAILED(Status)) {
            break;
        }

        if (ExecConfig) {
            MsQuic.SetParam(nullptr, QUIC_PARAM_GLOBAL_EXECUTION_CONFIG, ExecConfigSize, ExecConfig);
        }

        QUIC_SETTINGS QuicSettings{0};
        CXPLAT_THREAD_CONFIG Config = { 0 };

        if (0 == GetRandom(4)) {
            uint16_t RetryMemoryPercent = 0;
            if (!QUIC_SUCCEEDED(MsQuic.SetParam(nullptr, QUIC_PARAM_GLOBAL_RETRY_MEMORY_PERCENT, sizeof(RetryMemoryPercent), &RetryMemoryPercent))) {
                break;
            }
        }

        if (0 == GetRandom(4)) {
            uint16_t LoadBalancingMode = QUIC_LOAD_BALANCING_SERVER_ID_IP;
            if (!QUIC_SUCCEEDED(MsQuic.SetParam(nullptr, QUIC_PARAM_GLOBAL_LOAD_BALACING_MODE, sizeof(LoadBalancingMode), &LoadBalancingMode))) {
                break;
            }
        }

        if (0 == GetRandom(4)) {
            uint8_t StatelessResetKey[QUIC_STATELESS_RESET_KEY_LENGTH];
            CxPlatRandom(sizeof(StatelessResetKey), StatelessResetKey);
            if (!QUIC_SUCCEEDED(MsQuic.SetParam(
                    nullptr,
                    QUIC_PARAM_GLOBAL_STATELESS_RESET_KEY,
                    sizeof(StatelessResetKey),
                    StatelessResetKey))) {
                break;
            }
        }

        QUIC_REGISTRATION_CONFIG RegConfig;
        RegConfig.AppName = "spinquic";
        RegConfig.ExecutionProfile = FuzzData ? QUIC_EXECUTION_PROFILE_TYPE_SCAVENGER : (QUIC_EXECUTION_PROFILE)GetRandom(4);

        if (!QUIC_SUCCEEDED(MsQuic.RegistrationOpen(&RegConfig, &Gb.Registration))) {
            break;
        }

        Gb.Alpns = (QUIC_BUFFER*)malloc(sizeof(QUIC_BUFFER) * SpinSettings.SessionCount);
        ASSERT_ON_NOT(Gb.Alpns);
        Gb.AlpnCount = SpinSettings.SessionCount;

        for (uint32_t j = 0; j < SpinSettings.SessionCount; j++) {
            Gb.Alpns[j].Length = (uint32_t)strlen(SpinSettings.AlpnPrefix);
            if (j != 0) {
                Gb.Alpns[j].Length++;
            }
            Gb.Alpns[j].Buffer = (uint8_t*)malloc(Gb.Alpns[j].Length);
            ASSERT_ON_NOT(Gb.Alpns[j].Buffer);
            memcpy(Gb.Alpns[j].Buffer, SpinSettings.AlpnPrefix, Gb.Alpns[j].Length);
            if (j != 0) {
                Gb.Alpns[j].Buffer[Gb.Alpns[j].Length-1] = (uint8_t)j;
            }
        }

        QuicSettings.PeerBidiStreamCount = GetRandom((uint16_t)10);
        QuicSettings.IsSet.PeerBidiStreamCount = TRUE;
        QuicSettings.PeerUnidiStreamCount = GetRandom((uint16_t)10);
        QuicSettings.IsSet.PeerUnidiStreamCount = TRUE;
        // TODO - Randomize more of the settings.

        QUIC_CREDENTIAL_CONFIG CredConfig;
        CxPlatZeroMemory(&CredConfig, sizeof(CredConfig));
        CredConfig.Type = QUIC_CREDENTIAL_TYPE_NONE;
        CredConfig.Flags =
            QUIC_CREDENTIAL_FLAG_CLIENT |
            QUIC_CREDENTIAL_FLAG_NO_CERTIFICATE_VALIDATION; // TODO - Randomize cert validation flag

        for (uint32_t j = 0; j < Gb.AlpnCount; j++) {
            HQUIC Configuration;
            if (!QUIC_SUCCEEDED(MsQuic.ConfigurationOpen(Gb.Registration, &Gb.Alpns[j], 1, &QuicSettings, sizeof(QuicSettings), nullptr, &Configuration))) {
                break;
            }
            if (!QUIC_SUCCEEDED(MsQuic.ConfigurationLoadCredential(Configuration, &CredConfig))) {
                MsQuic.ConfigurationClose(Configuration);
                break;
            }
            Gb.ClientConfigurations.push_back(Configuration);
        }
        if (Gb.ClientConfigurations.size() != Gb.AlpnCount) {
            break;
        }

        CXPLAT_THREAD Threads[2];

        Gb.StartTimeMs = CxPlatTimeMs64();

        //
        // Start worker threads
        //

        if (SpinSettings.RunServer) {
            Config.Name = "spin_server";
            Config.Callback = ServerSpin;
            Config.Context = &Gb;
            ASSERT_ON_FAILURE(CxPlatThreadCreate(&Config, &Threads[0]));
        }

        if (SpinSettings.RunClient) {
            Config.Name = "spin_client";
            Config.Callback = ClientSpin;
            Config.Context = &Gb;
            ASSERT_ON_FAILURE(CxPlatThreadCreate(&Config, &Threads[1]));
        }

        //
        // Wait on worker threads
        //

        if (SpinSettings.RunClient) {
            CxPlatThreadWait(&Threads[1]);
            CxPlatThreadDelete(&Threads[1]);
        }

        if (SpinSettings.RunServer) {
            CxPlatThreadWait(&Threads[0]);
            CxPlatThreadDelete(&Threads[0]);
        }

    } while (false);

    CXPLAT_THREAD_RETURN(0);
}


void start() {
    CxPlatSystemLoad();
    CxPlatInitialize();
    CxPlatLockInitialize(&RunThreadLock);

    {
        SpinQuicWatchdog Watchdog((uint32_t)SpinSettings.RunTimeMs + SpinSettings.RepeatCount*WATCHDOG_WIGGLE_ROOM);

        //
        // Initial MsQuicOpen2 and initialization.
        //
        const QUIC_API_TABLE* TempMsQuic = nullptr;
        ASSERT_ON_FAILURE(MsQuicOpen2(&TempMsQuic));
        CxPlatCopyMemory(&MsQuic, TempMsQuic, sizeof(MsQuic));

        if (SpinSettings.AllocFailDenominator > 0) {
            if (QUIC_FAILED(
                MsQuic.SetParam(
                    nullptr,
                    QUIC_PARAM_GLOBAL_ALLOC_FAIL_DENOMINATOR,
                    sizeof(SpinSettings.AllocFailDenominator),
                    &SpinSettings.AllocFailDenominator))) {
                printf("Setting Allocation Failure Denominator failed.\n");
            }
        }

        if (SpinSettings.LossPercent != 0) {
            QUIC_TEST_DATAPATH_HOOKS* Value = &DataPathHooks;
            if (QUIC_FAILED(
                MsQuic.SetParam(
                    nullptr,
                    QUIC_PARAM_GLOBAL_TEST_DATAPATH_HOOKS,
                    sizeof(Value),
                    &Value))) {
                printf("Setting Datapath hooks failed.\n");
            }
        }

        MsQuicClose(TempMsQuic);

#ifndef FUZZING
        uint16_t ThreadID = UINT16_MAX;
        if (ExecConfig) {
            free(ExecConfig);
            ExecConfig = nullptr;
            ExecConfigSize = 0;
        }

        if (GetRandom(2) == 0) {
            const uint32_t ProcCount =
                CxPlatProcCount() == 1 ?
                    1 :
                    1 + GetRandom(CxPlatProcCount() - 1);
            printf("Using %u partitions...\n", ProcCount);
            ExecConfigSize = QUIC_EXECUTION_CONFIG_MIN_SIZE + sizeof(uint16_t)*ProcCount;
            ExecConfig = (QUIC_EXECUTION_CONFIG*)malloc(ExecConfigSize);
            if (strncmp(SpinSettings.ServerName, "192.168.1.11", 12) == 0) {
                ExecConfig->Flags = QUIC_EXECUTION_CONFIG_FLAG_XDP;
            } else {
                ExecConfig->Flags = QUIC_EXECUTION_CONFIG_FLAG_NONE;
            }
            ExecConfig->PollingIdleTimeoutUs = 0; // TODO - Randomize?
            ExecConfig->ProcessorCount = ProcCount;
            for (uint32_t i = 0; i < ProcCount; ++i) {
                ExecConfig->ProcessorList[i] = (uint16_t)i;
            }
        }
#endif

        SpinSettings.RunTimeMs = SpinSettings.RunTimeMs / SpinSettings.RepeatCount;
        for (uint32_t i = 0; i < SpinSettings.RepeatCount; i++) {

            CXPLAT_THREAD_CONFIG Config = {
                0, 0, "spin_run", RunThread, nullptr
            };
            CXPLAT_THREAD Threads[4];
            uint32_t Count = FuzzData ? (uint32_t)FuzzingData::NumSpinThread / 2 : (uint32_t)(rand() % (ARRAYSIZE(Threads) - 1) + 1);

            for (uint32_t j = 0; j < Count; ++j) {
                ASSERT_ON_FAILURE(CxPlatThreadCreate(&Config, &Threads[j]));
            }

            for (uint32_t j = 0; j < Count; ++j) {
                CxPlatThreadWait(&Threads[j]);
                CxPlatThreadDelete(&Threads[j]);
            }
        }
    }

    CxPlatLockUninitialize(&RunThreadLock);
    CxPlatUninitialize();
    CxPlatSystemUnload();
}

#ifdef FUZZING

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    if (size < FuzzingData::MinDataSize || size % 2 == 1) {
        return 0;
    }
    FuzzData = new FuzzingData(data, size);
    if (!FuzzData->Initialize()) {
        return 0;
    }

    SpinSettings.RunServer = true;
    SpinSettings.RunClient = true;
    // OSS-Fuzz timeout is 25 sec
    SpinSettings.RunTimeMs = 10000; // 10 sec
    SpinSettings.ServerName = "127.0.0.1";
    SpinSettings.Ports = std::vector<uint16_t>({9998, 9999});
    SpinSettings.AlpnPrefix = "spin";
    SpinSettings.MaxOperationCount = UINT64_MAX;
    SpinSettings.MaxFuzzIterationCount = 2;
    SpinSettings.LossPercent = 1;
    SpinSettings.AllocFailDenominator = 0;
    SpinSettings.RepeatCount = 1;

    start();
    delete FuzzData;
    return 0;
}

#else

int
QUIC_MAIN_EXPORT
main(int argc, char **argv)
{
    if (argc < 2) {
        PrintHelpText();
    }

    if (strcmp(argv[1], "server") == 0) {
        SpinSettings.RunServer = true;
    } else if (strcmp(argv[1], "client") == 0) {
        SpinSettings.RunClient = true;
    } else if (strcmp(argv[1], "both") == 0) {
        SpinSettings.RunServer = true;
        SpinSettings.RunClient = true;
    } else {
        printf("Must specify one of the following as the first argument: 'server' 'client' 'both'\n\n");
        PrintHelpText();
    }

    SpinSettings.RunTimeMs = 60000;
    SpinSettings.ServerName = "127.0.0.1";
    SpinSettings.Ports = std::vector<uint16_t>({9998, 9999});
    SpinSettings.AlpnPrefix = "spin";
    SpinSettings.MaxOperationCount = UINT64_MAX;
    SpinSettings.MaxFuzzIterationCount = UINT64_MAX;
    SpinSettings.LossPercent = 5;
    SpinSettings.AllocFailDenominator = 0;
    SpinSettings.RepeatCount = 1;

    TryGetValue(argc, argv, "timeout", &SpinSettings.RunTimeMs);
    TryGetValue(argc, argv, "max_ops", &SpinSettings.MaxOperationCount);
    TryGetValue(argc, argv, "loss", &SpinSettings.LossPercent);
    TryGetValue(argc, argv, "repeat_count", &SpinSettings.RepeatCount);
    TryGetValue(argc, argv, "alloc_fail", &SpinSettings.AllocFailDenominator);

    if (SpinSettings.RepeatCount == 0) {
        printf("Must specify a non 0 repeat count\n");
        PrintHelpText();
    }

    if (SpinSettings.RunClient) {
        uint16_t dstPort = 0;
        if (TryGetValue(argc, argv, "dstport", &dstPort)) {
            SpinSettings.Ports = std::vector<uint16_t>({dstPort});
        }
        TryGetValue(argc, argv, "target", &SpinSettings.ServerName);
        if (TryGetValue(argc, argv, "alpn", &SpinSettings.AlpnPrefix)) {
            SpinSettings.SessionCount = 1; // Default session count to 1 if ALPN explicitly specified.
        }
        TryGetValue(argc, argv, "sessions", &SpinSettings.SessionCount);
    }

    uint32_t RngSeed = 0;
    if (!TryGetValue(argc, argv, "seed", &RngSeed)) {
        CxPlatRandom(sizeof(RngSeed), &RngSeed);
    }
    printf("Using seed value: %u\n", RngSeed);
    srand(RngSeed);
    start();

    return 0;
}

#endif // FUZZING
