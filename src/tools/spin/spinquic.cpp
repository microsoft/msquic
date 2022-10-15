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
#include "msquichelper.h"

#define ASSERT_ON_FAILURE(x) \
    do { \
        QUIC_STATUS _STATUS; \
        CXPLAT_FRE_ASSERT(QUIC_SUCCEEDED((_STATUS = x))); \
    } while (0)
#define ASSERT_ON_NOT(x) CXPLAT_FRE_ASSERT(x)

class FuzzingData {
    const uint8_t* data;
    size_t size;
    // TODO: multiple EachSize for non divisible size
    size_t EachSize;
    std::vector<size_t> Ptrs;
    bool Cyclic;
    uint16_t NumThread;
public:
    short int IncrementalThreadId;

    FuzzingData() : data(nullptr), size(0), Ptrs({}), Cyclic(true), NumThread(65535) {}
    FuzzingData(const uint8_t* data, size_t size) : data(data), size(size), Ptrs({}), Cyclic(true), NumThread(65535) {}
    bool Initialize(uint16_t NumSpinThread) {
        // TODO: support non divisible size
        if (size % NumSpinThread != 0) {
            return false;
        }

        IncrementalThreadId = 0;
        NumThread = NumSpinThread;
        EachSize = size / NumThread;
        Ptrs.resize(NumThread);
        std::fill(Ptrs.begin(), Ptrs.end(), 0);
        return true;
    }
    bool TryGetByte(uint8_t* Val, uint16_t ThreadId = 0) {
        if (EachSize < Ptrs[ThreadId] + 1) {
            if (Cyclic) {
                return false;
            }
            Ptrs[ThreadId] = 0;
        }
        *Val = data[Ptrs[ThreadId]++ + EachSize * ThreadId];
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
        int type_size = sizeof(T);
        // TODO: efficient cyclic access
        if (EachSize < Ptrs[ThreadId] + type_size) {
            if (Cyclic) {
                return false;
            }
            Ptrs[ThreadId] = 0;
        }
        memcpy(Val, &data[Ptrs[ThreadId]], type_size);
        *(uint64_t*)Val %= (uint64_t)UpperBound;
        Ptrs[ThreadId] += type_size;
        return true;
    }
};

static FuzzingData* FuzzData = nullptr;

template<typename T>
T GetRandom(T UpperBound, uint16_t ThreadID = std::numeric_limits<uint16_t>::max()) {
    if (!FuzzData || ThreadID == std::numeric_limits<uint16_t>::max()) {
        return (T)(rand() % (int)UpperBound);
    }
    T out;
    (void)FuzzData->TryGetRandom(UpperBound, &out, ThreadID);
    return out;
}

template<typename T>
T& GetRandomFromVector(std::vector<T> &vec) {
    return vec.at(GetRandom(vec.size()));
}

template<typename T>
class LockableVector : public std::vector<T>, public std::mutex {
    uint16_t ThreadID = std::numeric_limits<uint16_t>::max();
public:
    T TryGetRandom(bool Erase = false) {
        std::lock_guard<std::mutex> Lock(*this);
        if (this->size() > 0) {
            auto idx = GetRandom(this->size(), ThreadID);
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
    static
    CXPLAT_THREAD_CALLBACK(WatchdogThreadCallback, Context) {
        auto This = (SpinQuicWatchdog*)Context;
        if (!CxPlatEventWaitWithTimeout(This->ShutdownEvent, This->TimeoutMs)) {
            printf("Watchdog timeout fired!\n");
            CXPLAT_FRE_ASSERTMSG(FALSE, "Watchdog timeout fired!");
        }
        CXPLAT_THREAD_RETURN(0);
    }
public:
    SpinQuicWatchdog(uint32_t WatchdogTimeoutMs) : TimeoutMs(WatchdogTimeoutMs) {
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
    QUIC_BUFFER Buffers[BufferCount];
    SpinQuicGlobals() { CxPlatZeroMemory(Buffers, sizeof(Buffers)); }
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
        for (size_t j = 0; j < BufferCount; ++j) {
            free(Buffers[j].Buffer);
        }
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
    SpinQuicAPICallStreamReceiveSetEnabled,
    SpinQuicAPICallStreamReceiveComplete,
    SpinQuicAPICallCount    // Always the last element
} SpinQuicAPICall;

class SpinQuicConnection {
public:
    std::mutex Lock;
    HQUIC Connection = nullptr;
    std::vector<HQUIC> Streams;
    bool IsShutdownComplete = false;
    bool IsDeleting = false;
    static SpinQuicConnection* Get(HQUIC Connection) {
        return (SpinQuicConnection*)MsQuic.GetContext(Connection);
    }
    SpinQuicConnection() { }
    SpinQuicConnection(HQUIC Connection) {
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
            MsQuic.StreamClose(Stream);
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
    const char* AlpnPrefix;
    std::vector<uint16_t> Ports;
    const char* ServerName;
    uint8_t LossPercent;
    int32_t AllocFailDenominator;
    uint32_t RepeatCount;
} Settings;

QUIC_STATUS QUIC_API SpinQuicHandleStreamEvent(HQUIC Stream, void * /* Context */, QUIC_STREAM_EVENT *Event)
{
    switch (Event->Type) {
    case QUIC_STREAM_EVENT_PEER_SEND_SHUTDOWN:
        MsQuic.StreamShutdown(Stream, (QUIC_STREAM_SHUTDOWN_FLAGS)GetRandom(16), 0);
        break;
    case QUIC_STREAM_EVENT_RECEIVE: {
        int Random = GetRandom(5);
        if (Random == 0) {
            MsQuic.SetContext(Stream, (void*)Event->RECEIVE.TotalBufferLength);
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

    return QUIC_STATUS_SUCCESS;
}

QUIC_STATUS QUIC_API SpinQuicHandleConnectionEvent(HQUIC Connection, void * /* Context */, QUIC_CONNECTION_EVENT *Event)
{
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
    case QUIC_CONNECTION_EVENT_PEER_STREAM_STARTED:
        MsQuic.SetCallbackHandler(Event->PEER_STREAM_STARTED.Stream, (void *)SpinQuicHandleStreamEvent, nullptr);
        SpinQuicConnection::Get(Connection)->AddStream(Event->PEER_STREAM_STARTED.Stream);
        break;
    default:
        break;
    }

    return QUIC_STATUS_SUCCESS;
}

struct ListenerContext {
    HQUIC ServerConfiguration;
    LockableVector<HQUIC>* Connections;
};

QUIC_STATUS QUIC_API SpinQuicServerHandleListenerEvent(HQUIC /* Listener */, void* Context , QUIC_LISTENER_EVENT* Event)
{
    HQUIC ServerConfiguration = ((ListenerContext*)Context)->ServerConfiguration;
    auto& Connections = *((ListenerContext*)Context)->Connections;

    switch (Event->Type) {
    case QUIC_LISTENER_EVENT_NEW_CONNECTION: {
        if (!GetRandom(20)) {
            return QUIC_STATUS_CONNECTION_REFUSED;
        }
        MsQuic.SetCallbackHandler(Event->NEW_CONNECTION.Connection, (void*)SpinQuicHandleConnectionEvent, nullptr);
        QUIC_STATUS Status =
            MsQuic.ConnectionSetConfiguration(
                Event->NEW_CONNECTION.Connection,
                ServerConfiguration);
        if (QUIC_FAILED(Status)) {
            return Status;
        }
        auto ctx = new SpinQuicConnection(Event->NEW_CONNECTION.Connection);
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

void SpinQuicSetRandomConnectionParam(HQUIC Connection)
{
    uint8_t RandomBuffer[8];
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
        // TODO
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
    case QUIC_PARAM_CONN_DISABLE_1RTT_ENCRYPTION:                   // uint8_t (BOOLEAN)
        Helper.SetUint8(QUIC_PARAM_CONN_DISABLE_1RTT_ENCRYPTION, (uint8_t)GetRandom(2));
        break;
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
        CxPlatRandom(sizeof(RandomBuffer), RandomBuffer);
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

void SpinQuicSetRandomStreamParam(HQUIC Stream)
{
    SetParamHelper Helper;

    switch (0x08000000 | (GetRandom(5))) {
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

void SpinQuicGetRandomParam(HQUIC Handle)
{
    for (uint32_t i = 0; i < GET_PARAM_LOOP_COUNT; ++i) {
        uint32_t Level = (uint32_t)GetRandom(ARRAYSIZE(ParamCounts));
        uint32_t Param = (uint32_t)GetRandom(((ParamCounts[Level] & 0xFFFFFFF)) + 1);
        uint32_t Combined = ((Level+1) << 28) + Param;

        uint8_t OutBuffer[200];
        uint32_t OutBufferLength = (uint32_t)GetRandom(sizeof(OutBuffer) + 1);

        MsQuic.GetParam(
            (GetRandom(10) == 0) ? nullptr : Handle,
            Combined,
            &OutBufferLength,
            (GetRandom(10) == 0) ? nullptr : OutBuffer);
    }
}

void Spin(Gbs& Gb, LockableVector<HQUIC>& Connections, std::vector<HQUIC>* Listeners = nullptr)
{

    uint16_t ThreadID = std::numeric_limits<uint16_t>::max();
    if (FuzzData) {
        ThreadID = InterlockedIncrement16(&FuzzData->IncrementalThreadId) - 1;
        Connections.SetThreadID(ThreadID);
    }

    bool IsServer = Listeners != nullptr;

    uint64_t OpCount = 0;
    while (++OpCount != Settings.MaxOperationCount &&
        CxPlatTimeDiff64(Gb.StartTimeMs, CxPlatTimeMs64()) < Settings.RunTimeMs) {

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
                    QuicAddrSetPort(&sockAddr, GetRandomFromVector(Settings.Ports));
                    MsQuic.ListenerStart(Listener, &Gb.Alpns[GetRandom(Gb.AlpnCount)], 1, &sockAddr);
                }
            } else {
                for (auto &Listener : *Listeners) {
                    SpinQuicGetRandomParam(Listener);
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

        switch (GetRandom(SpinQuicAPICallCount, ThreadID)) {
        case SpinQuicAPICallConnectionOpen:
            if (!IsServer) {
                auto ctx = new SpinQuicConnection();
                if (ctx == nullptr) continue;

                HQUIC Connection;
                QUIC_STATUS Status = MsQuic.ConnectionOpen(Gb.Registration, SpinQuicHandleConnectionEvent, ctx, &Connection);
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
            MsQuic.ConnectionStart(Connection, Configuration, QUIC_ADDRESS_FAMILY_INET, Settings.ServerName, GetRandomFromVector(Settings.Ports));
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
            QUIC_STATUS Status = MsQuic.StreamOpen(Connection, (QUIC_STREAM_OPEN_FLAGS)GetRandom(2), SpinQuicHandleStreamEvent, nullptr, &Stream);
            if (QUIC_SUCCEEDED(Status)) {
                SpinQuicGetRandomParam(Stream);
                SpinQuicSetRandomStreamParam(Stream);
                SpinQuicConnection::Get(Connection)->AddStream(Stream);
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
                auto Buffer = &Gb.Buffers[GetRandom(BufferCount)];
                MsQuic.StreamSend(Stream, Buffer, 1, (QUIC_SEND_FLAGS)GetRandom(16), nullptr);
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
                auto BytesRemaining = MsQuic.GetContext(Stream);
                if (BytesRemaining != nullptr && GetRandom(10) == 0) {
                    auto BytesConsumed = GetRandom((uint64_t)BytesRemaining);
                    MsQuic.SetContext(Stream, (void*)((uint64_t)BytesRemaining - BytesConsumed));
                    MsQuic.StreamReceiveComplete(Stream, BytesConsumed);
                } else {
                    MsQuic.SetContext(Stream, nullptr);
                    MsQuic.StreamReceiveComplete(Stream, (uint64_t)BytesRemaining);
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
                MsQuic.StreamShutdown(Stream, (QUIC_STREAM_SHUTDOWN_FLAGS)GetRandom(16), 0);
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
            MsQuic.StreamClose(Stream);
            break;
        }
        case SpinQuicAPICallSetParamConnection: {
            auto Connection = Connections.TryGetRandom();
            BAIL_ON_NULL_CONNECTION(Connection);
            SpinQuicSetRandomConnectionParam(Connection);
            break;
        }
        case SpinQuicAPICallGetParamConnection: {
            auto Connection = Connections.TryGetRandom();
            BAIL_ON_NULL_CONNECTION(Connection);
            SpinQuicGetRandomParam(Connection);
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
            auto Buffer = &Gb.Buffers[GetRandom(BufferCount)];
            MsQuic.DatagramSend(Connection, Buffer, 1, (QUIC_SEND_FLAGS)GetRandom(8), nullptr);
        }
        default:
            break;
        }
    }
}

CXPLAT_THREAD_CALLBACK(ServerSpin, Context)
{
    Gbs& Gb = *(Gbs*)Context;
    bool InitializeSuccess = false;
    do {
        LockableVector<HQUIC> Connections;
        std::vector<HQUIC> Listeners;
        ListenerContext ListenerCtx = { nullptr, &Connections };

        //
        // Setup
        //

        QUIC_SETTINGS QuicSettings{0};
        QuicSettings.PeerBidiStreamCount = GetRandom((uint16_t)10);
        QuicSettings.IsSet.PeerBidiStreamCount = TRUE;
        QuicSettings.PeerUnidiStreamCount = GetRandom((uint16_t)10);
        QuicSettings.IsSet.PeerUnidiStreamCount = TRUE;
        // TODO - Randomize more of the settings.

        auto CredConfig = CxPlatGetSelfSignedCert(CXPLAT_SELF_SIGN_CERT_USER, FALSE);
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
            for (auto &pt : Settings.Ports) {
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
        Spin(Gb, Connections, &Listeners);

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
    Gbs& Gb = *(Gbs*)Context;
    LockableVector<HQUIC> Connections;

    //
    // Run
    //

    Spin(Gb, Connections);

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

BOOLEAN QUIC_API DatapathHookReceiveCallback(struct CXPLAT_RECV_DATA* /* Datagram */)
{
    uint8_t RandomValue;
    CxPlatRandom(sizeof(RandomValue), &RandomValue);
    return (RandomValue % 100) < Settings.LossPercent;
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
    SpinQuicWatchdog Watchdog((uint32_t)Settings.RunTimeMs + WATCHDOG_WIGGLE_ROOM);

    do {
        Gbs Gb;

        for (size_t j = 0; j < BufferCount; ++j) {
            Gb.Buffers[j].Length = MaxBufferSizes[j]; // TODO - Randomize?
            Gb.Buffers[j].Buffer = (uint8_t*)malloc(Gb.Buffers[j].Length);
            ASSERT_ON_NOT(Gb.Buffers[j].Buffer);
        }

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

        QUIC_REGISTRATION_CONFIG RegConfig;
        RegConfig.AppName = "spinquic";
        RegConfig.ExecutionProfile = (QUIC_EXECUTION_PROFILE)GetRandom(4);

        if (!QUIC_SUCCEEDED(MsQuic.RegistrationOpen(&RegConfig, &Gb.Registration))) {
            break;
        }

        Gb.Alpns = (QUIC_BUFFER*)malloc(sizeof(QUIC_BUFFER) * Settings.SessionCount);
        ASSERT_ON_NOT(Gb.Alpns);
        Gb.AlpnCount = Settings.SessionCount;

        for (uint32_t j = 0; j < Settings.SessionCount; j++) {
            Gb.Alpns[j].Length = (uint32_t)strlen(Settings.AlpnPrefix);
            if (j != 0) {
                Gb.Alpns[j].Length++;
            }
            Gb.Alpns[j].Buffer = (uint8_t*)malloc(Gb.Alpns[j].Length);
            ASSERT_ON_NOT(Gb.Alpns[j].Buffer);
            memcpy(Gb.Alpns[j].Buffer, Settings.AlpnPrefix, Gb.Alpns[j].Length);
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

        if (Settings.RunServer) {
            Config.Name = "spin_server";
            Config.Callback = ServerSpin;
            Config.Context = &Gb;
            ASSERT_ON_FAILURE(CxPlatThreadCreate(&Config, &Threads[0]));
        }

        if (Settings.RunClient) {
            Config.Name = "spin_client";
            Config.Callback = ClientSpin;
            Config.Context = &Gb;
            ASSERT_ON_FAILURE(CxPlatThreadCreate(&Config, &Threads[1]));
        }

        //
        // Wait on worker threads
        //

        if (Settings.RunClient) {
            CxPlatThreadWait(&Threads[1]);
            CxPlatThreadDelete(&Threads[1]);
        }

        if (Settings.RunServer) {
            CxPlatThreadWait(&Threads[0]);
            CxPlatThreadDelete(&Threads[0]);
        }

    } while (false);

    CXPLAT_THREAD_RETURN(0);
}


int start(void* Context) {
    CxPlatSystemLoad();
    CxPlatInitialize();
    CxPlatLockInitialize(&RunThreadLock);

    //
    // Initial MsQuicOpen2 and initialization.
    //
    const QUIC_API_TABLE* TempMsQuic = nullptr;
    ASSERT_ON_FAILURE(MsQuicOpen2(&TempMsQuic));
    CxPlatCopyMemory(&MsQuic, TempMsQuic, sizeof(MsQuic));

    if (Settings.AllocFailDenominator > 0) {
        if (QUIC_FAILED(
            MsQuic.SetParam(
                nullptr,
                QUIC_PARAM_GLOBAL_ALLOC_FAIL_DENOMINATOR,
                sizeof(Settings.AllocFailDenominator),
                &Settings.AllocFailDenominator))) {
            printf("Setting Allocation Failure Denominator failed.\n");
        }
    }

    if (Settings.LossPercent != 0) {
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

    Settings.RunTimeMs = Settings.RunTimeMs / Settings.RepeatCount;
    for (uint32_t i = 0; i < Settings.RepeatCount; i++) {

        CXPLAT_THREAD_CONFIG Config = {
            0, 0, "spin_run", RunThread, Context
        };
        CXPLAT_THREAD Threads[4];
        const uint32_t Count = (uint32_t)(rand() % (ARRAYSIZE(Threads) - 1) + 1);
        if (FuzzData) {
            if (!(FuzzData->Initialize((uint16_t)(Count * (Settings.RunServer + Settings.RunClient))))) {
                return 0;
            }
        }

        for (uint32_t j = 0; j < Count; ++j) {
            ASSERT_ON_FAILURE(CxPlatThreadCreate(&Config, &Threads[j]));
        }

        for (uint32_t j = 0; j < Count; ++j) {
            CxPlatThreadWait(&Threads[j]);
            CxPlatThreadDelete(&Threads[j]);
        }
    }

    CxPlatLockUninitialize(&RunThreadLock);
    return 0;
}

#ifdef FUZZING

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    // TODD: timeout within 25 sec
    // cast "data" to any structures which are passed to any API with "size".

    if (size < sizeof(int)*4 || size % 2 == 1) {
        return 0;
    }

    Settings.RunServer = true;
    Settings.RunClient = true;
    Settings.RunTimeMs = 200; // OSS-Fuzz timeout is 25 sec
    Settings.ServerName = "127.0.0.1";
    Settings.Ports = std::vector<uint16_t>({9998, 9999});
    Settings.AlpnPrefix = "spin";
    Settings.MaxOperationCount = UINT64_MAX;
    Settings.LossPercent = 1;
    Settings.AllocFailDenominator = 0;
    Settings.RepeatCount = 1;

    FuzzData = new FuzzingData(data, size);
    start(nullptr);
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
        Settings.RunServer = true;
    } else if (strcmp(argv[1], "client") == 0) {
        Settings.RunClient = true;
    } else if (strcmp(argv[1], "both") == 0) {
        Settings.RunServer = true;
        Settings.RunClient = true;
    } else {
        printf("Must specify one of the following as the first argument: 'server' 'client' 'both'\n\n");
        PrintHelpText();
    }

    Settings.RunTimeMs = 60000;
    Settings.ServerName = "127.0.0.1";
    Settings.Ports = std::vector<uint16_t>({9998, 9999});
    Settings.AlpnPrefix = "spin";
    Settings.MaxOperationCount = UINT64_MAX;
    Settings.LossPercent = 1;
    Settings.AllocFailDenominator = 0;
    Settings.RepeatCount = 1;

    TryGetValue(argc, argv, "timeout", &Settings.RunTimeMs);
    TryGetValue(argc, argv, "max_ops", &Settings.MaxOperationCount);
    TryGetValue(argc, argv, "loss", &Settings.LossPercent);
    TryGetValue(argc, argv, "repeat_count", &Settings.RepeatCount);
    TryGetValue(argc, argv, "alloc_fail", &Settings.AllocFailDenominator);

    if (Settings.RepeatCount == 0) {
        printf("Must specify a non 0 repeat count\n");
        PrintHelpText();
    }

    if (Settings.RunClient) {
        uint16_t dstPort = 0;
        if (TryGetValue(argc, argv, "dstport", &dstPort)) {
            Settings.Ports = std::vector<uint16_t>({dstPort});
        }
        TryGetValue(argc, argv, "target", &Settings.ServerName);
        if (TryGetValue(argc, argv, "alpn", &Settings.AlpnPrefix)) {
            Settings.SessionCount = 1; // Default session count to 1 if ALPN explicitly specified.
        }
        TryGetValue(argc, argv, "sessions", &Settings.SessionCount);
    }

    uint32_t RngSeed = 0;
    if (!TryGetValue(argc, argv, "seed", &RngSeed)) {
        CxPlatRandom(sizeof(RngSeed), &RngSeed);
    }
    printf("Using seed value: %u\n", RngSeed);
    srand(RngSeed);

    return start(nullptr);
}

#endif
