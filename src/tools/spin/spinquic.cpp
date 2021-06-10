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
#include <msquichelper.h>

#define ASSERT_ON_FAILURE(x) \
    do { \
        QUIC_STATUS _STATUS; \
        CXPLAT_FRE_ASSERT(QUIC_SUCCEEDED((_STATUS = x))); \
    } while (0)
#define ASSERT_ON_NOT(x) CXPLAT_FRE_ASSERT(x)

template<typename T>
T GetRandom(T UpperBound) {
    return (T)(rand() % (int)UpperBound);
}

template<typename T>
T& GetRandomFromVector(std::vector<T> &vec) {
    return vec.at(GetRandom(vec.size()));
}

template<typename T>
class LockableVector : public std::vector<T>, public std::mutex {
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
};

//
// The amount of extra time (in milliseconds) to give the watchdog before
// actually firing.
//
#define WATCHDOG_WIGGLE_ROOM 15000

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

static uint64_t StartTimeMs;
static const QUIC_API_TABLE* MsQuic;
static HQUIC Registration;
static HQUIC ServerConfiguration;
static std::vector<HQUIC> ClientConfigurations;
static QUIC_BUFFER* Alpns;
static uint32_t AlpnCount;

const uint32_t MaxBufferSizes[] = { 0, 1, 2, 32, 50, 256, 500, 1000, 1024, 1400, 5000, 10000, 64000, 10000000 };
static const size_t BufferCount = ARRAYSIZE(MaxBufferSizes);
static QUIC_BUFFER Buffers[BufferCount];

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
        return (SpinQuicConnection*)MsQuic->GetContext(Connection);
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
        MsQuic->ConnectionClose(Connection);
    }
    void Set(HQUIC _Connection) {
        Connection = _Connection;
        MsQuic->SetContext(Connection, this);
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
            MsQuic->StreamClose(Stream);
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
    uint64_t RunTimeMs;
    uint64_t MaxOperationCount;
    const char* AlpnPrefix;
    std::vector<uint16_t> Ports;
    const char* ServerName;
    uint8_t LossPercent;
    int32_t AllocFailDenominator;
} Settings;

QUIC_STATUS QUIC_API SpinQuicHandleStreamEvent(HQUIC Stream, void * /* Context */, QUIC_STREAM_EVENT *Event)
{
    switch (Event->Type) {
    case QUIC_STREAM_EVENT_PEER_SEND_SHUTDOWN:
        MsQuic->StreamShutdown(Stream, (QUIC_STREAM_SHUTDOWN_FLAGS)GetRandom(16), 0);
        break;
    case QUIC_STREAM_EVENT_RECEIVE: {
        int Random = GetRandom(5);
        if (Random == 0) {
            MsQuic->SetContext(Stream, (void*)Event->RECEIVE.TotalBufferLength);
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
        MsQuic->ConnectionSendResumptionTicket(Connection, Flags, DataLength, Data);
        free(Data);
        break;
    }
    case QUIC_CONNECTION_EVENT_SHUTDOWN_COMPLETE:
        SpinQuicConnection::Get(Connection)->OnShutdownComplete();
        break;
    case QUIC_CONNECTION_EVENT_PEER_STREAM_STARTED:
        MsQuic->SetCallbackHandler(Event->PEER_STREAM_STARTED.Stream, (void *)SpinQuicHandleStreamEvent, nullptr);
        SpinQuicConnection::Get(Connection)->AddStream(Event->PEER_STREAM_STARTED.Stream);
        break;
    default:
        break;
    }

    return QUIC_STATUS_SUCCESS;
}

QUIC_STATUS QUIC_API SpinQuicServerHandleListenerEvent(HQUIC /* Listener */, void* Context , QUIC_LISTENER_EVENT* Event)
{
    auto& Connections = *(LockableVector<HQUIC>*)(Context);

    switch (Event->Type) {
    case QUIC_LISTENER_EVENT_NEW_CONNECTION: {
        if (!GetRandom(20)) {
            return QUIC_STATUS_CONNECTION_REFUSED;
        }
        MsQuic->SetCallbackHandler(Event->NEW_CONNECTION.Connection, (void*)SpinQuicHandleConnectionEvent, nullptr);
        QUIC_STATUS Status =
            MsQuic->ConnectionSetConfiguration(
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
    QUIC_PARAM_LEVEL Level;
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
    SetParamHelper(QUIC_PARAM_LEVEL _Level) {
        Level = _Level;
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
            MsQuic->SetParam(Handle, Level, Type, Size, IsPtr ? Param.ptr : &Param);
        }
    }
};

void SpinQuicSetRandomConnectionParam(HQUIC Connection)
{
    SetParamHelper Helper(QUIC_PARAM_LEVEL_CONNECTION);

    switch (GetRandom(22) + 1) {
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
    default:
        break;
    }

    Helper.Apply(Connection);
}

const uint32_t ParamCounts[] = {
    QUIC_PARAM_GLOBAL_LOAD_BALACING_MODE + 1,
    QUIC_PARAM_REGISTRATION_CID_PREFIX + 1,
    0,
    QUIC_PARAM_LISTENER_STATS + 1,
    QUIC_PARAM_CONN_DISABLE_1RTT_ENCRYPTION + 1,
    0,
    QUIC_PARAM_STREAM_IDEAL_SEND_BUFFER_SIZE + 1
};

#define GET_PARAM_LOOP_COUNT 10

void SpinQuicGetRandomParam(HQUIC Handle)
{
    for (uint32_t i = 0; i < GET_PARAM_LOOP_COUNT; ++i) {
        QUIC_PARAM_LEVEL Level = (QUIC_PARAM_LEVEL)GetRandom(5);
        uint32_t Param = (uint32_t)GetRandom(ParamCounts[Level] + 1);

        uint8_t OutBuffer[200];
        uint32_t OutBufferLength = (uint32_t)GetRandom(sizeof(OutBuffer) + 1);

        MsQuic->GetParam(
            (GetRandom(10) == 0) ? nullptr : Handle,
            Level,
            Param,
            &OutBufferLength,
            (GetRandom(10) == 0) ? nullptr : OutBuffer);
    }
}

void Spin(LockableVector<HQUIC>& Connections, std::vector<HQUIC>* Listeners = nullptr)
{
    bool IsServer = Listeners != nullptr;

    uint64_t OpCount = 0;
    while (++OpCount != Settings.MaxOperationCount &&
        CxPlatTimeDiff64(StartTimeMs, CxPlatTimeMs64()) < Settings.RunTimeMs) {

        if (Listeners) {
            auto Value = GetRandom(100);
            if (Value >= 90) {
                for (auto &Listener : *Listeners) {
                    MsQuic->ListenerStop(Listener);
                }
            } else if (Value >= 40) {
                for (auto &Listener : *Listeners) {
                    QUIC_ADDR sockAddr = { 0 };
                    QuicAddrSetFamily(&sockAddr, GetRandom(2) ? QUIC_ADDRESS_FAMILY_INET : QUIC_ADDRESS_FAMILY_UNSPEC);
                    QuicAddrSetPort(&sockAddr, GetRandomFromVector(Settings.Ports));
                    MsQuic->ListenerStart(Listener, &Alpns[GetRandom(AlpnCount)], 1, &sockAddr);
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

        switch (GetRandom(SpinQuicAPICallCount)) {
        case SpinQuicAPICallConnectionOpen:
            if (!IsServer) {
                auto ctx = new SpinQuicConnection();
                if (ctx == nullptr) continue;

                HQUIC Connection;
                QUIC_STATUS Status = MsQuic->ConnectionOpen(Registration, SpinQuicHandleConnectionEvent, ctx, &Connection);
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
            HQUIC Configuration = GetRandomFromVector(ClientConfigurations);
            MsQuic->ConnectionStart(Connection, Configuration, QUIC_ADDRESS_FAMILY_INET, Settings.ServerName, GetRandomFromVector(Settings.Ports));
            break;
        }
        case SpinQuicAPICallConnectionShutdown: {
            auto Connection = Connections.TryGetRandom();
            BAIL_ON_NULL_CONNECTION(Connection);
            MsQuic->ConnectionShutdown(Connection, (QUIC_CONNECTION_SHUTDOWN_FLAGS)GetRandom(2), 0);
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
            QUIC_STATUS Status = MsQuic->StreamOpen(Connection, (QUIC_STREAM_OPEN_FLAGS)GetRandom(2), SpinQuicHandleStreamEvent, nullptr, &Stream);
            if (QUIC_SUCCEEDED(Status)) {
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
                MsQuic->StreamStart(Stream, (QUIC_STREAM_START_FLAGS)GetRandom(2) | QUIC_STREAM_START_FLAG_ASYNC);
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
                auto Buffer = &Buffers[GetRandom(BufferCount)];
                MsQuic->StreamSend(Stream, Buffer, 1, (QUIC_SEND_FLAGS)GetRandom(16), nullptr);
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
                MsQuic->StreamReceiveSetEnabled(Stream, GetRandom(2) == 0);
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
                auto BytesRemaining = MsQuic->GetContext(Stream);
                if (BytesRemaining != nullptr && GetRandom(10) == 0) {
                    auto BytesConsumed = GetRandom((uint64_t)BytesRemaining);
                    MsQuic->SetContext(Stream, (void*)((uint64_t)BytesRemaining - BytesConsumed));
                    MsQuic->StreamReceiveComplete(Stream, BytesConsumed);
                } else {
                    MsQuic->SetContext(Stream, nullptr);
                    MsQuic->StreamReceiveComplete(Stream, (uint64_t)BytesRemaining);
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
                MsQuic->StreamShutdown(Stream, (QUIC_STREAM_SHUTDOWN_FLAGS)GetRandom(16), 0);
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
            MsQuic->StreamClose(Stream);
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
                    grab the same log when cleaning up the connections' streams.

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
            auto Buffer = &Buffers[GetRandom(BufferCount)];
            MsQuic->DatagramSend(Connection, Buffer, 1, (QUIC_SEND_FLAGS)GetRandom(8), nullptr);
        }
        default:
            break;
        }
    }
}

CXPLAT_THREAD_CALLBACK(ServerSpin, Context)
{
    UNREFERENCED_PARAMETER(Context);
    bool InitializeSuccess = false;
    do {
        LockableVector<HQUIC> Connections;
        std::vector<HQUIC> Listeners;

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
            MsQuic->ConfigurationOpen(
                Registration,
                Alpns,
                AlpnCount,
                &QuicSettings,
                sizeof(QuicSettings),
                nullptr,
                &ServerConfiguration))) {
            goto ConfigOpenFail;
        }

        ASSERT_ON_NOT(ServerConfiguration);

        if (!QUIC_SUCCEEDED(
            MsQuic->ConfigurationLoadCredential(
                ServerConfiguration,
                CredConfig))) {
            goto CredLoadFail;
        }

        for (uint32_t i = 0; i < AlpnCount; ++i) {
            for (auto &pt : Settings.Ports) {
                HQUIC Listener;
                if (!QUIC_SUCCEEDED(
                    (MsQuic->ListenerOpen(Registration, SpinQuicServerHandleListenerEvent, &Connections, &Listener)))) {
                    goto CleanupListeners;
                }

                QUIC_ADDR sockAddr = { 0 };
                QuicAddrSetFamily(&sockAddr, GetRandom(2) ? QUIC_ADDRESS_FAMILY_INET : QUIC_ADDRESS_FAMILY_UNSPEC);
                QuicAddrSetPort(&sockAddr, pt);

                if (!QUIC_SUCCEEDED(MsQuic->ListenerStart(Listener, &Alpns[i], 1, &sockAddr))) {
                    MsQuic->ListenerClose(Listener);
                    goto CleanupListeners;
                }
                Listeners.push_back(Listener);
            }
        }

        //
        // Run
        //

        InitializeSuccess = true;
        Spin(Connections, &Listeners);

        //
        // Clean up
        //
CleanupListeners:
        while (Listeners.size() > 0) {
            auto Listener = Listeners.back();
            Listeners.pop_back();
            MsQuic->ListenerClose(Listener);
        }

        for (auto &Connection : Connections) {
            MsQuic->ConnectionShutdown(Connection, QUIC_CONNECTION_SHUTDOWN_FLAG_SILENT, 0);
        }

        while (Connections.size() > 0) {
            auto Connection = Connections.back();
            Connections.pop_back();
            delete SpinQuicConnection::Get(Connection);
        }

CredLoadFail:
        MsQuic->ConfigurationClose(ServerConfiguration);
ConfigOpenFail:
        CxPlatFreeSelfSignedCert(CredConfig);
    } while (!InitializeSuccess);

    CXPLAT_THREAD_RETURN(0);
}

CXPLAT_THREAD_CALLBACK(ClientSpin, Context)
{
    UNREFERENCED_PARAMETER(Context);
    LockableVector<HQUIC> Connections;

    //
    // Run
    //

    Spin(Connections);

    //
    // Clean up
    //

    for (auto &Connection : Connections) {
        MsQuic->ConnectionShutdown(Connection, QUIC_CONNECTION_SHUTDOWN_FLAG_SILENT, 0);
    }

    while (Connections.size() > 0) {
        auto Connection = Connections.back();
        Connections.pop_back();
        delete SpinQuicConnection::Get(Connection);
    }

    CXPLAT_THREAD_RETURN(0);
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
    DatapathHookReceiveCallback, DatapathHookSendCallback
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

int
QUIC_MAIN_EXPORT
main(int argc, char **argv)
{
    if (argc < 2) {
        PrintHelpText();
    }

    bool RunServer = false;
    bool RunClient = false;

    if (strcmp(argv[1], "server") == 0) {
        RunServer = true;
    } else if (strcmp(argv[1], "client") == 0) {
        RunClient = true;
    } else if (strcmp(argv[1], "both") == 0) {
        RunServer = true;
        RunClient = true;
    } else {
        printf("Must specify one of the following as the first argument: 'server' 'client' 'both'\n\n");
        PrintHelpText();
    }

    CxPlatSystemLoad();
    CxPlatInitialize();

    uint32_t SessionCount = 4;
    uint32_t RepeatCount = 1;

    Settings.RunTimeMs = 60000;
    Settings.ServerName = "127.0.0.1";
    Settings.Ports = std::vector<uint16_t>({9998, 9999});
    Settings.AlpnPrefix = "spin";
    Settings.MaxOperationCount = UINT64_MAX;
    Settings.LossPercent = 1;
    Settings.AllocFailDenominator = 0;

    TryGetValue(argc, argv, "timeout", &Settings.RunTimeMs);
    TryGetValue(argc, argv, "max_ops", &Settings.MaxOperationCount);
    TryGetValue(argc, argv, "loss", &Settings.LossPercent);
    TryGetValue(argc, argv, "repeat_count", &RepeatCount);
    TryGetValue(argc, argv, "alloc_fail", &Settings.AllocFailDenominator);

    if (RepeatCount == 0) {
        printf("Must specify a non 0 repeat count\n");
        PrintHelpText();
    }

    if (RunClient) {
        uint16_t dstPort = 0;
        if (TryGetValue(argc, argv, "dstport", &dstPort)) {
            Settings.Ports = std::vector<uint16_t>({dstPort});
        }
        TryGetValue(argc, argv, "target", &Settings.ServerName);
        if (TryGetValue(argc, argv, "alpn", &Settings.AlpnPrefix)) {
            SessionCount = 1; // Default session count to 1 if ALPN explicitly specified.
        }
        TryGetValue(argc, argv, "sessions", &SessionCount);
    }

    uint32_t RngSeed = 0;
    if (!TryGetValue(argc, argv, "seed", &RngSeed)) {
        CxPlatRandom(sizeof(RngSeed), &RngSeed);
    }
    printf("Using seed value: %u\n", RngSeed);
    srand(RngSeed);

    SpinQuicWatchdog Watchdog((uint32_t)Settings.RunTimeMs + WATCHDOG_WIGGLE_ROOM);

    Settings.RunTimeMs = Settings.RunTimeMs / RepeatCount;

    for (uint32_t i = 0; i < RepeatCount; i++) {

        for (size_t j = 0; j < BufferCount; ++j) {
            Buffers[j].Length = MaxBufferSizes[j]; // TODO - Randomize?
            Buffers[j].Buffer = (uint8_t*)malloc(Buffers[j].Length);
            ASSERT_ON_NOT(Buffers[j].Buffer);
        }

        QUIC_STATUS Status = MsQuicOpen(&MsQuic);
        if (QUIC_FAILED(Status)) {
            //
            // This may fail on subsequent iterations, but not on the first.
            //
            CXPLAT_DBG_ASSERT(i > 0);
            continue;
        }

        if (Settings.AllocFailDenominator > 0) {
            if (QUIC_FAILED(
                MsQuic->SetParam(
                    nullptr,
                    QUIC_PARAM_LEVEL_GLOBAL,
                    QUIC_PARAM_GLOBAL_ALLOC_FAIL_DENOMINATOR,
                    sizeof(Settings.AllocFailDenominator),
                    &Settings.AllocFailDenominator))) {
                printf("Setting Allocation Failure Denominator failed.\n");
            }
        }

        if (Settings.LossPercent != 0) {
            QUIC_TEST_DATAPATH_HOOKS* Value = &DataPathHooks;
            if (QUIC_FAILED(
                MsQuic->SetParam(
                    nullptr,
                    QUIC_PARAM_LEVEL_GLOBAL,
                    QUIC_PARAM_GLOBAL_TEST_DATAPATH_HOOKS,
                    sizeof(Value),
                    &Value))) {
                printf("Setting Datapath hooks failed.\n");
            }
        }

        QUIC_SETTINGS QuicSettings{0};
        CXPLAT_THREAD_CONFIG Config = { 0 };

        if (0 == GetRandom(4)) {
            uint16_t RetryMemoryPercent = 0;
            if (!QUIC_SUCCEEDED(MsQuic->SetParam(nullptr, QUIC_PARAM_LEVEL_GLOBAL, QUIC_PARAM_GLOBAL_RETRY_MEMORY_PERCENT, sizeof(RetryMemoryPercent), &RetryMemoryPercent))) {
                goto Cleanup;
            }
        }

        if (0 == GetRandom(4)) {
            uint16_t LoadBalancingMode = QUIC_LOAD_BALANCING_SERVER_ID_IP;
            if (!QUIC_SUCCEEDED(MsQuic->SetParam(nullptr, QUIC_PARAM_LEVEL_GLOBAL, QUIC_PARAM_GLOBAL_LOAD_BALACING_MODE, sizeof(LoadBalancingMode), &LoadBalancingMode))) {
                goto Cleanup;
            }
        }

        QUIC_REGISTRATION_CONFIG RegConfig;
        RegConfig.AppName = "spinquic";
        RegConfig.ExecutionProfile = (QUIC_EXECUTION_PROFILE)GetRandom(4);

        if (!QUIC_SUCCEEDED(MsQuic->RegistrationOpen(&RegConfig, &Registration))) {
            goto Cleanup;
        }

        Alpns = (QUIC_BUFFER*)malloc(sizeof(QUIC_BUFFER) * SessionCount);
        ASSERT_ON_NOT(Alpns);
        AlpnCount = SessionCount;

        for (uint32_t j = 0; j < SessionCount; j++) {
            Alpns[j].Length = (uint32_t)strlen(Settings.AlpnPrefix);
            if (j != 0) {
                Alpns[j].Length++;
            }
            Alpns[j].Buffer = (uint8_t*)malloc(Alpns[j].Length);
            ASSERT_ON_NOT(Alpns[j].Buffer);
            memcpy(Alpns[j].Buffer, Settings.AlpnPrefix, Alpns[j].Length);
            if (j != 0) {
                Alpns[j].Buffer[Alpns[j].Length-1] = (uint8_t)j;
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

        for (uint32_t j = 0; j < AlpnCount; j++) {
            HQUIC Configuration;
            if (!QUIC_SUCCEEDED(MsQuic->ConfigurationOpen(Registration, &Alpns[j], 1, &QuicSettings, sizeof(QuicSettings), nullptr, &Configuration))) {
                continue;
            }
            if (!QUIC_SUCCEEDED(MsQuic->ConfigurationLoadCredential(Configuration, &CredConfig))) {
                MsQuic->ConfigurationClose(Configuration);
                continue;
            }
            ClientConfigurations.push_back(Configuration);
        }

        CXPLAT_THREAD Threads[2];

        StartTimeMs = CxPlatTimeMs64();

        //
        // Start worker threads
        //

        if (RunServer) {
            Config.Name = "spin_server";
            Config.Callback = ServerSpin;
            ASSERT_ON_FAILURE(CxPlatThreadCreate(&Config, &Threads[0]));
        }

        if (RunClient) {
            Config.Name = "spin_client";
            Config.Callback = ClientSpin;
            ASSERT_ON_FAILURE(CxPlatThreadCreate(&Config, &Threads[1]));
        }

        //
        // Wait on worker threads
        //

        if (RunClient) {
            CxPlatThreadWait(&Threads[1]);
            CxPlatThreadDelete(&Threads[1]);
        }

        if (RunServer) {
            CxPlatThreadWait(&Threads[0]);
            CxPlatThreadDelete(&Threads[0]);
        }

        //
        // Clean up
        //

Cleanup:
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
            Alpns = nullptr;
        }

        if (Registration) {
            MsQuic->RegistrationClose(Registration);
            Registration = nullptr;
        }

        DumpMsQuicPerfCounters(MsQuic);

        MsQuicClose(MsQuic);
        MsQuic = nullptr;

        for (size_t j = 0; j < BufferCount; ++j) {
            free(Buffers[j].Buffer);
            Buffers[j].Buffer = nullptr;
        }
    }

    return 0;
}
