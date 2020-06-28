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
#include <msquichelper.h>

#define EXIT_ON_FAILURE(x) do { \
    auto _Status = x; \
    if (QUIC_FAILED(_Status)) { \
       printf("%s:%d %s failed!\n", __FILE__, __LINE__, #x); \
       exit(10); \
    } \
} while (0);

#define EXIT_ON_NOT(x) do { \
    if (!(x)) { \
       printf("%s:%d !'%s' !\n", __FILE__, __LINE__, #x); \
       exit(10); \
    } \
} while (0);

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
    QUIC_THREAD WatchdogThread;
    QUIC_EVENT ShutdownEvent;
    uint32_t TimeoutMs;
    static
    QUIC_THREAD_CALLBACK(WatchdogThreadCallback, Context) {
        auto This = (SpinQuicWatchdog*)Context;
        if (!QuicEventWaitWithTimeout(This->ShutdownEvent, This->TimeoutMs)) {
            printf("Watchdog timeout fired!\n");
            QUIC_FRE_ASSERTMSG(FALSE, "Watchdog timeout fired!");
        }
        QUIC_THREAD_RETURN(0);
    }
public:
    SpinQuicWatchdog(uint32_t WatchdogTimeoutMs) : TimeoutMs(WatchdogTimeoutMs) {
        QuicEventInitialize(&ShutdownEvent, TRUE, FALSE);
        QUIC_THREAD_CONFIG Config = { 0 };
        Config.Name = "spin_watchdog";
        Config.Callback = WatchdogThreadCallback;
        Config.Context = this;
        EXIT_ON_FAILURE(QuicThreadCreate(&Config, &WatchdogThread));
    }
    ~SpinQuicWatchdog() {
        QuicEventSet(ShutdownEvent);
        QuicThreadWait(&WatchdogThread);
        QuicThreadDelete(&WatchdogThread);
        QuicEventUninitialize(ShutdownEvent);
    }
};

static uint64_t StartTimeMs;
static const QUIC_API_TABLE* MsQuic;
static HQUIC Registration;
static QUIC_SEC_CONFIG* GlobalSecurityConfig;
static std::vector<HQUIC> Sessions;

const uint32_t MaxBufferSizes[] = { 1, 2, 32, 50, 256, 500, 1000, 1024, 1400, 5000, 10000, 64000, 10000000 };
static const size_t BufferCount = ARRAYSIZE(MaxBufferSizes);
static QUIC_BUFFER Buffers[BufferCount];

typedef enum {
    SpinQuicAPICallCreateConnection = 0,
    SpinQuicAPICallStartConnection,
    SpinQuicAPICallShutdownConnection,
    SpinQuicAPICallCloseConnection,
    SpinQuicAPICallStreamOpen,
    SpinQuicAPICallStreamStart,
    SpinQuicAPICallStreamSend,
    SpinQuicAPICallStreamShutdown,
    SpinQuicAPICallStreamClose,
    SpinQuicAPICallSetParamSession,
    SpinQuicAPICallSetParamConnection,
    SpinQuicAPICallDatagramSend,
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
} Settings;

extern "C" void QuicTraceRundown(void) { }

QUIC_STATUS QUIC_API SpinQuicHandleStreamEvent(HQUIC Stream, void * /* Context */, QUIC_STREAM_EVENT *Event)
{
    switch (Event->Type) {
    case QUIC_STREAM_EVENT_PEER_SEND_SHUTDOWN:
        MsQuic->StreamShutdown(Stream, (QUIC_STREAM_SHUTDOWN_FLAGS)GetRandom(16), 0);
        break;
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
            DataLength = GetRandom(999) + 1;
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

void QUIC_API SpinQuicGetSecConfigComplete(_In_opt_ void *Context, _In_ QUIC_STATUS /* Status */, _In_opt_ QUIC_SEC_CONFIG *SecConfig)
{
    GlobalSecurityConfig = SecConfig;
    QuicEventSet(*(QUIC_EVENT*)Context);
}

QUIC_STATUS QUIC_API SpinQuicServerHandleListenerEvent(HQUIC /* Listener */, void* Context , QUIC_LISTENER_EVENT* Event)
{
    auto& Connections = *(LockableVector<HQUIC>*)(Context);

    switch (Event->Type) {
    case QUIC_LISTENER_EVENT_NEW_CONNECTION: {
        Event->NEW_CONNECTION.SecurityConfig = GlobalSecurityConfig;
        MsQuic->SetCallbackHandler(Event->NEW_CONNECTION.Connection, (void*)SpinQuicHandleConnectionEvent, nullptr);
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

void SpinQuicSetRandomSesssioParam(HQUIC Session)
{
    SetParamHelper Helper(QUIC_PARAM_LEVEL_SESSION);
    uint8_t TlsTicket[44];

    switch (GetRandom(8)) {
    case QUIC_PARAM_SESSION_TLS_TICKET_KEY:                         // uint8_t[44]
        QuicRandom(sizeof(TlsTicket), TlsTicket);
        Helper.SetPtr(QUIC_PARAM_SESSION_TLS_TICKET_KEY, TlsTicket, sizeof(TlsTicket));
        break;
    case QUIC_PARAM_SESSION_PEER_BIDI_STREAM_COUNT:                 // uint16_t
        Helper.SetUint16(QUIC_PARAM_SESSION_PEER_BIDI_STREAM_COUNT, GetRandom(10));
        break;
    case QUIC_PARAM_SESSION_PEER_UNIDI_STREAM_COUNT:                // uint16_t
        Helper.SetUint16(QUIC_PARAM_SESSION_PEER_UNIDI_STREAM_COUNT, GetRandom(10));
        break;
    case QUIC_PARAM_SESSION_IDLE_TIMEOUT:                           // uint64_t - milliseconds
        Helper.SetUint64(QUIC_PARAM_SESSION_IDLE_TIMEOUT, GetRandom(32000));
        break;
    case QUIC_PARAM_SESSION_DISCONNECT_TIMEOUT:                     // uint32_t - milliseconds
        Helper.SetUint32(QUIC_PARAM_SESSION_DISCONNECT_TIMEOUT, GetRandom(32000));
        break;
    case QUIC_PARAM_SESSION_MAX_BYTES_PER_KEY:                      // uint64_t - bytes
        Helper.SetUint64(QUIC_PARAM_SESSION_MAX_BYTES_PER_KEY, GetRandom(32000));
        break;
    case QUIC_PARAM_SESSION_MIGRATION_ENABLED:                      // uint8_t (BOOLEAN)
        Helper.SetUint8(QUIC_PARAM_SESSION_MIGRATION_ENABLED, GetRandom(2));
        break;
    case QUIC_PARAM_SESSION_DATAGRAM_RECEIVE_ENABLED:               // uint8_t (BOOLEAN)
        Helper.SetUint8(QUIC_PARAM_SESSION_DATAGRAM_RECEIVE_ENABLED, GetRandom(2));
        break;
    default:
        break;
    }

    Helper.Apply(Session);
}

void SpinQuicSetRandomConnectionParam(HQUIC Connection)
{
    SetParamHelper Helper(QUIC_PARAM_LEVEL_CONNECTION);

    switch (GetRandom(23)) {
    case QUIC_PARAM_CONN_QUIC_VERSION:                              // uint32_t
        Helper.SetUint32(QUIC_PARAM_CONN_QUIC_VERSION, GetRandom(UINT32_MAX));
        break;
    case QUIC_PARAM_CONN_LOCAL_ADDRESS:                             // QUIC_ADDR
        break; // TODO - Add support here
    case QUIC_PARAM_CONN_REMOTE_ADDRESS:                            // QUIC_ADDR
        break; // Get Only
    case QUIC_PARAM_CONN_IDLE_TIMEOUT:                              // uint64_t - milliseconds
        Helper.SetUint64(QUIC_PARAM_CONN_IDLE_TIMEOUT, GetRandom(20000));
        break;
    case QUIC_PARAM_CONN_PEER_BIDI_STREAM_COUNT:                    // uint16_t
        Helper.SetUint16(QUIC_PARAM_CONN_PEER_BIDI_STREAM_COUNT, GetRandom(50000));
        break;
    case QUIC_PARAM_CONN_PEER_UNIDI_STREAM_COUNT:                   // uint16_t
        Helper.SetUint16(QUIC_PARAM_CONN_PEER_UNIDI_STREAM_COUNT, GetRandom(50000));
        break;
    case QUIC_PARAM_CONN_LOCAL_BIDI_STREAM_COUNT:                   // uint16_t
        break; // Get Only
    case QUIC_PARAM_CONN_LOCAL_UNIDI_STREAM_COUNT:                  // uint16_t
        break; // Get Only
    case QUIC_PARAM_CONN_CLOSE_REASON_PHRASE:                       // char[]
        Helper.SetPtr(QUIC_PARAM_CONN_CLOSE_REASON_PHRASE, "ABCDEFGHI\x00\x00\x00\x00\x00", 10);
        break;
    case QUIC_PARAM_CONN_STATISTICS:                                // QUIC_STATISTICS
        break; // Get Only
    case QUIC_PARAM_CONN_STATISTICS_PLAT:                           // QUIC_STATISTICS
        break; // Get Only
    case QUIC_PARAM_CONN_CERT_VALIDATION_FLAGS:                     // uint32_t
        Helper.SetUint32(QUIC_PARAM_CONN_CERT_VALIDATION_FLAGS, QUIC_CERTIFICATE_FLAG_DISABLE_CERT_VALIDATION);
        break;
    case QUIC_PARAM_CONN_KEEP_ALIVE:                                // uint32_t - milliseconds
        Helper.SetUint32(QUIC_PARAM_CONN_KEEP_ALIVE, GetRandom(200));
        break;
    case QUIC_PARAM_CONN_DISCONNECT_TIMEOUT:                        // uint32_t - milliseconds
        Helper.SetUint32(QUIC_PARAM_CONN_DISCONNECT_TIMEOUT, GetRandom(200));
        break;
    case QUIC_PARAM_CONN_SEND_BUFFERING:                            // uint8_t (BOOLEAN)
        Helper.SetUint8(QUIC_PARAM_CONN_SEND_BUFFERING, GetRandom(2));
        break;
    case QUIC_PARAM_CONN_SEND_PACING:                               // uint8_t (BOOLEAN)
        Helper.SetUint8(QUIC_PARAM_CONN_SEND_PACING, GetRandom(2));
        break;
    case QUIC_PARAM_CONN_SHARE_UDP_BINDING:                         // uint8_t (BOOLEAN)
        Helper.SetUint8(QUIC_PARAM_CONN_SHARE_UDP_BINDING, GetRandom(2));
        break;
    case QUIC_PARAM_CONN_IDEAL_PROCESSOR:                           // uint8_t
        break; // Get Only
    case QUIC_PARAM_CONN_MAX_STREAM_IDS:                            // uint64_t[4]
        break; // Get Only
    case QUIC_PARAM_CONN_STREAM_SCHEDULING_SCHEME:                  // QUIC_STREAM_SCHEDULING_SCHEME
        Helper.SetUint32(QUIC_PARAM_CONN_STREAM_SCHEDULING_SCHEME, GetRandom(QUIC_STREAM_SCHEDULING_SCHEME_COUNT));
        break;
    case QUIC_PARAM_CONN_DATAGRAM_RECEIVE_ENABLED:                  // uint8_t (BOOLEAN)
        Helper.SetUint8(QUIC_PARAM_CONN_DATAGRAM_RECEIVE_ENABLED, GetRandom(2));
        break;
    case QUIC_PARAM_CONN_DATAGRAM_SEND_ENABLED:                     // uint8_t (BOOLEAN)
        break; // Get Only
    default:
        break;
    }

    Helper.Apply(Connection);
}

void Spin(LockableVector<HQUIC>& Connections, bool IsServer)
{
    uint64_t OpCount = 0;
    while (++OpCount != Settings.MaxOperationCount &&
        QuicTimeDiff64(StartTimeMs, QuicTimeMs64()) < Settings.RunTimeMs) {

    #define BAIL_ON_NULL_CONNECTION(Connection) \
        if (Connection == nullptr) { \
            if (IsServer) { \
                QuicSleep(100); \
            } \
            continue; \
        }

        switch (GetRandom(SpinQuicAPICallCount)) {
        case SpinQuicAPICallCreateConnection:
            if (!IsServer) {
                auto ctx = new SpinQuicConnection();
                if (ctx == nullptr) continue;

                HQUIC Connection;
                HQUIC Session = GetRandomFromVector(Sessions);
                QUIC_STATUS Status = MsQuic->ConnectionOpen(Session, SpinQuicHandleConnectionEvent, ctx, &Connection);
                if (QUIC_SUCCEEDED(Status)) {
                    ctx->Set(Connection);
                    if (GetRandom(2)) {
                        uint32_t DisableCertValidation = QUIC_CERTIFICATE_FLAG_DISABLE_CERT_VALIDATION;
                        MsQuic->SetParam(Connection, QUIC_PARAM_LEVEL_CONNECTION, QUIC_PARAM_CONN_CERT_VALIDATION_FLAGS, sizeof(uint32_t), &DisableCertValidation);
                    }
                    Connections.push_back(Connection);
                } else {
                    delete ctx;
                }
            }
            break;
        case SpinQuicAPICallStartConnection: {
            auto Connection = Connections.TryGetRandom();
            BAIL_ON_NULL_CONNECTION(Connection);
            MsQuic->ConnectionStart(Connection, AF_INET, Settings.ServerName, GetRandomFromVector(Settings.Ports));
            break;
        }
        case SpinQuicAPICallShutdownConnection: {
            auto Connection = Connections.TryGetRandom();
            BAIL_ON_NULL_CONNECTION(Connection);
            MsQuic->ConnectionShutdown(Connection, (QUIC_CONNECTION_SHUTDOWN_FLAGS)GetRandom(2), 0);
            break;
        }
        case SpinQuicAPICallCloseConnection: {
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
                MsQuic->StreamSend(Stream, Buffer, 1, (QUIC_SEND_FLAGS)GetRandom(8), nullptr);
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
        case SpinQuicAPICallSetParamSession: {
            auto Session = GetRandomFromVector(Sessions);
            SpinQuicSetRandomSesssioParam(Session);
            break;
        }
        case SpinQuicAPICallSetParamConnection: {
            auto Connection = Connections.TryGetRandom();
            BAIL_ON_NULL_CONNECTION(Connection);
            SpinQuicSetRandomConnectionParam(Connection);
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

QUIC_THREAD_CALLBACK(ServerSpin, Context)
{
    UNREFERENCED_PARAMETER(Context);
    LockableVector<HQUIC> Connections;

    //
    // Setup
    //

    auto SelfSignedCertParams = QuicPlatGetSelfSignedCert(QUIC_SELF_SIGN_CERT_USER);
    EXIT_ON_NOT(SelfSignedCertParams);

    QUIC_EVENT Event;
    QuicEventInitialize(&Event, FALSE, FALSE);
    EXIT_ON_FAILURE(
        MsQuic->SecConfigCreate(
            Registration,
            (QUIC_SEC_CONFIG_FLAGS)SelfSignedCertParams->Flags,
            SelfSignedCertParams->Certificate,
            SelfSignedCertParams->Principal,
            &Event,
            SpinQuicGetSecConfigComplete));
    QuicEventWaitForever(Event);
    QuicEventUninitialize(Event);

    EXIT_ON_NOT(GlobalSecurityConfig);

    std::vector<HQUIC> Listeners;
    for (auto &session : Sessions) {
        for (auto &pt : Settings.Ports) {
            HQUIC Listener;
            EXIT_ON_FAILURE(MsQuic->ListenerOpen(session, SpinQuicServerHandleListenerEvent, &Connections, &Listener));

            QUIC_ADDR sockAddr = { 0 };
            QuicAddrSetFamily(&sockAddr, GetRandom(2) ? AF_INET : AF_UNSPEC);
            QuicAddrSetPort(&sockAddr, pt);

            EXIT_ON_FAILURE(MsQuic->ListenerStart(Listener, &sockAddr));
            Listeners.push_back(Listener);
        }
    }

    //
    // Run
    //

    Spin(Connections, true);

    //
    // Clean up
    //

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

    MsQuic->SecConfigDelete(GlobalSecurityConfig);
    QuicPlatFreeSelfSignedCert(SelfSignedCertParams);

    QUIC_THREAD_RETURN(0);
}

QUIC_THREAD_CALLBACK(ClientSpin, Context)
{
    UNREFERENCED_PARAMETER(Context);
    LockableVector<HQUIC> Connections;

    //
    // Run
    //

    Spin(Connections, false);

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

    QUIC_THREAD_RETURN(0);
}

BOOLEAN QUIC_API DatapathHookReceiveCallback(struct QUIC_RECV_DATAGRAM* /* Datagram */)
{
    uint8_t RandomValue;
    QuicRandom(sizeof(RandomValue), &RandomValue);
    return (RandomValue % 100) < Settings.LossPercent;
}

BOOLEAN QUIC_API DatapathHookSendCallback(QUIC_ADDR* /* RemoteAddress */, QUIC_ADDR* /* LocalAddress */, struct QUIC_DATAPATH_SEND_CONTEXT* /* SendContext */)
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

    QuicPlatformSystemLoad();
    QuicPlatformInitialize();

    uint32_t SessionCount = 4;
    uint32_t RepeatCount = 1;

    Settings.RunTimeMs = 60000;
    Settings.ServerName = "127.0.0.1";
    Settings.Ports = std::vector<uint16_t>({9998, 9999});
    Settings.AlpnPrefix = "spin";
    Settings.MaxOperationCount = UINT64_MAX;
    Settings.LossPercent = 1;

    TryGetValue(argc, argv, "timeout", &Settings.RunTimeMs);
    TryGetValue(argc, argv, "max_ops", &Settings.MaxOperationCount);
    TryGetValue(argc, argv, "loss", &Settings.LossPercent);
    TryGetValue(argc, argv, "repeat_count", &RepeatCount);

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

    uint32_t RngSeed = 6;
    TryGetValue(argc, argv, "seed", &RngSeed);
    srand(RngSeed);

    SpinQuicWatchdog Watchdog((uint32_t)Settings.RunTimeMs + WATCHDOG_WIGGLE_ROOM);

    Settings.RunTimeMs = Settings.RunTimeMs / RepeatCount;

    for (uint32_t i = 0; i < RepeatCount; i++) {

        for (size_t i = 0; i < BufferCount; ++i) {
            Buffers[i].Length = MaxBufferSizes[i]; // TODO - Randomize?
            Buffers[i].Buffer = (uint8_t*)malloc(Buffers[i].Length);
            EXIT_ON_NOT(Buffers[i].Buffer);
        }

        EXIT_ON_FAILURE(MsQuicOpen(&MsQuic));

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

        const QUIC_REGISTRATION_CONFIG RegConfig = { "spinquic", QUIC_EXECUTION_PROFILE_LOW_LATENCY };
        EXIT_ON_FAILURE(MsQuic->RegistrationOpen(&RegConfig, &Registration));

        if (SessionCount == 1) {
            QUIC_BUFFER AlpnBuffer;
            AlpnBuffer.Length = (uint32_t)strlen(Settings.AlpnPrefix);
            AlpnBuffer.Buffer = (uint8_t*)Settings.AlpnPrefix;

            HQUIC Session;
            EXIT_ON_FAILURE(MsQuic->SessionOpen(Registration, &AlpnBuffer, 1, nullptr, &Session));
            Sessions.push_back(Session);

            // Configure Session
            auto PeerStreamCount = GetRandom((uint16_t)10);
            EXIT_ON_FAILURE(MsQuic->SetParam(Session, QUIC_PARAM_LEVEL_SESSION, QUIC_PARAM_SESSION_PEER_BIDI_STREAM_COUNT, sizeof(PeerStreamCount), &PeerStreamCount));
            EXIT_ON_FAILURE(MsQuic->SetParam(Session, QUIC_PARAM_LEVEL_SESSION, QUIC_PARAM_SESSION_PEER_UNIDI_STREAM_COUNT, sizeof(PeerStreamCount), &PeerStreamCount));

        } else {
            QUIC_BUFFER AlpnBuffer;
            AlpnBuffer.Length = (uint32_t)strlen(Settings.AlpnPrefix) + 1; // You can't have more than 2^8 SessionCount. :)
            AlpnBuffer.Buffer = (uint8_t*)malloc(AlpnBuffer.Length);
            EXIT_ON_NOT(AlpnBuffer.Buffer);
            memcpy(AlpnBuffer.Buffer, Settings.AlpnPrefix, AlpnBuffer.Length);

            for (uint32_t i = 0; i < SessionCount; i++) {

                AlpnBuffer.Buffer[AlpnBuffer.Length-1] = (uint8_t)i;

                HQUIC Session;
                EXIT_ON_FAILURE(MsQuic->SessionOpen(Registration, &AlpnBuffer, 1, nullptr, &Session));
                Sessions.push_back(Session);

                // Configure Session
                auto PeerStreamCount = GetRandom((uint16_t)10);
                EXIT_ON_FAILURE(MsQuic->SetParam(Session, QUIC_PARAM_LEVEL_SESSION, QUIC_PARAM_SESSION_PEER_BIDI_STREAM_COUNT, sizeof(PeerStreamCount), &PeerStreamCount));
                EXIT_ON_FAILURE(MsQuic->SetParam(Session, QUIC_PARAM_LEVEL_SESSION, QUIC_PARAM_SESSION_PEER_UNIDI_STREAM_COUNT, sizeof(PeerStreamCount), &PeerStreamCount));
            }

            free(AlpnBuffer.Buffer);
        }

        QUIC_THREAD Threads[2];
        QUIC_THREAD_CONFIG Config = { 0 };

        StartTimeMs = QuicTimeMs64();

        //
        // Start worker threads
        //

        if (RunServer) {
            Config.Name = "spin_server";
            Config.Callback = ServerSpin;
            EXIT_ON_FAILURE(QuicThreadCreate(&Config, &Threads[0]));
        }

        if (RunClient) {
            Config.Name = "spin_client";
            Config.Callback = ClientSpin;
            EXIT_ON_FAILURE(QuicThreadCreate(&Config, &Threads[1]));
        }

        //
        // Wait on worker threads
        //

        if (RunClient) {
            QuicThreadWait(&Threads[1]);
            QuicThreadDelete(&Threads[1]);
        }

        if (RunServer) {
            QuicThreadWait(&Threads[0]);
            QuicThreadDelete(&Threads[0]);
        }

        //
        // Clean up
        //

        while (Sessions.size() > 0) {
            auto Session = Sessions.back();
            Sessions.pop_back();
            MsQuic->SessionClose(Session);
        }

        MsQuic->RegistrationClose(Registration);
        Registration = nullptr;

        MsQuicClose(MsQuic);
        MsQuic = nullptr;

        for (size_t i = 0; i < BufferCount; ++i) {
            free(Buffers[i].Buffer);
        }
    }

    return 0;
}
