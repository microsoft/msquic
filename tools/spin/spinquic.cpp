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

#define QUIC_TEST_APIS 1 // Needed to self signed cert API
#include <msquichelper.h>

// Replace these with random data?
const char pkt0[] = "AAAAAAAAAAA";
const char pkt1[] = "\x01";

const QUIC_BUFFER Buffers[2] = {
    { ARRAYSIZE(pkt0) - 1, (uint8_t*)pkt0 },
    { ARRAYSIZE(pkt1) - 1, (uint8_t*)pkt1 }
};

#if 1
#define PRINT(fmt, ...) printf(fmt, ##__VA_ARGS__)
#else
#define PRINT(fmt, ...)
#endif

#define EXIT_ON_FAILURE(x) do { \
    auto _Status = x; \
    if (QUIC_FAILED(_Status)) { \
       printf("%s:%d %s failed!\n", __FILE__, __LINE__, #x); \
       exit(10); \
    } \
} while (0);

template<typename T>
T& GetRandomFromVector(std::vector<T> &vec) {
    return vec.at(rand() % vec.size());
}

template<typename T>
T GetRandom(T upper_bound) {
    return (T)(rand() % (int)upper_bound);
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

static uint64_t StartTimeMs;
static QUIC_API_V1* MsQuic;
static HQUIC Registration;
static QUIC_SEC_CONFIG* GlobalSecurityConfig;
static std::vector<HQUIC> Sessions;

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
        PRINT("MsQuic->ConnectionClose(%p)\n", Connection);
        MsQuic->ConnectionClose(Connection);
    }
    void Set(HQUIC _Connection) {
        Connection = _Connection;
        MsQuic->SetContext(Connection, this);
    }
    void OnShutdownComplete() {
        PRINT("[Shutdown] %p\n", Connection);
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
            StreamsCopy.clear();
        }
        while (StreamsCopy.size() > 0) {
            HQUIC Stream = StreamsCopy.back();
            StreamsCopy.pop_back();
            PRINT("MsQuic->StreamClose(%p)\n", Stream);
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
} Settings;

extern "C" void QuicTraceRundown(void) { }

QUIC_STATUS SpinQuicHandleStreamEvent(HQUIC Stream, void * /* Context */, QUIC_STREAM_EVENT *Event)
{
    switch (Event->Type) {
    case QUIC_STREAM_EVENT_PEER_SEND_SHUTDOWN:
        MsQuic->StreamShutdown(Stream, (QUIC_STREAM_SHUTDOWN_FLAGS)(rand() % 16), 0);
        break;
    default:
        break;
    }

    return QUIC_STATUS_SUCCESS;
}

QUIC_STATUS SpinQuicHandleConnectionEvent(HQUIC Connection, void * /* Context */, QUIC_CONNECTION_EVENT *Event)
{
    switch (Event->Type) {
    case QUIC_CONNECTION_EVENT_SHUTDOWN_COMPLETE:
        PRINT("[Shutdown] %p\n", Connection);
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

void SpinQuicGetSecConfigComplete(_In_opt_ void *Context, _In_ QUIC_STATUS /* Status */, _In_opt_ QUIC_SEC_CONFIG *SecConfig)
{
    GlobalSecurityConfig = SecConfig;
    QuicEventSet(*(QUIC_EVENT*)Context);
}

QUIC_STATUS SpinQuicServerHandleListenerEvent(HQUIC /* Listener */, void* Context , QUIC_LISTENER_EVENT* Event)
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
        PRINT("[Adding] %p\n", Event->NEW_CONNECTION.Connection);
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

void SpinQuicSetRandomConnectionParam(HQUIC Connection)
{
    union {
        uint64_t u64;
        uint32_t u32;
        uint16_t u16;
        uint8_t  u8;
        const char *cp;
    } Param;
    Param.cp = 0;
    uint32_t ParamSize = 0;
    int ParamFlag = -1;

   // Move this to the enum
    switch (rand() % 13) {
    case 0: // QUIC_PARAM_CONN_IDLE_TIMEOUT                    3   // uint64_t - milliseconds
        ParamFlag = QUIC_PARAM_CONN_IDLE_TIMEOUT;
        ParamSize = 8;
        Param.u64 = (rand() % 20000);
        break;
    case 1: // QUIC_PARAM_CONN_PEER_BIDI_STREAM_COUNT          4   // uint16_t
        ParamFlag = QUIC_PARAM_CONN_PEER_BIDI_STREAM_COUNT;
        ParamSize = 2;
        Param.u16 = (rand() % 50000);
        break;
    case 2: // QUIC_PARAM_CONN_PEER_UNIDI_STREAM_COUNT         5   // uint16_t
        ParamFlag = QUIC_PARAM_CONN_PEER_UNIDI_STREAM_COUNT;
        ParamSize = 2;
        Param.u16 = (rand() % 50000);
        break;
    case 3: // QUIC_PARAM_CONN_LOCAL_BIDI_STREAM_COUNT         6   // uint16_t
        ParamFlag = QUIC_PARAM_CONN_LOCAL_BIDI_STREAM_COUNT;
        ParamSize = 2;
        Param.u16 = (rand() % 50000);
        break;
    case 4: // QUIC_PARAM_CONN_LOCAL_UNIDI_STREAM_COUNT        7   // uint16_t
        ParamFlag = QUIC_PARAM_CONN_LOCAL_UNIDI_STREAM_COUNT;
        ParamSize = 2;
        Param.u16 = (rand() % 50000);
        break;
    case 5: // QUIC_PARAM_CONN_CLOSE_REASON_PHRASE             8   // char[]
        ParamFlag = QUIC_PARAM_CONN_CLOSE_REASON_PHRASE;
        ParamSize = 10;
        Param.cp = "ABCDEFGHI\x00\x00\x00\x00\x00";
        break;
    case 6: // QUIC_PARAM_CONN_MAX_STREAM_IDS                  11  // uint64_t[4]
    //    ParamSize = 8 * 4;
    //    ParamFlag = QUIC_PARAM_CONN_MAX_STREAM_IDS;
        break;
    case 7: // QUIC_PARAM_CONN_KEEP_ALIVE                      12  // uint32_t - milliseconds
        ParamFlag = QUIC_PARAM_CONN_KEEP_ALIVE;
        ParamSize = 4;
        Param.u32 = (rand() % 200);
        break;
    case 8: // QUIC_PARAM_CONN_DISCONNECT_TIMEOUT              13  // uint32_t - milliseconds
        ParamFlag = QUIC_PARAM_CONN_DISCONNECT_TIMEOUT;
        ParamSize = 4;
        Param.u32 = (rand() % 200);
        break;
    case 9: // QUIC_PARAM_CONN_SEND_BUFFERING                  15  // uint8_t (BOOLEAN)
        ParamFlag = QUIC_PARAM_CONN_SEND_BUFFERING;
        ParamSize = 1;
        Param.u8 = (rand() % 2);
        break;
    case 10: // QUIC_PARAM_CONN_SEND_PACING                     16  // uint8_t (BOOLEAN)
        ParamFlag = QUIC_PARAM_CONN_SEND_PACING;
        ParamSize = 1;
        Param.u8 = (rand() % 2);
        break;
    case 11: // QUIC_PARAM_CONN_SHARE_UDP_BINDING               17  // uint8_t (BOOLEAN)
        ParamFlag = QUIC_PARAM_CONN_SHARE_UDP_BINDING;
        ParamSize = 1;
        Param.u8 = (rand() % 2);
        break;
    case 12: // QUIC_PARAM_CONN_IDEAL_PROCESSOR                 18  // uint8_t
        ParamFlag = QUIC_PARAM_CONN_IDEAL_PROCESSOR;
        ParamSize = 1;
        Param.u8 = (rand() % 254);
        break;
    default:
        break;
    }

    if (ParamFlag != -1) {
        if (ParamFlag == QUIC_PARAM_CONN_CLOSE_REASON_PHRASE) {
            MsQuic->SetParam(Connection, QUIC_PARAM_LEVEL_CONNECTION, ParamFlag, ParamSize, (void *)Param.cp);
        } else {
            MsQuic->SetParam(Connection, QUIC_PARAM_LEVEL_CONNECTION, ParamFlag, ParamSize, &Param);
        }
    }
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
        case SpinQuicAPICallCreateConnection :
            if (!IsServer) {
                auto ctx = new SpinQuicConnection();
                if (ctx == nullptr) continue;

                HQUIC Connection;
                HQUIC Session = GetRandomFromVector(Sessions);
                PRINT("MsQuic->ConnectionOpen(%p, ...) = ", Session);
                QUIC_STATUS Status = MsQuic->ConnectionOpen(Session, SpinQuicHandleConnectionEvent, ctx, &Connection);
                PRINT("0x%x\n", Status);
                if (QUIC_SUCCEEDED(Status)) {
                    ctx->Set(Connection);
                    PRINT("[Adding] %p\n", Connection);
                    Connections.push_back(Connection);
                } else {
                    delete ctx;
                }
            }
            break;
        case SpinQuicAPICallStartConnection: {
            auto Connection = Connections.TryGetRandom();
            BAIL_ON_NULL_CONNECTION(Connection);
            PRINT("MsQuic->ConnectionStart(%p, ...) = ", Connection);
            QUIC_STATUS Status = MsQuic->ConnectionStart(Connection, AF_INET, Settings.ServerName, GetRandomFromVector(Settings.Ports));
            PRINT("0x%x\n", Status);
            break;
        }
        case SpinQuicAPICallShutdownConnection: {
            auto Connection = Connections.TryGetRandom();
            BAIL_ON_NULL_CONNECTION(Connection);
            PRINT("MsQuic->ConnectionShutdown(%p, ...)\n", Connection);
            MsQuic->ConnectionShutdown(Connection, (QUIC_CONNECTION_SHUTDOWN_FLAGS)(rand() % 2), 0);
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
            PRINT("MsQuic->StreamOpen(%p, ...) = ", Connection);
            QUIC_STATUS Status = MsQuic->StreamOpen(Connection, (QUIC_STREAM_OPEN_FLAGS)(rand() % 2), SpinQuicHandleStreamEvent, nullptr, &Stream);
            PRINT("0x%x\n", Status);
            if (QUIC_SUCCEEDED(Status)) {
                PRINT("[Adding Stream] %p\n", Stream);
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
                PRINT("MsQuic->StreamStart(%p, ...) = ", Stream);
                QUIC_STATUS Status = MsQuic->StreamStart(Stream, (QUIC_STREAM_START_FLAGS)(rand() % 2) | QUIC_STREAM_START_FLAG_ASYNC);
                PRINT("0x%x\n", Status);
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
                PRINT("MsQuic->StreamSend(%p, ...) = ", Stream);
                QUIC_STATUS Status = MsQuic->StreamSend(Stream, Buffers, ARRAYSIZE(Buffers), QUIC_SEND_FLAG_NONE, nullptr);
                PRINT("0x%x\n", Status);
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
                PRINT("MsQuic->StreamShutdown(%p, ...) = ", Stream);
                QUIC_STATUS Status = MsQuic->StreamShutdown(Stream, (QUIC_STREAM_SHUTDOWN_FLAGS)(rand() % 16), 0);
                PRINT("0x%x\n", Status);
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
            PRINT("MsQuic->StreamClose(%p)\n", Stream);
            MsQuic->StreamClose(Stream);
            break;
        }
        case SpinQuicAPICallSetParamSession: {
            auto Session = GetRandomFromVector(Sessions);
            auto PeerStreamCount = GetRandom((uint16_t)10);
            MsQuic->SetParam(
                Session,
                QUIC_PARAM_LEVEL_SESSION,
                (GetRandom(2) == 0 ? QUIC_PARAM_SESSION_PEER_UNIDI_STREAM_COUNT : QUIC_PARAM_SESSION_PEER_BIDI_STREAM_COUNT),
                sizeof(PeerStreamCount),
                &PeerStreamCount);
            break;
        }
        case SpinQuicAPICallSetParamConnection: {
            auto Connection = Connections.TryGetRandom();
            BAIL_ON_NULL_CONNECTION(Connection);
            SpinQuicSetRandomConnectionParam(Connection);
            break;
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
    if (!SelfSignedCertParams) {
        exit(1);
    }

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

    PRINT("Security config: %p\n", GlobalSecurityConfig);
    if (!GlobalSecurityConfig) exit(1);

    std::vector<HQUIC> Listeners;
    for (auto &session : Sessions) {
        for (auto &pt : Settings.Ports) {
            HQUIC Listener;
            PRINT("MsQuic->ListenerOpen(%p, ...) = ", session);
            QUIC_STATUS Status = MsQuic->ListenerOpen(session, SpinQuicServerHandleListenerEvent, &Connections, &Listener);
            PRINT("0x%x\n", Status);

            QUIC_ADDR sockAddr = { 0 };
            QuicAddrSetFamily(&sockAddr, (rand() % 2) ? AF_INET : AF_UNSPEC);
            QuicAddrSetPort(&sockAddr, pt);

            PRINT("MsQuic->ListenerStart(%p, {*:%d}) = ", Listener, pt);
            Status = MsQuic->ListenerStart(Listener, &sockAddr);
            PRINT("0x%x\n", Status);

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

    while (Connections.size() > 0) {
        auto Connection = Connections.back();
        Connections.pop_back();
        delete SpinQuicConnection::Get(Connection);
    }

    QUIC_THREAD_RETURN(0);
}

void PrintHelpText(void)
{
    printf("Usage: spinquic.exe [client/server/both] [options]\n" \
          "\n" \
          "  -alpn:<alpn>         default: 'spin'\n" \
          "  -dstport:<port>      default: 9999\n" \
          "  -max_ops:<count>     default: UINT64_MAX\n"
          "  -seed:<seed>         default: 6\n" \
          "  -sessions:<count>    default: 4\n" \
          "  -target:<ip>         default: '127.0.0.1'\n" \
          "  -timeout:<count_ms>  default: 60000\n" \
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

    Settings.RunTimeMs = 60000;
    Settings.ServerName = "127.0.0.1";
    Settings.Ports = std::vector<uint16_t>({9998, 9999});
    Settings.AlpnPrefix = "spin";
    Settings.MaxOperationCount = UINT64_MAX;

    TryGetValue(argc, argv, "timeout", &Settings.RunTimeMs);
    TryGetValue(argc, argv, "max_ops", &Settings.MaxOperationCount);

    if (RunClient) {
        uint16_t dstPort = 0;
        if (TryGetValue(argc, argv, "dstport", &dstPort)) {
            Settings.Ports = std::vector<uint16_t>({dstPort});
        }
        TryGetValue(argc, argv, "target", &Settings.ServerName);
        TryGetValue(argc, argv, "alpn", &Settings.AlpnPrefix);
        TryGetValue(argc, argv, "sessions", &SessionCount);
    }

    uint32_t RngSeed = 6;
    TryGetValue(argc, argv, "seed", &RngSeed);
    srand(RngSeed);

    EXIT_ON_FAILURE(MsQuicOpenV1(&MsQuic));

    EXIT_ON_FAILURE(MsQuic->RegistrationOpen("spinquic", &Registration));
    
    const size_t AlpnLen = strlen(Settings.AlpnPrefix) + 5; // You can't have more than 10^4 SessionCount. :)
    char *AlpnBuffer = (char *)malloc(AlpnLen);

    for (uint32_t i = 0; i < SessionCount; i++) {

        sprintf_s(AlpnBuffer, AlpnLen, i > 0 ? "%s%d" : "%s", Settings.AlpnPrefix, i);

        HQUIC Session;
        QUIC_STATUS Status = MsQuic->SessionOpen(Registration, AlpnBuffer, nullptr, &Session);
        PRINT("Opening session #%d: %d\n", i, Status);
        if (QUIC_FAILED(Status)) {
            PRINT("Failed to open session #%d\n", i);
            continue;
        }

        Sessions.push_back(Session);

        // Configure Session
        auto PeerStreamCount = GetRandom((uint16_t)10);
        EXIT_ON_FAILURE(MsQuic->SetParam(Session, QUIC_PARAM_LEVEL_SESSION, QUIC_PARAM_SESSION_PEER_BIDI_STREAM_COUNT, sizeof(PeerStreamCount), &PeerStreamCount));
        EXIT_ON_FAILURE(MsQuic->SetParam(Session, QUIC_PARAM_LEVEL_SESSION, QUIC_PARAM_SESSION_PEER_BIDI_STREAM_COUNT, sizeof(PeerStreamCount), &PeerStreamCount));
    }

    free(AlpnBuffer);

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

    MsQuicClose(MsQuic);

    return 0;
}
