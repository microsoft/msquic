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

#include "spinquic.h"

static QUIC_API_V1 *MsQuic = nullptr;
static HQUIC Registration = nullptr;
static QUIC_SEC_CONFIG *GlobalSecurityConfig = nullptr;
static std::vector<HQUIC> Sessions;
static std::vector<HQUIC> ServerConnections;
static std::mutex ServerConnectionsLock;

class SpinQuicServerConnectionContext {
public:
    std::mutex StreamsLock;
    std::vector<HQUIC> Streams;
};;

static struct {
    std::vector<uint16_t> Ports;
    bool IsServer;
    const char* ServerName;

    // Sessions Settings
    const char* AlpnPrefix;
    uint64_t MaxOperationCount;
} Settings;

extern "C" void QuicTraceRundown(void) { }

// MsQuic Client Callbacks
QUIC_STATUS SpinQuicClientHandleStreamEvent(HQUIC Stream, void * /* p_context */, QUIC_STREAM_EVENT *Event)
{
    switch (Event->Type) {
        case QUIC_STREAM_EVENT_IDEAL_SEND_BUFFER_SIZE:
        case QUIC_STREAM_EVENT_PEER_RECEIVE_ABORTED:
        case QUIC_STREAM_EVENT_PEER_SEND_ABORTED:
        case QUIC_STREAM_EVENT_RECEIVE: // send it back?
        case QUIC_STREAM_EVENT_SEND_COMPLETE:
        case QUIC_STREAM_EVENT_SEND_SHUTDOWN_COMPLETE:
        case QUIC_STREAM_EVENT_SHUTDOWN_COMPLETE:
        case QUIC_STREAM_EVENT_START_COMPLETE:
            break;
        case QUIC_STREAM_EVENT_PEER_SEND_SHUTDOWN:
            MsQuic->StreamShutdown(Stream, (QUIC_STREAM_SHUTDOWN_FLAGS) (rand() % 16), 0);
            break;
    }

    return QUIC_STATUS_SUCCESS;
}

QUIC_STATUS SpinQuicClientHandleConnectionEvent(HQUIC /* Connection */, void * /* p_context */, QUIC_CONNECTION_EVENT *Event)
{
    switch (Event->Type) {
        case QUIC_CONNECTION_EVENT_CONNECTED:
            break;
        case QUIC_CONNECTION_EVENT_SHUTDOWN_COMPLETE:
            break;
        case QUIC_CONNECTION_EVENT_PEER_STREAM_STARTED:
            MsQuic->SetCallbackHandler(Event->PEER_STREAM_STARTED.Stream, (void *)SpinQuicClientHandleStreamEvent, nullptr);
            break;
        default:
            break;
    }

    return QUIC_STATUS_SUCCESS;
}

// MsQuic Server callbacks
QUIC_STATUS SpinQuicServerHandleStreamEvent(HQUIC Stream, void * /* p_context */, QUIC_STREAM_EVENT *Event)
{
    switch (Event->Type) {
        case QUIC_STREAM_EVENT_IDEAL_SEND_BUFFER_SIZE:
        case QUIC_STREAM_EVENT_PEER_RECEIVE_ABORTED:
        case QUIC_STREAM_EVENT_PEER_SEND_ABORTED:
        case QUIC_STREAM_EVENT_RECEIVE: // send it back?
        case QUIC_STREAM_EVENT_SEND_COMPLETE:
        case QUIC_STREAM_EVENT_SEND_SHUTDOWN_COMPLETE:
        case QUIC_STREAM_EVENT_SHUTDOWN_COMPLETE:
        case QUIC_STREAM_EVENT_START_COMPLETE:
            break;
        case QUIC_STREAM_EVENT_PEER_SEND_SHUTDOWN:
            MsQuic->StreamShutdown(Stream, (QUIC_STREAM_SHUTDOWN_FLAGS) (rand() % 16), 0);
            break;
    }

    return QUIC_STATUS_SUCCESS;
}

QUIC_STATUS SpinQuicServerHandleConnectionEvent(HQUIC Connection, void * /* p_context */, QUIC_CONNECTION_EVENT *Event)
{
    switch (Event->Type) {
        case QUIC_CONNECTION_EVENT_CONNECTED:
            break;
        case QUIC_CONNECTION_EVENT_SHUTDOWN_COMPLETE: {
            // Close all Streams.
            auto ctx = (SpinQuicServerConnectionContext *)MsQuic->GetContext(Connection);
            {
                std::lock_guard<std::mutex> Lock(ctx->StreamsLock);
                auto &Streams = ctx->Streams;
                while (Streams.size() > 0) {
                    HQUIC Stream = Streams.back();
                    Streams.pop_back();
                    MsQuic->StreamClose(Stream);
                }
            }
            break;
        }
        case QUIC_CONNECTION_EVENT_PEER_STREAM_STARTED: {
            MsQuic->SetCallbackHandler(Event->PEER_STREAM_STARTED.Stream, (void *)SpinQuicServerHandleStreamEvent, nullptr);

            auto ctx = (SpinQuicServerConnectionContext *)MsQuic->GetContext(Connection);
            {
                std::lock_guard<std::mutex> Lock(ctx->StreamsLock);
                ctx->Streams.push_back(Event->PEER_STREAM_STARTED.Stream);
            }
            break;
        }
        default:
            break;
    }

    return QUIC_STATUS_SUCCESS;
}

QUIC_STATUS SpinQuicServerHandleListenerEvent(HQUIC /* Listener */, void * /* p_context */, QUIC_LISTENER_EVENT *Event)
{
    switch (Event->Type) {
        case QUIC_LISTENER_EVENT_NEW_CONNECTION:
            Event->NEW_CONNECTION.SecurityConfig = GlobalSecurityConfig;
            MsQuic->SetCallbackHandler(Event->NEW_CONNECTION.Connection, (void *)SpinQuicServerHandleConnectionEvent, nullptr);
            {
                HQUIC Connection = Event->NEW_CONNECTION.Connection;
                std::lock_guard<std::mutex> Lock(ServerConnectionsLock);

                auto ctx = new SpinQuicServerConnectionContext();
                MsQuic->SetContext(Connection, ctx);
                printf("[NEW CONNECTION] %p:%p\n", Event->NEW_CONNECTION.Connection, MsQuic->GetContext(Connection));

                ServerConnections.push_back(Connection);
            }
            break;
        default:
            break;
    }

    return QUIC_STATUS_SUCCESS;
}

template<typename T>
T& SpinQuicGetRandomFromVector(std::vector<T> &vec)
{
    return vec.at(rand() % vec.size());
}

// Replace these with actually random data
char pkt0[] = "AAAAAAAAAAA";
char pkt1[] = "\x01";

int SpinQuicGetRandom(int upper_bound)
{
    // Use more uniform random if necessary.
    // upper_bound may be unaligned leading to non-uniformity
    return rand() % upper_bound;
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

void SpinQuicGetSecConfigComplete(_In_opt_ void *Context, _In_ QUIC_STATUS /* Status */, _In_opt_ QUIC_SEC_CONFIG *SecConfig)
{
    GlobalSecurityConfig = SecConfig;
    QuicEventSet(*(QUIC_EVENT*)Context);
}

void InitializeServer()
{
    QUIC_SEC_CONFIG_PARAMS* SelfSignedCertParams = QuicPlatGetSelfSignedCert(QUIC_SELF_SIGN_CERT_USER);
    if (!SelfSignedCertParams) {
        exit(1);
    }

    QUIC_EVENT Event;
    QuicEventInitialize(&Event, FALSE, FALSE);

    SQ_ASSERT(!QUIC_FAILED(MsQuic->SecConfigCreate(Registration,
                            (QUIC_SEC_CONFIG_FLAGS)SelfSignedCertParams->Flags,
                            SelfSignedCertParams->Certificate,
                            SelfSignedCertParams->Principal,
                            &Event,
                            SpinQuicGetSecConfigComplete)));

    QuicEventWaitForever(Event);
    QuicEventUninitialize(Event);

    printf("Security config: %p\n", GlobalSecurityConfig);
    if (!GlobalSecurityConfig) exit(1);

    for (auto &session : Sessions) {
        for (auto &pt : Settings.Ports) {
            HQUIC Listener;
            printf("MsQuic->ListenerOpen(%p, ...) = ", session);
            QUIC_STATUS Status = MsQuic->ListenerOpen(session, SpinQuicServerHandleListenerEvent, nullptr, &Listener);
            printf("0x%x\n", Status);

            QUIC_ADDR sockAddr = { 0 };
            QuicAddrSetFamily(&sockAddr, (rand() % 2) ? AF_INET : AF_UNSPEC);
            QuicAddrSetPort(&sockAddr, pt);

            printf("MsQuic->ListenerStart(%p, {*:%d}) = ", Listener, pt);
            Status = MsQuic->ListenerStart(Listener, &sockAddr);
            printf("0x%x\n", Status);
        }
    }
}

// Match signature of LPTHREAD_START_ROUTINE
void ServerSpin(void *)
{
    uint64_t OpCount = 0;
    while (++OpCount != Settings.MaxOperationCount) {
        // Acquire a connection
        HQUIC Connection = nullptr;
        {
            std::lock_guard<std::mutex> Lock(ServerConnectionsLock);
            if (ServerConnections.size() > 0) {
                Connection = SpinQuicGetRandomFromVector(ServerConnections);
            }
        }

        // Don't sleep while holding the Lock
        if (Connection == nullptr) {
            QuicSleep(100);
            continue;
        }

        switch (SpinQuicGetRandom(SpinQuicAPICallCount)) {
        case SpinQuicAPICallCreateConnection:
        case SpinQuicAPICallStartConnection:
            // Don't think we can do these
            break;
        case SpinQuicAPICallShutdownConnection:
            printf("MsQuic->ConnectionShutdown(%p, ...)\n", Connection);
            MsQuic->ConnectionShutdown(Connection, (QUIC_CONNECTION_SHUTDOWN_FLAGS)(rand() % 2), 0);
            break;
        case SpinQuicAPICallCloseConnection: {
            // Close all Streams in the SHUTDOWN_COMPLETE callback.
            {
                std::lock_guard<std::mutex> Lock(ServerConnectionsLock);
                auto it = std::find(ServerConnections.begin(), ServerConnections.end(), Connection);
                if (it == ServerConnections.end()) continue;
                ServerConnections.erase(it);
            }

            SpinQuicServerConnectionContext *ctx = (SpinQuicServerConnectionContext *)MsQuic->GetContext(Connection);
            MsQuic->ConnectionClose(Connection);
            printf("MsQuic->ConnectionClose(%p)\n", Connection);
            delete ctx;
            break;
        }
        case SpinQuicAPICallStreamOpen: {
            auto ctx = (SpinQuicServerConnectionContext *)MsQuic->GetContext(Connection);
            HQUIC Stream;

            printf("MsQuic->StreamOpen(%p, ...) = ", Connection);
            QUIC_STATUS Status = MsQuic->StreamOpen(Connection, (QUIC_STREAM_OPEN_FLAGS)(rand() % 2), SpinQuicServerHandleStreamEvent, nullptr, &Stream);
            printf("0x%x\n", Status);

            if (QUIC_SUCCEEDED(Status)) {
                printf("[Adding Stream] %p\n", Stream);
                {
                    std::lock_guard<std::mutex> Lock(ctx->StreamsLock);
                    ctx->Streams.push_back(Stream);
                }
            }
            break;
        }
        case SpinQuicAPICallStreamStart: {
            auto ctx = (SpinQuicServerConnectionContext *)MsQuic->GetContext(Connection);
            {
                std::lock_guard<std::mutex> Lock(ctx->StreamsLock);
                if (ctx->Streams.size() == 0) continue;

                HQUIC Stream = SpinQuicGetRandomFromVector(ctx->Streams);

                // QUIC_STREAM_START_FLAGS flags[] = { QUIC_STREAM_START_FLAG_NONE, QUIC_STREAM_START_FLAG_IMMEDIATE, QUIC_STREAM_START_FLAG_ASYNC };
                // Can't pass other flags for now, it'll cause a deadlock.

                printf("MsQuic->StreamStart(%p, ...) = ", Stream);
                QUIC_STATUS Status = MsQuic->StreamStart(Stream, QUIC_STREAM_START_FLAG_ASYNC);
                printf("0x%x\n", Status);
            }
            break;
        }
        case SpinQuicAPICallStreamSend: {
            auto ctx = (SpinQuicServerConnectionContext *)MsQuic->GetContext(Connection);
            {
                std::lock_guard<std::mutex> Lock(ctx->StreamsLock);
                if (ctx->Streams.size() == 0) continue;

                HQUIC Stream = SpinQuicGetRandomFromVector(ctx->Streams);

                QUIC_BUFFER Buffers[2] = {
                    { (uint32_t)strlen(pkt0), reinterpret_cast<uint8_t *>(pkt0) },
                    { (uint32_t)strlen(pkt1), reinterpret_cast<uint8_t *>(pkt1) },
                };

                printf("MsQuic->StreamSend(%p, ...) = ", Stream);
                QUIC_STATUS Status = MsQuic->StreamSend(Stream, Buffers, 2, QUIC_SEND_FLAG_NONE, nullptr);
                printf("0x%x\n", Status);
            }
            break;
        }
        case SpinQuicAPICallStreamShutdown: {
            auto ctx = (SpinQuicServerConnectionContext *)MsQuic->GetContext(Connection);
            {
                std::lock_guard<std::mutex> Lock(ctx->StreamsLock);
                if (ctx->Streams.size() == 0) continue;

                HQUIC Stream = SpinQuicGetRandomFromVector(ctx->Streams);
                printf("MsQuic->StreamShutdown(%p, ...) = ", Stream);
                QUIC_STATUS Status = MsQuic->StreamShutdown(Stream, (QUIC_STREAM_SHUTDOWN_FLAGS) (rand() % 16), 0);
                printf("0x%x\n", Status);
            }
            break;
        }
        case SpinQuicAPICallStreamClose: {
            auto ctx = (SpinQuicServerConnectionContext *)MsQuic->GetContext(Connection);
            HQUIC Stream = nullptr;
            {
                std::lock_guard<std::mutex> Lock(ctx->StreamsLock);
                if (ctx->Streams.size() == 0) continue;

                auto &Streams = ctx->Streams;
                int idx = SpinQuicGetRandom((int)Streams.size());
                Stream = Streams[idx];
                Streams.erase(Streams.begin() + idx);
            }

            printf("MsQuic->StreamClose(%p)\n", Stream);
            MsQuic->StreamClose(Stream);
            break;
        }
        case SpinQuicAPICallSetParamSession: {
            HQUIC Session = SpinQuicGetRandomFromVector(Sessions);

            uint16_t PeerStreamCount = (uint16_t)SpinQuicGetRandom(10);
            int uni = SpinQuicGetRandom(2);

            MsQuic->SetParam(Session, QUIC_PARAM_LEVEL_SESSION, (uni == 0 ? QUIC_PARAM_SESSION_PEER_UNIDI_STREAM_COUNT : QUIC_PARAM_SESSION_PEER_BIDI_STREAM_COUNT), sizeof(PeerStreamCount), &PeerStreamCount);
            break;
        }
        case SpinQuicAPICallSetParamConnection:
            SpinQuicSetRandomConnectionParam(Connection);
            break;
        default:
            break;
        }
    }
}

void ClientSpin(void *)
{
    std::vector<HQUIC> Connections;
    uint64_t OpCount = 0;
    while (++OpCount != Settings.MaxOperationCount) {
        switch (SpinQuicGetRandom(SpinQuicAPICallCount)) {
        case SpinQuicAPICallCreateConnection : { // Create connection
            HQUIC Session = SpinQuicGetRandomFromVector(Sessions);
            HQUIC Connection;

            std::vector<HQUIC> *Streams = new std::vector<HQUIC>();

            printf("MsQuic->ConnectionOpen(%p, ...) = ", Session);
            QUIC_STATUS Status = MsQuic->ConnectionOpen(Session, SpinQuicClientHandleConnectionEvent, Streams, &Connection);
            printf("0x%x\n", Status);

            if (QUIC_SUCCEEDED(Status)) {
                printf("[Adding] %p\n", Connection);
                Connections.push_back(Connection);
            }

            if (SpinQuicGetRandom(2) % 1 == 0) {
                break;
            }

            __fallthrough;
        }
        case SpinQuicAPICallStartConnection: { // Start connection
            if (Connections.size() == 0) continue;

            HQUIC Connection = SpinQuicGetRandomFromVector(Connections);

            printf("MsQuic->ConnectionStart(%p, ...) = ", Connection);
            QUIC_STATUS Status = MsQuic->ConnectionStart(Connection, AF_INET, Settings.ServerName, SpinQuicGetRandomFromVector(Settings.Ports));
            printf("0x%x\n", Status);
            break;
        }
        case SpinQuicAPICallShutdownConnection: { // Shutdown connection
            if (Connections.size() == 0) continue;
            // fill with random flags and error codes..
            HQUIC Connection = SpinQuicGetRandomFromVector(Connections);
            printf("MsQuic->ConnectionShutdown(%p, ...)\n", Connection);
            MsQuic->ConnectionShutdown(Connection, (QUIC_CONNECTION_SHUTDOWN_FLAGS)(rand() % 2), 0);
            break;
        }
        case SpinQuicAPICallCloseConnection: { // Close connection
            if (Connections.size() == 0) continue;

            int idx = SpinQuicGetRandom((int)Connections.size());
            HQUIC Connection = Connections[idx];
            Connections.erase(Connections.begin() + idx);

            auto Streams = (std::vector<HQUIC> *)MsQuic->GetContext(Connection);
            while (Streams->size() != 0) {
                HQUIC Stream = Streams->back();
                Streams->pop_back();
                //*Streams.erase(Streams.begin());
                printf("[Closing Connection %p] MsQuic->StreamClose(%p)\n", Connection, Stream);
                MsQuic->StreamClose(Stream);
            }

            printf("MsQuic->ConnectionClose(%p)\n", Connection);
            delete Streams;
            MsQuic->ConnectionClose(Connection);
            break;
        }
        case SpinQuicAPICallStreamOpen: { // StreamOpen
            if (Connections.size() == 0) continue;

            HQUIC Connection = SpinQuicGetRandomFromVector(Connections);

            HQUIC Stream;
            printf("MsQuic->StreamOpen(%p, ...) = ", Connection);
            QUIC_STATUS Status = MsQuic->StreamOpen(Connection, (QUIC_STREAM_OPEN_FLAGS)(rand() % 2), SpinQuicClientHandleStreamEvent, nullptr, &Stream);
            printf("0x%x\n", Status);

            if (QUIC_SUCCEEDED(Status)) {
                printf("[Adding Stream] %p\n", Stream);
                auto Streams = (std::vector<HQUIC> *)MsQuic->GetContext(Connection);
                Streams->push_back(Stream);
            }

            break;
        }
        case SpinQuicAPICallStreamStart: { // StreamStart
            if  (Connections.size() == 0) continue;

            HQUIC Connection = SpinQuicGetRandomFromVector(Connections);

            auto Streams = (std::vector<HQUIC> *)MsQuic->GetContext(Connection);
            if (Streams->size() == 0) continue;

            HQUIC Stream = SpinQuicGetRandomFromVector(*Streams);

            QUIC_STREAM_START_FLAGS flags[] = { QUIC_STREAM_START_FLAG_NONE, QUIC_STREAM_START_FLAG_IMMEDIATE, QUIC_STREAM_START_FLAG_ASYNC };

            printf("MsQuic->StreamStart(%p, ...) = ", Stream);
            QUIC_STATUS Status = MsQuic->StreamStart(Stream, flags[rand() % 3]);
            printf("0x%x\n", Status);
            break;
        }
        case SpinQuicAPICallStreamShutdown: { // StreamShutdown
            if (Connections.size() == 0) continue;

            HQUIC Connection = SpinQuicGetRandomFromVector(Connections);

            auto Streams = (std::vector<HQUIC> *)MsQuic->GetContext(Connection);
            if (Streams->size() == 0) continue;

            HQUIC Stream = SpinQuicGetRandomFromVector(*Streams);
            printf("MsQuic->StreamShutdown(%p, ...) = ", Stream);
            QUIC_STATUS Status = MsQuic->StreamShutdown(Stream, (QUIC_STREAM_SHUTDOWN_FLAGS) (rand() % 16), 0);
            printf("0x%x\n", Status);
            break;
        }
        case SpinQuicAPICallStreamSend: { // StreamSend
            if (Connections.size() == 0) continue;
            HQUIC Connection = SpinQuicGetRandomFromVector(Connections);

            auto Streams = (std::vector<HQUIC> *)MsQuic->GetContext(Connection);

            if (Streams->size() == 0) continue;

            HQUIC Stream = SpinQuicGetRandomFromVector(*Streams);

            QUIC_BUFFER Buffers[2] = {
                { (uint32_t)strlen(pkt0), reinterpret_cast<uint8_t *>(pkt0) },
                { (uint32_t)strlen(pkt1), reinterpret_cast<uint8_t *>(pkt1) },
            };

            printf("MsQuic->StreamSend(%p, ...) = ", Stream);
            QUIC_STATUS Status = MsQuic->StreamSend(Stream, Buffers, 2, QUIC_SEND_FLAG_NONE, nullptr);
            printf("0x%x\n", Status);
            break;
        }
        case SpinQuicAPICallStreamClose: { // StreamClose
            if (Connections.size() == 0) continue;

            HQUIC Connection = SpinQuicGetRandomFromVector(Connections);

            auto Streams = (std::vector<HQUIC> *)MsQuic->GetContext(Connection);
            if (Streams->size() == 0) continue;

            int idx = rand() % Streams->size();
            HQUIC Stream = (*Streams)[idx];
            Streams->erase(Streams->begin() + idx);

            printf("MsQuic->StreamClose(%p)\n", Stream);
            MsQuic->StreamClose(Stream);
            break;
        }
        case SpinQuicAPICallSetParamSession: { // SetParam - Session
            HQUIC Session = SpinQuicGetRandomFromVector(Sessions);

            uint16_t PeerStreamCount = (uint16_t)SpinQuicGetRandom(10);
            int uni = SpinQuicGetRandom(2);

            MsQuic->SetParam(Session, QUIC_PARAM_LEVEL_SESSION, (uni == 0 ? QUIC_PARAM_SESSION_PEER_UNIDI_STREAM_COUNT : QUIC_PARAM_SESSION_PEER_BIDI_STREAM_COUNT), sizeof(PeerStreamCount), &PeerStreamCount);

            break;
        }
        case SpinQuicAPICallSetParamConnection: { // SetParam - Connection
            if (Connections.size() == 0) continue;

            HQUIC Connection = SpinQuicGetRandomFromVector(Connections);

            SpinQuicSetRandomConnectionParam(Connection);
            break;
        }
        default:
            break;
        }
    }
}

void PrintHelpText(void)
{
    printf("Usage: spinquic.exe [client/server] [options]\n" \
          "\n" \
          "  -alpn:<alpn>         default: 'spin'\n" \
          "  -dstport:<port>      default: 9999\n" \
          "  -seed:<seed>         default: 6\n" \
          "  -target:<ip>         default: '127.0.0.1'\n" \
          "  -sessions:<count>    default: 4\n" \
          "  -max_ops:<count>     default: UINT64_MAX\n"
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

    uint32_t SessionCount = 4;
    uint32_t RngSeed = 6;

    Settings.ServerName = "127.0.0.1";
    Settings.Ports = std::vector<uint16_t>({9998, 9999});
    Settings.AlpnPrefix = "spin";
    Settings.MaxOperationCount = UINT64_MAX;

    TryGetValue(argc, argv, "max_ops", &Settings.MaxOperationCount);
    TryGetValue(argc, argv, "seed", &RngSeed);
    srand(RngSeed);

    if (strcmp(argv[1], "server") == 0) {
        Settings.IsServer = true;
    } else {
        Settings.IsServer = false;
        uint16_t dstPort = 0;
        if (TryGetValue(argc, argv, "dstport", &dstPort)) {
            Settings.Ports = std::vector<uint16_t>({dstPort});
        }
        TryGetValue(argc, argv, "target", &Settings.ServerName);
        TryGetValue(argc, argv, "alpn", &Settings.AlpnPrefix);
        TryGetValue(argc, argv, "sessions", &SessionCount);
    }

    SQ_ASSERT(!QUIC_FAILED(MsQuicOpenV1(&MsQuic)));

    SQ_ASSERT(!QUIC_FAILED(MsQuic->RegistrationOpen("spinquic", &Registration)));
    
    const size_t AlpnLen = strlen(Settings.AlpnPrefix) + 5; // You can't have more than 10^4 SessionCount. :)
    char *AlpnBuffer = (char *)malloc(AlpnLen);

    for (uint32_t i = 0; i < SessionCount; i++) {

        sprintf_s(AlpnBuffer, AlpnLen, i > 0 ? "%s%d" : "%s", Settings.AlpnPrefix, i);

        HQUIC Session;
        QUIC_STATUS Status = MsQuic->SessionOpen(Registration, AlpnBuffer, nullptr, &Session);
        printf("Opening session #%d: %d\n", i, Status);

        if (QUIC_FAILED(Status)) {
            printf("Failed to open session #%d\n", i);
            continue;
        }

        Sessions.push_back(Session);

        // Configure Session
        uint16_t PeerBidiStreamCount = 9999;
        SQ_ASSERT(!QUIC_FAILED(MsQuic->SetParam(Session, QUIC_PARAM_LEVEL_SESSION, QUIC_PARAM_SESSION_PEER_BIDI_STREAM_COUNT, sizeof(PeerBidiStreamCount), &PeerBidiStreamCount)));
        SQ_ASSERT(!QUIC_FAILED(MsQuic->SetParam(Session, QUIC_PARAM_LEVEL_SESSION, QUIC_PARAM_SESSION_PEER_BIDI_STREAM_COUNT, sizeof(PeerBidiStreamCount), &PeerBidiStreamCount)));
    }

    free(AlpnBuffer);

    // Make it optional to do both server and client in the same process
    if (Settings.IsServer) {
        InitializeServer();
        ServerSpin(nullptr);
    } else {
        ClientSpin(nullptr);
    }

    return 0;
}

