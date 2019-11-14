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

// Needed to self signed cert API
#define QUIC_TEST_APIS 1

#include <quic_platform.h>
#include <msquic.h>
#include <msquichelper.h>

#include "spinquic.h"

static QUIC_API_V1 *MsQuic = nullptr;
static HQUIC Registration = nullptr;
static QUIC_SEC_CONFIG *GlobalSecurityConfig = nullptr;
static std::vector<HQUIC> sessions;
static std::vector<HQUIC> server_connections;
static std::mutex server_connections_mtx;

class SpinQuicServerConnectionContext {
    public:
    std::mutex stream_mtx;
    std::vector<HQUIC> streams;
};;

static struct {
    std::vector<uint16_t> ports;
    bool server;
    const char *server_ip;

    // Sessions settings
    int sessions;
    const char *alpn_prefix;
    int rng_seed;
} settings;

extern "C" void QuicTraceRundown(void) { }

// MsQuic Client Callbacks
QUIC_STATUS SpinQuicClientHandleStreamEvent(HQUIC Stream, void * /* p_context */, QUIC_STREAM_EVENT *Event) {
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

QUIC_STATUS SpinQuicClientHandleConnectionEvent(HQUIC /* Connection */, void * /* p_context */, QUIC_CONNECTION_EVENT *Event) {
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
QUIC_STATUS SpinQuicServerHandleStreamEvent(HQUIC Stream, void * /* p_context */, QUIC_STREAM_EVENT *Event) {
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

QUIC_STATUS SpinQuicServerHandleConnectionEvent(HQUIC Connection, void * /* p_context */, QUIC_CONNECTION_EVENT *Event) {
    switch (Event->Type) {
        case QUIC_CONNECTION_EVENT_CONNECTED:
            break;
        case QUIC_CONNECTION_EVENT_SHUTDOWN_COMPLETE: {
            // Close all streams.
            auto ctx = (SpinQuicServerConnectionContext *)MsQuic->GetContext(Connection);
            {
                std::lock_guard<std::mutex> lock(ctx->stream_mtx);
                auto &streams = ctx->streams;
                while (streams.size() > 0) {
                    HQUIC Stream = streams.back();
                    streams.pop_back();
                    MsQuic->StreamClose(Stream);
                }
            }
            break;
        }
        case QUIC_CONNECTION_EVENT_PEER_STREAM_STARTED: {
            MsQuic->SetCallbackHandler(Event->PEER_STREAM_STARTED.Stream, (void *)SpinQuicServerHandleStreamEvent, nullptr);

            auto ctx = (SpinQuicServerConnectionContext *)MsQuic->GetContext(Connection);
            {
                std::lock_guard<std::mutex> lock(ctx->stream_mtx);
                ctx->streams.push_back(Event->PEER_STREAM_STARTED.Stream);
            }
            break;
        }
        default:
            break;
    }

    return QUIC_STATUS_SUCCESS;
}

QUIC_STATUS SpinQuicServerHandleListenerEvent(HQUIC /* Listener */, void * /* p_context */, QUIC_LISTENER_EVENT *Event) {
    switch (Event->Type) {
        case QUIC_LISTENER_EVENT_NEW_CONNECTION:
            Event->NEW_CONNECTION.SecurityConfig = GlobalSecurityConfig;
            MsQuic->SetCallbackHandler(Event->NEW_CONNECTION.Connection, (void *)SpinQuicServerHandleConnectionEvent, nullptr);
            {
                HQUIC Connection = Event->NEW_CONNECTION.Connection;
                std::lock_guard<std::mutex> lock(server_connections_mtx);

                auto ctx = new SpinQuicServerConnectionContext();
                MsQuic->SetContext(Connection, ctx);
                printf("[NEW CONNECTION] %p:%p\n", Event->NEW_CONNECTION.Connection, MsQuic->GetContext(Connection));

                server_connections.push_back(Connection);
            }
            break;
        default:
            break;
    }

    return QUIC_STATUS_SUCCESS;
}

template<typename T>
T& SpinQuicGetRandomFromVector(std::vector<T> &vec) {
    return vec.at(rand() % vec.size());
}

// Replace these with actually random data
char pkt0[] = "AAAAAAAAAAA";
char pkt1[] = "\x01";

int SpinQuicGetRandom(int upper_bound) {
    // Use more uniform random if necessary.
    // upper_bound may be unaligned leading to non-uniformity
    return rand() % upper_bound;
}

void SpinQuicSetRandomConnectionParam(HQUIC Connection) {
    int choice = rand() % 20;

    union {
        uint64_t u64;
        uint32_t u32;
        uint16_t u16;
        uint8_t  u8;
        const char *cp;
    } param;
    param.cp = 0;
    uint32_t param_size = 0;
    int param_flag = -1;

   // Move this to the enum
    switch (choice) {
        case 0: // QUIC_PARAM_CONN_IDLE_TIMEOUT                    3   // uint64_t - milliseconds
            param_flag = QUIC_PARAM_CONN_IDLE_TIMEOUT;
            param_size = 8;
            param.u64 = (rand() % 20);
            break;
        case 1: // QUIC_PARAM_CONN_PEER_BIDI_STREAM_COUNT          4   // uint16_t
            param_flag = QUIC_PARAM_CONN_PEER_BIDI_STREAM_COUNT;
            param_size = 2;
            param.u16 = (rand() % 50000);
            break;
        case 2: // QUIC_PARAM_CONN_PEER_UNIDI_STREAM_COUNT         5   // uint16_t
            param_flag = QUIC_PARAM_CONN_PEER_UNIDI_STREAM_COUNT;
            param_size = 2;
            param.u16 = (rand() % 50000);
            break;
        case 3: // QUIC_PARAM_CONN_LOCAL_BIDI_STREAM_COUNT         6   // uint16_t
            param_flag = QUIC_PARAM_CONN_LOCAL_BIDI_STREAM_COUNT;
            param_size = 2;
            param.u16 = (rand() % 50000);
            break;
        case 4: // QUIC_PARAM_CONN_LOCAL_UNIDI_STREAM_COUNT        7   // uint16_t
            param_flag = QUIC_PARAM_CONN_LOCAL_UNIDI_STREAM_COUNT;
            param_size = 2;
            param.u16 = (rand() % 50000);
            break;
        case 5: // QUIC_PARAM_CONN_CLOSE_REASON_PHRASE             8   // char[]
            param_flag = QUIC_PARAM_CONN_CLOSE_REASON_PHRASE;
            param_size = 10;
            param.cp = "ABCDEFGHI\x00\x00\x00\x00\x00";
            break;
            //case 6: // QUIC_PARAM_CONN_MAX_STREAM_IDS           11  // uint64_t[4]
            //    param_size = 8 * 4;
            //    param_flag = QUIC_PARAM_CONN_MAX_STREAM_IDS;
            //    break;
        case 7: // QUIC_PARAM_CONN_KEEP_ALIVE                      12  // uint32_t - milliseconds
            param_flag = QUIC_PARAM_CONN_KEEP_ALIVE;
            param_size = 4;
            param.u32 = (rand() % 200);
            break;
        case 8: // QUIC_PARAM_CONN_DISCONNECT_TIMEOUT              13  // uint32_t - milliseconds
            param_flag = QUIC_PARAM_CONN_DISCONNECT_TIMEOUT;
            param_size = 4;
            param.u32 = (rand() % 200);
            break;
        case 9: // QUIC_PARAM_CONN_SEND_BUFFERING                  15  // uint8_t (BOOLEAN)
            param_flag = QUIC_PARAM_CONN_SEND_BUFFERING;
            param_size = 1;
            param.u8 = (rand() % 2);
            break;
        case 10: // QUIC_PARAM_CONN_SEND_PACING                     16  // uint8_t (BOOLEAN)
            param_flag = QUIC_PARAM_CONN_SEND_PACING;
            param_size = 1;
            param.u8 = (rand() % 2);
            break;
        case 11: // QUIC_PARAM_CONN_SHARE_UDP_BINDING               17  // uint8_t (BOOLEAN)
            param_flag = QUIC_PARAM_CONN_SHARE_UDP_BINDING;
            param_size = 1;
            param.u8 = (rand() % 2);
            break;
        case 12: // QUIC_PARAM_CONN_IDEAL_PROCESSOR                 18  // uint8_t
            param_flag = QUIC_PARAM_CONN_IDEAL_PROCESSOR;
            param_size = 1;
            param.u8 = (rand() % 254);
            break;
        default:
            break;
    }

    if (param_flag != -1) {
        if (param_flag == QUIC_PARAM_CONN_CLOSE_REASON_PHRASE)
            MsQuic->SetParam(Connection, QUIC_PARAM_LEVEL_CONNECTION, param_flag, param_size, (void *)param.cp);
        else
            MsQuic->SetParam(Connection, QUIC_PARAM_LEVEL_CONNECTION, param_flag, param_size, &param);
    }
}

void SpinQuicGetSecConfigComplete(_In_opt_ void *Context, _In_ QUIC_STATUS /* Status */, _In_opt_ QUIC_SEC_CONFIG *SecConfig) {
    auto Event = (QUIC_EVENT *)Context;

    GlobalSecurityConfig = SecConfig;

    QuicEventSet(*Event);
}

void InitializeServer() {

    QUIC_SEC_CONFIG_PARAMS *SelfSignedCertParams = QuicPlatGetSelfSignedCert(QUIC_SELF_SIGN_CERT_USER);
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

    for (auto &session : sessions) {
        for (auto &pt : settings.ports) {
            HQUIC Listener;
            printf("MsQuic->ListenerOpen(%p, ...) = ", session);
            int ret = MsQuic->ListenerOpen(session, SpinQuicServerHandleListenerEvent, nullptr, &Listener);
            printf("0x%x\n", ret);

            SOCKADDR_INET sockAddr = { 0 };
            sockAddr.Ipv4.sin_family = AF_INET;
            sockAddr.Ipv4.sin_port = htons(pt);

            printf("MsQuic->ListenerStart(%p, {*:%d}) = ", Listener, pt);
            ret = MsQuic->ListenerStart(Listener, &sockAddr);
            printf("0x%x\n", ret);
        }
    }
}

// Match signature of LPTHREAD_START_ROUTINE
void *ServerSpin(void *) {
    while ((1)) {
        // Acquire a connection
        HQUIC Connection = nullptr;
        {
            std::lock_guard<std::mutex> lock(server_connections_mtx);
            if (server_connections.size() > 0) {
                Connection = SpinQuicGetRandomFromVector(server_connections);
            }
        }

        // Don't sleep while holding the lock
        if (Connection == nullptr) {
            QuicSleep(100);
            continue;
        }

        SpinQuicAPICall option = (SpinQuicAPICall)SpinQuicGetRandom(SpinQuicAPICallCount);
        // https://tools.ietf.org/html/draft-ietf-quic-invariants-01#appendix-A

        switch (option) {
            case SpinQuicAPICallCreateConnection:
            case SpinQuicAPICallStartConnection:
                // Don't think we can do these
                break;
            case SpinQuicAPICallShutdownConnection:
                printf("MsQuic->ConnectionShutdown(%p, ...)\n", Connection);
                MsQuic->ConnectionShutdown(Connection, (QUIC_CONNECTION_SHUTDOWN_FLAGS)(rand() % 2), 0);
                break;
            case SpinQuicAPICallCloseConnection: {
                // Close all streams in the SHUTDOWN_COMPLETE callback.
                {
                    std::lock_guard<std::mutex> lock(server_connections_mtx);
                    auto it = std::find(server_connections.begin(), server_connections.end(), Connection);
                    if (it == server_connections.end()) continue;
                    server_connections.erase(it);
                }

                //SpinQuicServerConnectionContext *ctx = (SpinQuicServerConnectionContext *)MsQuic->GetContext(Connection);
                //MsQuic->ConnectionClose(Connection);
                printf("MsQuic->ConnectionClose(%p)\n", Connection);
                //delete ctx;
                break;
            }
            case SpinQuicAPICallStreamOpen: {
                auto ctx = (SpinQuicServerConnectionContext *)MsQuic->GetContext(Connection);
                HQUIC Stream;

                printf("MsQuic->StreamOpen(%p, ...) = ", Connection);
                int ret = MsQuic->StreamOpen(Connection, (QUIC_STREAM_OPEN_FLAGS)(rand() % 2), SpinQuicServerHandleStreamEvent, nullptr, &Stream);
                printf("0x%x\n", ret);

                if (!ret) {
                    printf("[Adding Stream] %p\n", Stream);
                    {
                        std::lock_guard<std::mutex> lock(ctx->stream_mtx);
                        ctx->streams.push_back(Stream);
                    }
                }
                break;
            }
            case SpinQuicAPICallStreamStart: {
                auto ctx = (SpinQuicServerConnectionContext *)MsQuic->GetContext(Connection);
                {
                    std::lock_guard<std::mutex> lock(ctx->stream_mtx);
                    if (ctx->streams.size() == 0) continue;

                    HQUIC Stream = SpinQuicGetRandomFromVector(ctx->streams);

                    // QUIC_STREAM_START_FLAGS flags[] = { QUIC_STREAM_START_FLAG_NONE, QUIC_STREAM_START_FLAG_IMMEDIATE, QUIC_STREAM_START_FLAG_ASYNC };
                    // Can't pass other flags for now, it'll cause a deadlock.

                    printf("MsQuic->StreamStart(%p, ...) = ", Stream);
                    int ret = MsQuic->StreamStart(Stream, QUIC_STREAM_START_FLAG_ASYNC);
                    printf("0x%x\n", ret);
                }
                break;
            }
            case SpinQuicAPICallStreamSend: {
                auto ctx = (SpinQuicServerConnectionContext *)MsQuic->GetContext(Connection);
                {
                    std::lock_guard<std::mutex> lock(ctx->stream_mtx);
                    if (ctx->streams.size() == 0) continue;

                    HQUIC Stream = SpinQuicGetRandomFromVector(ctx->streams);

                    QUIC_BUFFER Buffers[2] = {
                        { (uint32_t)strlen(pkt0), reinterpret_cast<uint8_t *>(pkt0) },
                        { (uint32_t)strlen(pkt1), reinterpret_cast<uint8_t *>(pkt1) },
                    };

                    printf("MsQuic->StreamSend(%p, ...) = ", Stream);
                    int ret = MsQuic->StreamSend(Stream, Buffers, 2, QUIC_SEND_FLAG_NONE, nullptr);
                    printf("0x%x\n", ret);
                }
                break;
            }
            case SpinQuicAPICallStreamShutdown: {
                auto ctx = (SpinQuicServerConnectionContext *)MsQuic->GetContext(Connection);
                {
                    std::lock_guard<std::mutex> lock(ctx->stream_mtx);
                    if (ctx->streams.size() == 0) continue;

                    HQUIC Stream = SpinQuicGetRandomFromVector(ctx->streams);
                    printf("MsQuic->StreamShutdown(%p, ...) = ", Stream);
                    int ret = MsQuic->StreamShutdown(Stream, (QUIC_STREAM_SHUTDOWN_FLAGS) (rand() % 16), 0);
                    printf("0x%x\n", ret);
                }
                break;
            }
            case SpinQuicAPICallStreamClose: {
                auto ctx = (SpinQuicServerConnectionContext *)MsQuic->GetContext(Connection);
                HQUIC Stream = nullptr;
                {
                    std::lock_guard<std::mutex> lock(ctx->stream_mtx);
                    if (ctx->streams.size() == 0) continue;

                    auto &streams = ctx->streams;

                    int idx = SpinQuicGetRandom((int)streams.size());
                    Stream = streams[idx];
                    streams.erase(streams.begin() + idx);
                }

                printf("MsQuic->StreamClose(%p)\n", Stream);
                MsQuic->StreamClose(Stream);
                break;
            }
            case SpinQuicAPICallSetParamSession: {
                HQUIC Session = SpinQuicGetRandomFromVector(sessions);

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

    return nullptr;
}

void *ClientSpin(void *) {
    std::vector<HQUIC> connections;

    while ((1)) {
        SpinQuicAPICall option = (SpinQuicAPICall)SpinQuicGetRandom(SpinQuicAPICallCount);

        switch (option) {
            case SpinQuicAPICallCreateConnection : { // Create connection
                HQUIC Session = SpinQuicGetRandomFromVector(sessions);
                HQUIC Connection;

                std::vector<HQUIC> *streams = new std::vector<HQUIC>();

                printf("MsQuic->ConnectionOpen(%p, ...) = ", Session);
                int ret = MsQuic->ConnectionOpen(Session, SpinQuicClientHandleConnectionEvent, streams, &Connection);
                printf("0x%x\n", ret);

                if (!ret) {
                    printf("[Adding] %p\n", Connection);
                    connections.push_back(Connection);
                }
                break;
            }
            case SpinQuicAPICallShutdownConnection: { // Shutdown connection
                if (connections.size() == 0) continue;
                // fill with random flags and error codes..
                HQUIC Connection = SpinQuicGetRandomFromVector(connections);
                printf("MsQuic->ConnectionShutdown(%p, ...)\n", Connection);
                MsQuic->ConnectionShutdown(Connection, (QUIC_CONNECTION_SHUTDOWN_FLAGS)(rand() % 2), 0);
                break;
            }
            case SpinQuicAPICallStartConnection: { // Start connection
                if (connections.size() == 0) continue;

                HQUIC Connection = SpinQuicGetRandomFromVector(connections);

                printf("MsQuic->ConnectionStart(%p, ...) = ", Connection);
                int ret = MsQuic->ConnectionStart(Connection, AF_INET, settings.server_ip, SpinQuicGetRandomFromVector(settings.ports));
                printf("0x%x\n", ret);
                break;
            }
            case SpinQuicAPICallCloseConnection: { // Close connection
                if (connections.size() == 0) continue;

                int idx = SpinQuicGetRandom((int)connections.size());
                HQUIC Connection = connections[idx];
                connections.erase(connections.begin() + idx);

                auto streams = (std::vector<HQUIC> *)MsQuic->GetContext(Connection);
                while (streams->size() != 0) {
                    HQUIC Stream = streams->back();
                    streams->pop_back();
                    //*streams.erase(streams.begin());
                    printf("[Closing Connection %p] MsQuic->StreamClose(%p)\n", Connection, Stream);
                    MsQuic->StreamClose(Stream);
                }

                printf("MsQuic->ConnectionClose(%p)\n", Connection);
                delete streams;
                //MsQuic->ConnectionClose(Connection);
                break;
            }
            case SpinQuicAPICallStreamOpen: { // StreamOpen
                if (connections.size() == 0) continue;

                HQUIC Connection = SpinQuicGetRandomFromVector(connections);

                HQUIC Stream;
                printf("MsQuic->StreamOpen(%p, ...) = ", Connection);
                int ret = MsQuic->StreamOpen(Connection, (QUIC_STREAM_OPEN_FLAGS)(rand() % 2), SpinQuicClientHandleStreamEvent, nullptr, &Stream);
                printf("0x%x\n", ret);

                if (!ret) {
                    printf("[Adding Stream] %p\n", Stream);
                    auto streams = (std::vector<HQUIC> *)MsQuic->GetContext(Connection);
                    streams->push_back(Stream);
                }

                break;
            }
            case SpinQuicAPICallStreamStart: { // StreamStart
                if  (connections.size() == 0) continue;

                HQUIC Connection = SpinQuicGetRandomFromVector(connections);

                auto streams = (std::vector<HQUIC> *)MsQuic->GetContext(Connection);
                if (streams->size() == 0) continue;

                HQUIC Stream = SpinQuicGetRandomFromVector(*streams);

                QUIC_STREAM_START_FLAGS flags[] = { QUIC_STREAM_START_FLAG_NONE, QUIC_STREAM_START_FLAG_IMMEDIATE, QUIC_STREAM_START_FLAG_ASYNC };

                printf("MsQuic->StreamStart(%p, ...) = ", Stream);
                int ret = MsQuic->StreamStart(Stream, flags[rand() % 3]);
                printf("0x%x\n", ret);
                break;
            }
            case SpinQuicAPICallStreamShutdown: { // StreamShutdown
                if (connections.size() == 0) continue;

                HQUIC Connection = SpinQuicGetRandomFromVector(connections);

                auto streams = (std::vector<HQUIC> *)MsQuic->GetContext(Connection);
                if (streams->size() == 0) continue;

                HQUIC Stream = SpinQuicGetRandomFromVector(*streams);

                printf("MsQuic->StreamShutdown(%p, ...) = ", Stream);
                int ret = MsQuic->StreamShutdown(Stream, (QUIC_STREAM_SHUTDOWN_FLAGS) (rand() % 16), 0);
                printf("0x%x\n", ret);
                break;
            }
            case SpinQuicAPICallStreamSend: { // StreamSend
                if (connections.size() == 0) continue;
                HQUIC Connection = SpinQuicGetRandomFromVector(connections);

                auto streams = (std::vector<HQUIC> *)MsQuic->GetContext(Connection);

                if (streams->size() == 0) continue;

                HQUIC Stream = SpinQuicGetRandomFromVector(*streams);

                QUIC_BUFFER Buffers[2] = {
                    { (uint32_t)strlen(pkt0), reinterpret_cast<uint8_t *>(pkt0) },
                    { (uint32_t)strlen(pkt1), reinterpret_cast<uint8_t *>(pkt1) },
                };

                printf("MsQuic->StreamSend(%p, ...) = ", Stream);
                int ret = MsQuic->StreamSend(Stream, Buffers, 2, QUIC_SEND_FLAG_NONE, nullptr);
                printf("0x%x\n", ret);
                break;
            }
            case SpinQuicAPICallStreamClose: { // StreamClose
                if (connections.size() == 0) continue;

                HQUIC Connection = SpinQuicGetRandomFromVector(connections);

                auto streams = (std::vector<HQUIC> *)MsQuic->GetContext(Connection);
                if (streams->size() == 0) continue;

                int idx = rand() % streams->size();
                HQUIC Stream = (*streams)[idx];
                streams->erase(streams->begin() + idx);

                printf("MsQuic->StreamClose(%p)\n", Stream);
                MsQuic->StreamClose(Stream);
                break;
            }
            case SpinQuicAPICallSetParamSession: { // SetParam - Session
                HQUIC Session = SpinQuicGetRandomFromVector(sessions);

                uint16_t PeerStreamCount = (uint16_t)SpinQuicGetRandom(10);
                int uni = SpinQuicGetRandom(2);

                MsQuic->SetParam(Session, QUIC_PARAM_LEVEL_SESSION, (uni == 0 ? QUIC_PARAM_SESSION_PEER_UNIDI_STREAM_COUNT : QUIC_PARAM_SESSION_PEER_BIDI_STREAM_COUNT), sizeof(PeerStreamCount), &PeerStreamCount);

                break;
            }
            case SpinQuicAPICallSetParamConnection: { // SetParam - Connection
                if (connections.size() == 0) continue;

                HQUIC Connection = SpinQuicGetRandomFromVector(connections);

                SpinQuicSetRandomConnectionParam(Connection);
                break;
             }

            default:
                 break;
        }
    }
}

void PrintHelpText(void) {
    printf("Usage: spinquic.exe [client/server]\n");
    exit(1);
}

int
QUIC_MAIN_EXPORT
main(int argc, char **argv) {

    if (argc < 2) {
        PrintHelpText();
    }

    if (strcmp(argv[1], "server") == 0) {
        settings.server = true;
    } else {
        settings.server = false;
    }

    settings.server_ip = "127.0.0.1";
    settings.ports = std::vector<uint16_t>({9998, 9999});
    settings.rng_seed = 6;
    settings.sessions = 4;
    settings.alpn_prefix = "quic";

    // get this from argv
    srand(settings.rng_seed);

    SQ_ASSERT(!QUIC_FAILED(MsQuicOpenV1(&MsQuic)));

    SQ_ASSERT(!QUIC_FAILED(MsQuic->RegistrationOpen("kqnc-cli", &Registration)));

    for (int i = 0; i < settings.sessions; i++) {
        HQUIC Session;

        char *alpn_buffer = (char *)malloc(strlen(settings.alpn_prefix) + 5); // You can't have more than 10^4 sessions. :)
        sprintf(alpn_buffer, "%s%d", settings.alpn_prefix, i);

        int ret = MsQuic->SessionOpen(Registration, alpn_buffer, nullptr, &Session);
        printf("Opening session #%d: %d\n", i, ret);
        free(alpn_buffer);

        if (ret != 0) {
            printf("Failed to open session #%d\n", i);
            continue;
        }

        sessions.push_back(Session);

        // Configure Session
        uint16_t PeerBidiStreamCount = 9999;

        SQ_ASSERT(!QUIC_FAILED(MsQuic->SetParam(Session, QUIC_PARAM_LEVEL_SESSION, QUIC_PARAM_SESSION_PEER_BIDI_STREAM_COUNT, sizeof(PeerBidiStreamCount), &PeerBidiStreamCount)));
        SQ_ASSERT(!QUIC_FAILED(MsQuic->SetParam(Session, QUIC_PARAM_LEVEL_SESSION, QUIC_PARAM_SESSION_PEER_BIDI_STREAM_COUNT, sizeof(PeerBidiStreamCount), &PeerBidiStreamCount)));
    }

    // Make it optional to do both server and client in the same process
    if (settings.server) {
        InitializeServer();
        ServerSpin(nullptr);
    }
    else {
        ClientSpin(nullptr);
    }

    return 0;
}

