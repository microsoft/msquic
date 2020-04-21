/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.

Abstract:

    Very Simple QUIC HTTP 0.9 POST client.

--*/

#define _CRT_SECURE_NO_WARNINGS 1

#include <msquichelper.h>

extern "C" void QuicTraceRundown(void) { }

#define IO_SIZE (64 * 1024)

#define POST_HEADER_FORMAT "POST %s \r\n"

#define EXIT_ON_FAILURE(x) do { \
    auto _Status = x; \
    if (QUIC_FAILED(_Status)) { \
       printf("%s:%d %s failed!\n", __FILE__, __LINE__, #x); \
       exit(1); \
    } \
} while (0);

#define ALPN_BUFFER(str) { sizeof(str) - 1, (uint8_t*)str }
const QUIC_BUFFER ALPNs[] = {
    ALPN_BUFFER("hq-27"),
    ALPN_BUFFER("hq-25")
};

const QUIC_API_TABLE* MsQuic;
uint16_t Port = 4433;
const char* ServerName = "localhost";
const char* FilePath = nullptr;
FILE* File = nullptr;
QUIC_EVENT SendReady;
bool TransferCanceled = false;

_IRQL_requires_max_(PASSIVE_LEVEL)
_Function_class_(QUIC_CONNECTION_CALLBACK)
QUIC_STATUS
QUIC_API
ConnectionHandler(
    _In_ HQUIC Connection,
    _In_opt_ void* /* Context */,
    _Inout_ QUIC_CONNECTION_EVENT* Event
    )
{
    switch (Event->Type) {
    case QUIC_CONNECTION_EVENT_CONNECTED:
        printf("Connected\n");
        break;
    case QUIC_CONNECTION_EVENT_SHUTDOWN_COMPLETE:
        printf("Shutdown Complete\n");
        MsQuic->ConnectionClose(Connection);
        break;
    default:
        break;
    }
    return QUIC_STATUS_SUCCESS;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
_Function_class_(QUIC_STREAM_CALLBACK)
QUIC_STATUS
QUIC_API
StreamHandler(
    _In_ HQUIC Stream,
    _In_opt_ void* /* Context */,
    _Inout_ QUIC_STREAM_EVENT* Event
    )
{
    switch (Event->Type) {
    case QUIC_STREAM_EVENT_SEND_COMPLETE:
        if (Event->SEND_COMPLETE.Canceled) {
            TransferCanceled = true;
            printf("Send canceled!\n");
        }
        QuicEventSet(SendReady);
        printf("Send complete!\n");
        break;
    case QUIC_STREAM_EVENT_SHUTDOWN_COMPLETE:
        printf("Stream Shutdown Complete\n");
        MsQuic->ConnectionShutdown(Stream, QUIC_CONNECTION_SHUTDOWN_FLAG_NONE, 0);
        MsQuic->StreamClose(Stream);
        break;
    default:
        break;
    }
    return QUIC_STATUS_SUCCESS;
}

int
QUIC_MAIN_EXPORT
main(
    _In_ int argc,
    _In_reads_(argc) _Null_terminated_ char* argv[]
    )
{
    if (argc < 2 ||
        !TryGetValue(argc, argv, "file", &FilePath) ||
        !strcmp(argv[1], "?") ||
        !strcmp(argv[1], "-?") ||
        !strcmp(argv[1], "--?") ||
        !strcmp(argv[1], "/?") ||
        !strcmp(argv[1], "help")) {
        printf("Usage: quicpost.exe [-server:<name>] [-ip:<ip>] [-port:<number>] -file:<path>\n");
        exit(1);
    }

    TryGetValue(argc, argv, "server", &ServerName);
    TryGetValue(argc, argv, "port", &Port);

    QuicPlatformSystemLoad();
    QuicPlatformInitialize();

    File = fopen(FilePath, "rb");
    if (File == nullptr) {
        printf("Failed to open file!\n");
        exit(1);
    }

    const char* FileName = strrchr(FilePath, '\\');
    if (FileName == nullptr) {
        FileName = strrchr(FilePath, '/');
        if (FileName == nullptr) {
            printf("Failed to parse file name!\n");
            exit(1);
        }
    }
    FileName += 1;

    QuicEventInitialize(&SendReady, FALSE, FALSE);

    HQUIC Registration = nullptr;
    HQUIC Session = nullptr;
    HQUIC Connection = nullptr;
    HQUIC Stream = nullptr;

    EXIT_ON_FAILURE(MsQuicOpen(&MsQuic));
    const QUIC_REGISTRATION_CONFIG RegConfig = { "post", QUIC_EXECUTION_PROFILE_LOW_LATENCY };
    EXIT_ON_FAILURE(MsQuic->RegistrationOpen(&RegConfig, &Registration));
    EXIT_ON_FAILURE(MsQuic->SessionOpen(Registration, ALPNs, ARRAYSIZE(ALPNs), nullptr, &Session));
    EXIT_ON_FAILURE(MsQuic->ConnectionOpen(Session, ConnectionHandler, nullptr, &Connection));
    EXIT_ON_FAILURE(MsQuic->StreamOpen(Connection, QUIC_STREAM_OPEN_FLAG_UNIDIRECTIONAL, StreamHandler, nullptr, &Stream));
    EXIT_ON_FAILURE(MsQuic->StreamStart(Stream, QUIC_STREAM_START_FLAG_ASYNC));
    EXIT_ON_FAILURE(MsQuic->ConnectionStart(Connection, AF_UNSPEC, ServerName, Port));

    printf("Starting send\n");

    uint8_t Buffer[IO_SIZE];
    QUIC_BUFFER SendBuffer = { 0, Buffer };

    SendBuffer.Length = snprintf((char*)Buffer, sizeof(Buffer), POST_HEADER_FORMAT, FileName);
    if (SendBuffer.Length >= sizeof(Buffer)) {
        printf("Failed writing POST header!\n");
        exit(1);
    }

    EXIT_ON_FAILURE(MsQuic->StreamSend(Stream, &SendBuffer, 1, QUIC_SEND_FLAG_NONE, nullptr));
    QuicEventWaitForever(SendReady);

    do {
        SendBuffer.Length = (uint32_t)
            fread(
                SendBuffer.Buffer,
                1,
                sizeof(Buffer),
                File);
        QUIC_SEND_FLAGS SendFlags =
            (SendBuffer.Length != sizeof(Buffer)) ? QUIC_SEND_FLAG_FIN : QUIC_SEND_FLAG_NONE;
        EXIT_ON_FAILURE(MsQuic->StreamSend(Stream, &SendBuffer, 1, SendFlags, nullptr));
        QuicEventWaitForever(SendReady);
    } while (!TransferCanceled && SendBuffer.Length == sizeof(Buffer));

    MsQuic->SessionClose(Session);
    MsQuic->RegistrationClose(Registration);
    MsQuicClose(MsQuic);

    QuicEventUninitialize(SendReady);
    fclose(File);

    QuicPlatformUninitialize();
    QuicPlatformSystemUnload();

    return 0;
}
