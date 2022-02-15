/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.

Abstract:

    Very Simple QUIC HTTP 0.9 POST client.

--*/

#define _CRT_SECURE_NO_WARNINGS 1

#include "msquichelper.h"

#define IO_SIZE (128 * 1024)

#define POST_HEADER_FORMAT "POST %s\r\n"

#define EXIT_ON_FAILURE(x) do { \
    auto _Status = x; \
    if (QUIC_FAILED(_Status)) { \
       printf("%s:%d %s failed!\n", __FILE__, __LINE__, #x); \
       exit(1); \
    } \
} while (0);

#define ALPN_BUFFER(str) { sizeof(str) - 1, (uint8_t*)str }
const QUIC_BUFFER ALPNs[] = {
    ALPN_BUFFER("hq-interop"),
    ALPN_BUFFER("hq-29")
};

const QUIC_API_TABLE* MsQuic;
uint16_t Port = 4433;
const char* ServerName = "localhost";
const char* FilePath = nullptr;
FILE* File = nullptr;
CXPLAT_EVENT SendReady;
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
    case QUIC_CONNECTION_EVENT_SHUTDOWN_INITIATED_BY_TRANSPORT:
        printf("Transport Shutdown 0x%x\n", Event->SHUTDOWN_INITIATED_BY_TRANSPORT.Status);
        break;
    case QUIC_CONNECTION_EVENT_SHUTDOWN_INITIATED_BY_PEER:
        printf("Peer Shutdown 0x%llx\n", (unsigned long long)Event->SHUTDOWN_INITIATED_BY_PEER.ErrorCode);
        break;
    case QUIC_CONNECTION_EVENT_SHUTDOWN_COMPLETE:
        //printf("Shutdown Complete\n");
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
        CxPlatEventSet(SendReady);
        break;
    case QUIC_STREAM_EVENT_PEER_RECEIVE_ABORTED:
        printf("Peer stream recv abort (0x%llx)\n", (unsigned long long)Event->PEER_RECEIVE_ABORTED.ErrorCode);
        break;
    case QUIC_STREAM_EVENT_SHUTDOWN_COMPLETE:
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
    if (argc < 2 || !TryGetValue(argc, argv, "file", &FilePath)) {
        printf("Usage: quicpost.exe [-server:<name>] [-ip:<ip>] [-port:<number>] -file:<path>\n");
        exit(1);
    }

    TryGetValue(argc, argv, "server", &ServerName);
    TryGetValue(argc, argv, "port", &Port);

    CxPlatSystemLoad();
    CxPlatInitialize();

    File = fopen(FilePath, "rb");
    if (File == nullptr) {
        printf("Failed to open file!\n");
        exit(1);
    }

    const char* FileName = strrchr(FilePath, '\\');
    if (FileName == nullptr) {
        FileName = strrchr(FilePath, '/');
    }
    if (FileName == nullptr) {
        FileName = FilePath; // There was no path in FilePath
    } else {
        FileName += 1;
    }

    CxPlatEventInitialize(&SendReady, FALSE, FALSE);

    HQUIC Registration = nullptr;
    HQUIC Configuration = nullptr;
    HQUIC Connection = nullptr;
    HQUIC Stream = nullptr;

    QUIC_CREDENTIAL_CONFIG CredConfig;
    CxPlatZeroMemory(&CredConfig, sizeof(CredConfig));
    CredConfig.Type = QUIC_CREDENTIAL_TYPE_NONE;
    CredConfig.Flags = QUIC_CREDENTIAL_FLAG_NO_CERTIFICATE_VALIDATION | QUIC_CREDENTIAL_FLAG_CLIENT;

    EXIT_ON_FAILURE(MsQuicOpen2(&MsQuic));
    const QUIC_REGISTRATION_CONFIG RegConfig = { "post", QUIC_EXECUTION_PROFILE_LOW_LATENCY };
    EXIT_ON_FAILURE(MsQuic->RegistrationOpen(&RegConfig, &Registration));
    EXIT_ON_FAILURE(MsQuic->ConfigurationOpen(Registration, ALPNs, ARRAYSIZE(ALPNs), nullptr, 0, nullptr, &Configuration));
    EXIT_ON_FAILURE(MsQuic->ConfigurationLoadCredential(Configuration, &CredConfig));
    EXIT_ON_FAILURE(MsQuic->ConnectionOpen(Registration, ConnectionHandler, nullptr, &Connection));
    EXIT_ON_FAILURE(MsQuic->StreamOpen(Connection, QUIC_STREAM_OPEN_FLAG_UNIDIRECTIONAL, StreamHandler, nullptr, &Stream));
    EXIT_ON_FAILURE(MsQuic->StreamStart(Stream, QUIC_STREAM_START_FLAG_NONE));
    EXIT_ON_FAILURE(MsQuic->ConnectionStart(Connection, Configuration, QUIC_ADDRESS_FAMILY_UNSPEC, ServerName, Port));

    printf("POST '%s' to %s:%hu\n", FileName, ServerName, Port);

    uint64_t TotalBytesSent = 0;
    uint64_t TimeStart = CxPlatTimeUs64();

    uint8_t Buffer[IO_SIZE];
    QUIC_BUFFER SendBuffer = { 0, Buffer };
    SendBuffer.Length = snprintf((char*)Buffer, sizeof(Buffer), POST_HEADER_FORMAT, FileName);

    bool EndOfFile = false;
    do {
        SendBuffer.Length += (uint32_t)
            fread(
                SendBuffer.Buffer + SendBuffer.Length,
                1,
                sizeof(Buffer) - SendBuffer.Length,
                File);
        EndOfFile = SendBuffer.Length != sizeof(Buffer);
        EXIT_ON_FAILURE(MsQuic->StreamSend(Stream, &SendBuffer, 1, EndOfFile ? QUIC_SEND_FLAG_FIN : QUIC_SEND_FLAG_NONE, nullptr));
        CxPlatEventWaitForever(SendReady);
        TotalBytesSent += SendBuffer.Length;
        SendBuffer.Length = 0;
    } while (!TransferCanceled && !EndOfFile);

    MsQuic->ConfigurationClose(Configuration);
    MsQuic->RegistrationClose(Registration);
    MsQuicClose(MsQuic);

    uint64_t TimeEnd = CxPlatTimeUs64();
    uint64_t ElapsedUs = CxPlatTimeDiff64(TimeStart, TimeEnd);
    uint64_t SendRateKbps = (TotalBytesSent * 1000 * 8) / ElapsedUs;

    printf("%llu bytes sent in %llu.%03llu ms ", (unsigned long long)TotalBytesSent, (unsigned long long)ElapsedUs / 1000, (unsigned long long)ElapsedUs % 1000);
    if (SendRateKbps > 1000) {
        printf("(%llu.%03llu mbps)\n", (unsigned long long)SendRateKbps / 1000, (unsigned long long)SendRateKbps % 1000);
    } else {
        printf("(%llu kbps)\n", (unsigned long long)SendRateKbps);
    }

    CxPlatEventUninitialize(SendReady);
    fclose(File);

    CxPlatUninitialize();
    CxPlatSystemUnload();

    return 0;
}
