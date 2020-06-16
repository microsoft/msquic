/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.

Abstract:

    Provides a very simple implementation of the SiDUCK protocol described here:

        https://tools.ietf.org/html/draft-pardue-quic-siduck-00

--*/

#include <msquichelper.h>

const QUIC_REGISTRATION_CONFIG RegConfig = { "siduck", QUIC_EXECUTION_PROFILE_LOW_LATENCY };
const QUIC_BUFFER Alpn = { sizeof("siduck") - 1, (uint8_t*)"siduck" };
uint16_t UdpPort = 5000;
uint64_t IdleTimeoutMs = 3000;
uint32_t QuackPeriodMs = 500;
uint32_t QuackCount = 10;

const QUIC_API_TABLE* MsQuic;
HQUIC Registration;
HQUIC Session;
QUIC_SEC_CONFIG* SecurityConfig;

const QUIC_BUFFER QuackBuffer = { sizeof("quack") - 1, (uint8_t*)"quack" };
const QUIC_BUFFER QuackAckBuffer = { sizeof("quack-ack") - 1, (uint8_t*)"quack-ack" };

#define SIDUCK_ONLY_QUACKS_ECHO 0x101

extern "C" void QuicTraceRundown(void) { }

void
PrintUsage()
{
    printf("\nquicsiduck runs a SiDUCK client or server.\n\n");

    printf("Usage:\n");
    printf("  quicsiduck.exe -client -target:<...> [-unsecure]\n");
    printf("  quicsiduck.exe -server -cert_hash:<...> or (-cert_file:<...> and -key_file:<...>)\n");
}

_IRQL_requires_max_(DISPATCH_LEVEL)
_Function_class_(QUIC_CONNECTION_CALLBACK)
QUIC_STATUS
QUIC_API
ServerConnectionCallback(
    _In_ HQUIC Connection,
    _In_opt_ void* /* Context */,
    _Inout_ QUIC_CONNECTION_EVENT* Event
    )
{
    switch (Event->Type) {
    case QUIC_CONNECTION_EVENT_CONNECTED:
        printf("[conn][%p] Connected\n", Connection);
        break;
    case QUIC_CONNECTION_EVENT_SHUTDOWN_INITIATED_BY_TRANSPORT:
        if (Event->SHUTDOWN_INITIATED_BY_TRANSPORT.Status != QUIC_STATUS_CONNECTION_IDLE) {
            printf("[conn][%p] Shutdown by peer, 0x%x\n", Connection, Event->SHUTDOWN_INITIATED_BY_TRANSPORT.Status);
        }
        break;
    case QUIC_CONNECTION_EVENT_SHUTDOWN_INITIATED_BY_PEER:
        printf("[conn][%p] Shutdown by peer, 0x%llx\n", Connection, Event->SHUTDOWN_INITIATED_BY_PEER.ErrorCode);
        break;
    case QUIC_CONNECTION_EVENT_SHUTDOWN_COMPLETE:
        printf("[conn][%p] Complete\n", Connection);
        MsQuic->ConnectionClose(Connection);
        break;
    case QUIC_CONNECTION_EVENT_DATAGRAM_RECEIVED:
        if (Event->DATAGRAM_RECEIVED.Buffer->Length == QuackBuffer.Length &&
            !memcmp(Event->DATAGRAM_RECEIVED.Buffer->Buffer, QuackBuffer.Buffer, QuackBuffer.Length)) {
            printf("[conn][%p] quack received. Sending quack-ack...\n", Connection);

            QUIC_STATUS Status;
            if (QUIC_FAILED(Status = MsQuic->DatagramSend(Connection, &QuackAckBuffer, 1, QUIC_SEND_FLAG_NONE, nullptr))) {
                printf("DatagramSend failed, 0x%x!\n", Status);
            }
        } else {
            printf("[conn][%p] Invalid datagram response received\n", Connection);
            MsQuic->ConnectionShutdown(Connection, QUIC_CONNECTION_SHUTDOWN_FLAG_NONE, SIDUCK_ONLY_QUACKS_ECHO);
        }
        break;
    default:
        break;
    }
    return QUIC_STATUS_SUCCESS;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
_Function_class_(QUIC_LISTENER_CALLBACK)
QUIC_STATUS
QUIC_API
ServerListenerCallback(
    _In_ HQUIC /* Listener */,
    _In_opt_ void* /* Context */,
    _Inout_ QUIC_LISTENER_EVENT* Event
    )
{
    switch (Event->Type) {
    case QUIC_LISTENER_EVENT_NEW_CONNECTION: {
        QUIC_STATUS Status;
        BOOLEAN EnableDatagrams = TRUE;
        if (QUIC_FAILED(Status = MsQuic->SetParam(
                Event->NEW_CONNECTION.Connection, QUIC_PARAM_LEVEL_CONNECTION,
                QUIC_PARAM_CONN_DATAGRAM_RECEIVE_ENABLED, sizeof(EnableDatagrams), &EnableDatagrams))) {
            printf("SetParam(QUIC_PARAM_CONN_DATAGRAM_RECEIVE_ENABLED) failed, 0x%x!\n", Status);
        }
        Event->NEW_CONNECTION.SecurityConfig = SecurityConfig;
        MsQuic->SetCallbackHandler(Event->NEW_CONNECTION.Connection, (void*)ServerConnectionCallback, nullptr);
        break;
    }
    default:
        break;
    }
    return QUIC_STATUS_SUCCESS;
}

void
RunServer(
    _In_ int argc,
    _In_reads_(argc) _Null_terminated_ char* argv[]
    )
{
    QUIC_STATUS Status;
    const uint16_t PeerStreamCount = 1;
    HQUIC Listener = nullptr;

    QUIC_ADDR Address = {};
    QuicAddrSetFamily(&Address, AF_UNSPEC);
    QuicAddrSetPort(&Address, UdpPort);

    const char* Cert;
    const char* KeyFile;
    if (TryGetValue(argc, argv, "cert_hash", &Cert)) {
        SecurityConfig = GetSecConfigForThumbprint(MsQuic, Registration, Cert);
        if (SecurityConfig == nullptr) {
            printf("Failed to load certificate from hash!\n");
            return;
        }
    } else if (TryGetValue(argc, argv, "cert_file", &Cert) &&
        TryGetValue(argc, argv, "key_file", &KeyFile)) {
        SecurityConfig = GetSecConfigForFile(MsQuic, Registration, KeyFile, Cert);
        if (SecurityConfig == nullptr) {
            printf("Failed to load certificate from file!\n");
            return;
        }
    } else {
        printf("Must specify '-cert_hash' or 'cert_file'!\n");
        return;
    }

    if (QUIC_FAILED(Status = MsQuic->ListenerOpen(Session, ServerListenerCallback, nullptr, &Listener))) {
        printf("ListenerOpen failed, 0x%x!\n", Status);
        goto Error;
    }

    if (QUIC_FAILED(Status = MsQuic->ListenerStart(Listener, &Address))) {
        printf("ListenerStart failed, 0x%x!\n", Status);
        goto Error;
    }

    printf("Press Enter to exit.\n\n");
    getchar();

Error:

    if (Listener != nullptr) {
        MsQuic->ListenerClose(Listener);
    }
    MsQuic->SecConfigDelete(SecurityConfig);
}

bool
ClientSend(
    _In_ HQUIC Connection
    )
{
    printf("[conn][%p] Sending quack...\n", Connection);

    QUIC_STATUS Status;
    if (QUIC_FAILED(Status = MsQuic->DatagramSend(Connection, &QuackBuffer, 1, QUIC_SEND_FLAG_NONE, nullptr))) {
        printf("DatagramSend failed, 0x%x!\n", Status);
        MsQuic->ConnectionShutdown(Connection, QUIC_CONNECTION_SHUTDOWN_FLAG_NONE, 0);
        return false;
    }

    return true;
}

_IRQL_requires_max_(DISPATCH_LEVEL)
_Function_class_(QUIC_CONNECTION_CALLBACK)
QUIC_STATUS
QUIC_API
ClientConnectionCallback(
    _In_ HQUIC Connection,
    _In_opt_ void* /* Context */,
    _Inout_ QUIC_CONNECTION_EVENT* Event
    )
{
    switch (Event->Type) {
    case QUIC_CONNECTION_EVENT_CONNECTED:
        printf("[conn][%p] Connected\n", Connection);
        break;
    case QUIC_CONNECTION_EVENT_SHUTDOWN_INITIATED_BY_TRANSPORT:
        if (Event->SHUTDOWN_INITIATED_BY_TRANSPORT.Status != QUIC_STATUS_CONNECTION_IDLE) {
            printf("[conn][%p] Shutdown by peer, 0x%x\n", Connection, Event->SHUTDOWN_INITIATED_BY_TRANSPORT.Status);
        }
        break;
    case QUIC_CONNECTION_EVENT_SHUTDOWN_INITIATED_BY_PEER:
        printf("[conn][%p] Shutdown by peer, 0x%llx\n", Connection, Event->SHUTDOWN_INITIATED_BY_PEER.ErrorCode);
        break;
    case QUIC_CONNECTION_EVENT_SHUTDOWN_COMPLETE:
        printf("[conn][%p] Complete\n", Connection);
        MsQuic->ConnectionClose(Connection);
        break;
    case QUIC_CONNECTION_EVENT_DATAGRAM_RECEIVED:
        if (Event->DATAGRAM_RECEIVED.Buffer->Length == QuackAckBuffer.Length &&
            !memcmp(Event->DATAGRAM_RECEIVED.Buffer->Buffer, QuackAckBuffer.Buffer, QuackAckBuffer.Length)) {
            printf("[conn][%p] quack-ack received\n", Connection);
        } else {
            printf("[conn][%p] Invalid datagram response received\n", Connection);
        }
        break;
    default:
        break;
    }
    return QUIC_STATUS_SUCCESS;
}

void
RunClient(
    _In_ int argc,
    _In_reads_(argc) _Null_terminated_ char* argv[]
    )
{
    QUIC_STATUS Status;
    HQUIC Connection = nullptr;
    const char* Target;
    BOOLEAN EnableDatagrams = TRUE;
    uint32_t Count = 0;

    if (QUIC_FAILED(Status = MsQuic->ConnectionOpen(Session, ClientConnectionCallback, nullptr, &Connection))) {
        printf("ConnectionOpen failed, 0x%x!\n", Status);
        goto Error;
    }

    if (QUIC_FAILED(Status = MsQuic->SetParam(
            Connection, QUIC_PARAM_LEVEL_CONNECTION, QUIC_PARAM_CONN_DATAGRAM_RECEIVE_ENABLED,
            sizeof(EnableDatagrams), &EnableDatagrams))) {
        printf("SetParam(QUIC_PARAM_CONN_DATAGRAMS) failed, 0x%x!\n", Status);
        goto Error;
    }

    if (GetValue(argc, argv, "unsecure")) {
        const uint32_t CertificateValidationFlags = QUIC_CERTIFICATE_FLAG_DISABLE_CERT_VALIDATION;
        if (QUIC_FAILED(Status = MsQuic->SetParam(
                Connection, QUIC_PARAM_LEVEL_CONNECTION, QUIC_PARAM_CONN_CERT_VALIDATION_FLAGS,
                sizeof(CertificateValidationFlags), &CertificateValidationFlags))) {
            printf("SetParam(QUIC_PARAM_CONN_CERT_VALIDATION_FLAGS) failed, 0x%x!\n", Status);
            goto Error;
        }
    }

    if (!TryGetValue(argc, argv, "target", &Target)) {
        printf("Must specify '-target' argument!\n");
        goto Error;
    }

    printf("[conn][%p] Connecting...\n", Connection);

    if (QUIC_FAILED(Status = MsQuic->ConnectionStart(Connection, AF_UNSPEC, Target, UdpPort))) {
        printf("ConnectionStart failed, 0x%x!\n", Status);
        goto Error;
    }

    do {
        if (!ClientSend(Connection)) {
            break;
        }
        QuicSleep(QuackPeriodMs);
    } while (++Count < QuackCount);

Error:

    if (QUIC_FAILED(Status) && Connection != nullptr) {
        MsQuic->ConnectionClose(Connection);
    }
}

int
QUIC_MAIN_EXPORT
main(
    _In_ int argc,
    _In_reads_(argc) _Null_terminated_ char* argv[]
    )
{
    QuicPlatformSystemLoad();

    QUIC_STATUS Status = QUIC_STATUS_SUCCESS;
    if (QUIC_FAILED(Status = QuicPlatformInitialize())) {
        printf("QuicPlatformInitialize failed, 0x%x!\n", Status);
        QuicPlatformSystemUnload();
        return Status;
    }

    TryGetValue(argc, argv, "port", &UdpPort);
    TryGetValue(argc, argv, "idle", &IdleTimeoutMs);
    TryGetValue(argc, argv, "count", &QuackCount);
    TryGetValue(argc, argv, "period", &QuackPeriodMs);

    if (QUIC_FAILED(Status = MsQuicOpen(&MsQuic))) {
        printf("MsQuicOpen failed, 0x%x!\n", Status);
        goto Error;
    }

    if (QUIC_FAILED(Status = MsQuic->RegistrationOpen(&RegConfig, &Registration))) {
        printf("RegistrationOpen failed, 0x%x!\n", Status);
        goto Error;
    }

    if (QUIC_FAILED(Status = MsQuic->SessionOpen(Registration, &Alpn, 1, nullptr, &Session))) {
        printf("SessionOpen failed, 0x%x!\n", Status);
        goto Error;
    }

    if (QUIC_FAILED(Status = MsQuic->SetParam(
            Session, QUIC_PARAM_LEVEL_SESSION, QUIC_PARAM_SESSION_IDLE_TIMEOUT,
            sizeof(IdleTimeoutMs), &IdleTimeoutMs))) {
        printf("SetParam(QUIC_PARAM_SESSION_IDLE_TIMEOUT) failed, 0x%x!\n", Status);
        goto Error;
    }

    if (GetValue(argc, argv, "help") ||
        GetValue(argc, argv, "?")) {
        PrintUsage();
    } else if (GetValue(argc, argv, "client")) {
        RunClient(argc, argv);
    } else if (GetValue(argc, argv, "server")) {
        RunServer(argc, argv);
    } else {
        PrintUsage();
    }

Error:

    if (MsQuic != nullptr) {
        if (Session != nullptr) {
            MsQuic->SessionClose(Session); // Waits on all connections to be cleaned up.
        }
        if (Registration != nullptr) {
            MsQuic->RegistrationClose(Registration);
        }
        MsQuicClose(MsQuic);
    }

    QuicPlatformUninitialize();
    QuicPlatformSystemUnload();

    return (int)Status;
}
