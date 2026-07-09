/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.

Abstract:

    This sample application serves as an untrusted process which can accept QUIC connections via XDP maps.

    The goal is to demonstrate how to use XDP maps to de-couple the trusted XDP rule setters and the
    untrusted AF_XDP socket users.

    Usage:

        Assuming your environment is correctly set up with the XDP driver runtime >= v1.4

        1. Start the untrusted QUIC server:
            quicxdpmappeer.exe -xdp_map_ifindex:<N> -cert_hash:<hash>
            (will print to stdout the PID)

        2. On a separate terminal, run the trusted orchestrator:
            orchestrator.exe -TargetPid <PID> -IfIndex <N> -UdpPort <port>
            (will print the duplicated XSKMAP handle value to stdout)

        3. Paste the printed handle value into the quicxdpmappeer's stdin
        4. Press Enter in the orchestrator terminal to attach the XDP program
        5. The quicxdpmappeer process can now start accepting QUIC connections from other quicxdpmappeers via XDP maps.

--*/

#define _CRT_SECURE_NO_WARNINGS 1
#define QUIC_API_ENABLE_PREVIEW_FEATURES

#ifdef _WIN32
#pragma warning(disable:5105)
#include <share.h>
#endif

#include "msquic.h"
#include "xdpmap_common.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifndef UNREFERENCED_PARAMETER
#define UNREFERENCED_PARAMETER(P) (void)(P)
#endif

const QUIC_REGISTRATION_CONFIG RegConfig = { "quicxdpmappeer", QUIC_EXECUTION_PROFILE_LOW_LATENCY };
const QUIC_BUFFER Alpn = { sizeof("quicxdpmappeer") - 1, (uint8_t*)"quicxdpmappeer" };
const uint16_t UdpPort = 4567;

const QUIC_API_TABLE* MsQuic;
HQUIC Registration;
HQUIC Configuration;

static
BOOLEAN
GetFlag(
    _In_ int argc,
    _In_reads_(argc) _Null_terminated_ char* argv[],
    _In_z_ const char* name
    )
{
    const size_t nameLen = strlen(name);
    for (int i = 0; i < argc; i++) {
        if (_strnicmp(argv[i] + 1, name, nameLen) == 0 && strlen(argv[i]) == nameLen + 1) {
            return TRUE;
        }
    }
    return FALSE;
}

static
_Ret_maybenull_ _Null_terminated_ const char*
GetValue(
    _In_ int argc,
    _In_reads_(argc) _Null_terminated_ char* argv[],
    _In_z_ const char* name
    )
{
    const size_t nameLen = strlen(name);
    for (int i = 0; i < argc; i++) {
        if (_strnicmp(argv[i] + 1, name, nameLen) == 0 &&
            strlen(argv[i]) > 1 + nameLen + 1 &&
            *(argv[i] + 1 + nameLen) == ':') {
            return argv[i] + 1 + nameLen + 1;
        }
    }
    return NULL;
}

static
uint32_t
DecodeHexBuffer(
    _In_z_ const char* HexBuffer,
    _In_ uint32_t OutBufferLen,
    _Out_writes_to_(OutBufferLen, return) uint8_t* OutBuffer
    )
{
    uint32_t HexBufferLen = (uint32_t)strlen(HexBuffer) / 2;
    if (HexBufferLen > OutBufferLen) {
        return 0;
    }

    for (uint32_t i = 0; i < HexBufferLen; i++) {
        OutBuffer[i] =
            (XdpMapDecodeHexChar(HexBuffer[i * 2]) << 4) |
            XdpMapDecodeHexChar(HexBuffer[i * 2 + 1]);
    }

    return HexBufferLen;
}

static
void
PrintUsage(void)
{
    printf(
        "\n"
        "quicxdpmappeer: minimal XDP map consumer peer (server/client).\n"
        "\n"
        "Server usage:\n"
        "  quicxdpmappeer.exe -xdp_map_ifindex:<N> -cert_hash:<THUMBPRINT> [-cibir_id:<hex>]\n"
        "  quicxdpmappeer.exe -xdp_map_ifindex:<N> -cert_file:<path> -key_file:<path> [-password:<pwd>] [-cibir_id:<hex>]\n"
        "\n"
        "Client usage:\n"
        "  quicxdpmappeer.exe -client -xdp_map_ifindex:<N> -target:<host_or_ip>\n"
        "\n"
        "Required (all modes):\n"
        "  -xdp_map_ifindex:<N>  Interface index for XDP map mode.\n"
        "\n"
        "Required (server):\n"
        "  -cert_hash:<...>      or -cert_file:<...> with -key_file:<...>.\n"
        "\n"
        "Required (client):\n"
        "  -client               Run in client mode.\n"
        "  -target:<...>         Server name or IP to connect to.\n"
        "\n"
        "Optional:\n"
        "  -cibir_id:<hex>       CIBIR ID (offset byte + CID prefix bytes).\n"
    );
}

typedef struct QUIC_CREDENTIAL_CONFIG_HELPER {
    QUIC_CREDENTIAL_CONFIG CredConfig;
    union {
        QUIC_CERTIFICATE_HASH CertHash;
        QUIC_CERTIFICATE_HASH_STORE CertHashStore;
        QUIC_CERTIFICATE_FILE CertFile;
        QUIC_CERTIFICATE_FILE_PROTECTED CertFileProtected;
    };
} QUIC_CREDENTIAL_CONFIG_HELPER;

_IRQL_requires_max_(DISPATCH_LEVEL)
_Function_class_(QUIC_STREAM_CALLBACK)
static
QUIC_STATUS
QUIC_API
ServerStreamCallback(
    _In_ HQUIC Stream,
    _In_opt_ void* Context,
    _Inout_ QUIC_STREAM_EVENT* Event
    )
{
    UNREFERENCED_PARAMETER(Context);

    switch (Event->Type) {
    case QUIC_STREAM_EVENT_RECEIVE:
        MsQuic->StreamShutdown(Stream, QUIC_STREAM_SHUTDOWN_FLAG_GRACEFUL, 0);
        break;
    case QUIC_STREAM_EVENT_PEER_SEND_ABORTED:
    case QUIC_STREAM_EVENT_PEER_SEND_SHUTDOWN:
        MsQuic->StreamShutdown(Stream, QUIC_STREAM_SHUTDOWN_FLAG_GRACEFUL, 0);
        break;
    case QUIC_STREAM_EVENT_SHUTDOWN_COMPLETE:
        MsQuic->StreamClose(Stream);
        break;
    default:
        break;
    }

    return QUIC_STATUS_SUCCESS;
}

_IRQL_requires_max_(DISPATCH_LEVEL)
_Function_class_(QUIC_CONNECTION_CALLBACK)
static
QUIC_STATUS
QUIC_API
ServerConnectionCallback(
    _In_ HQUIC Connection,
    _In_opt_ void* Context,
    _Inout_ QUIC_CONNECTION_EVENT* Event
    )
{
    UNREFERENCED_PARAMETER(Context);

    switch (Event->Type) {
    case QUIC_CONNECTION_EVENT_CONNECTED:
        printf("[conn][%p] Connected\n", Connection);
        break;
    case QUIC_CONNECTION_EVENT_SHUTDOWN_INITIATED_BY_TRANSPORT:
        printf("[conn][%p] Shutdown by transport, 0x%x\n", Connection, Event->SHUTDOWN_INITIATED_BY_TRANSPORT.Status);
        break;
    case QUIC_CONNECTION_EVENT_SHUTDOWN_INITIATED_BY_PEER:
        printf("[conn][%p] Shutdown by peer, 0x%llu\n", Connection, (unsigned long long)Event->SHUTDOWN_INITIATED_BY_PEER.ErrorCode);
        break;
    case QUIC_CONNECTION_EVENT_PEER_STREAM_STARTED:
        MsQuic->SetCallbackHandler(Event->PEER_STREAM_STARTED.Stream, (void*)ServerStreamCallback, NULL);
        break;
    case QUIC_CONNECTION_EVENT_SHUTDOWN_COMPLETE:
        MsQuic->ConnectionClose(Connection);
        break;
    default:
        break;
    }

    return QUIC_STATUS_SUCCESS;
}

_IRQL_requires_max_(DISPATCH_LEVEL)
_Function_class_(QUIC_CONNECTION_CALLBACK)
static
QUIC_STATUS
QUIC_API
ClientConnectionCallback(
    _In_ HQUIC Connection,
    _In_opt_ void* Context,
    _Inout_ QUIC_CONNECTION_EVENT* Event
    )
{
    UNREFERENCED_PARAMETER(Context);

    switch (Event->Type) {
    case QUIC_CONNECTION_EVENT_CONNECTED:
        printf("[conn][%p] Connected (XDP map path validated)\n", Connection);
        MsQuic->ConnectionShutdown(Connection, QUIC_CONNECTION_SHUTDOWN_FLAG_NONE, 0);
        break;
    case QUIC_CONNECTION_EVENT_SHUTDOWN_INITIATED_BY_TRANSPORT:
        printf("[conn][%p] Shutdown by transport, 0x%x\n", Connection, Event->SHUTDOWN_INITIATED_BY_TRANSPORT.Status);
        break;
    case QUIC_CONNECTION_EVENT_SHUTDOWN_INITIATED_BY_PEER:
        printf("[conn][%p] Shutdown by peer, 0x%llu\n", Connection, (unsigned long long)Event->SHUTDOWN_INITIATED_BY_PEER.ErrorCode);
        break;
    case QUIC_CONNECTION_EVENT_SHUTDOWN_COMPLETE:
        MsQuic->ConnectionClose(Connection);
        break;
    default:
        break;
    }

    return QUIC_STATUS_SUCCESS;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
_Function_class_(QUIC_LISTENER_CALLBACK)
static
QUIC_STATUS
QUIC_API
ServerListenerCallback(
    _In_ HQUIC Listener,
    _In_opt_ void* Context,
    _Inout_ QUIC_LISTENER_EVENT* Event
    )
{
    UNREFERENCED_PARAMETER(Listener);
    UNREFERENCED_PARAMETER(Context);

    if (Event->Type == QUIC_LISTENER_EVENT_NEW_CONNECTION) {
        MsQuic->SetCallbackHandler(Event->NEW_CONNECTION.Connection, (void*)ServerConnectionCallback, NULL);
        return MsQuic->ConnectionSetConfiguration(Event->NEW_CONNECTION.Connection, Configuration);
    }

    return QUIC_STATUS_NOT_SUPPORTED;
}

static
BOOLEAN
LoadServerConfiguration(
    _In_ int argc,
    _In_reads_(argc) _Null_terminated_ char* argv[]
    )
{
    QUIC_SETTINGS Settings = {0};
    QUIC_STATUS Status;

    QUIC_SETTINGS XdpSettings = {0};
    XdpSettings.XdpEnabled = TRUE;
    XdpSettings.IsSet.XdpEnabled = TRUE;
    Status = MsQuic->SetParam(NULL, QUIC_PARAM_GLOBAL_SETTINGS, sizeof(XdpSettings), &XdpSettings);
    if (QUIC_FAILED(Status)) {
        printf("Failed to enable XDP globally, 0x%x!\n", Status);
        return FALSE;
    }

    QUIC_CREDENTIAL_CONFIG_HELPER Config;
    memset(&Config, 0, sizeof(Config));
    Config.CredConfig.Flags = QUIC_CREDENTIAL_FLAG_NONE;

    const char* Cert;
    const char* KeyFile;
    if ((Cert = GetValue(argc, argv, "cert_hash")) != NULL) {
        uint32_t CertHashLen =
            DecodeHexBuffer(
                Cert,
                sizeof(Config.CertHash.ShaHash),
                Config.CertHash.ShaHash);
        if (CertHashLen != sizeof(Config.CertHash.ShaHash)) {
            printf("Invalid cert hash length.\n");
            return FALSE;
        }
        Config.CredConfig.Type = QUIC_CREDENTIAL_TYPE_CERTIFICATE_HASH;
        Config.CredConfig.CertificateHash = &Config.CertHash;
    } else if ((Cert = GetValue(argc, argv, "cert_file")) != NULL &&
               (KeyFile = GetValue(argc, argv, "key_file")) != NULL) {
        const char* Password = GetValue(argc, argv, "password");
        if (Password != NULL) {
            Config.CertFileProtected.CertificateFile = (char*)Cert;
            Config.CertFileProtected.PrivateKeyFile = (char*)KeyFile;
            Config.CertFileProtected.PrivateKeyPassword = (char*)Password;
            Config.CredConfig.Type = QUIC_CREDENTIAL_TYPE_CERTIFICATE_FILE_PROTECTED;
            Config.CredConfig.CertificateFileProtected = &Config.CertFileProtected;
        } else {
            Config.CertFile.CertificateFile = (char*)Cert;
            Config.CertFile.PrivateKeyFile = (char*)KeyFile;
            Config.CredConfig.Type = QUIC_CREDENTIAL_TYPE_CERTIFICATE_FILE;
            Config.CredConfig.CertificateFile = &Config.CertFile;
        }
    } else {
        printf("Must specify '-cert_hash' or '-cert_file' with '-key_file'.\n");
        return FALSE;
    }

    if (QUIC_FAILED(Status = MsQuic->ConfigurationOpen(Registration, &Alpn, 1, &Settings, sizeof(Settings), NULL, &Configuration))) {
        printf("ConfigurationOpen failed, 0x%x!\n", Status);
        return FALSE;
    }

    if (QUIC_FAILED(Status = MsQuic->ConfigurationLoadCredential(Configuration, &Config.CredConfig))) {
        printf("ConfigurationLoadCredential failed, 0x%x!\n", Status);
        return FALSE;
    }

    return TRUE;
}

static
BOOLEAN
LoadClientConfiguration(void)
{
    QUIC_SETTINGS Settings = {0};
    QUIC_STATUS Status;

    QUIC_SETTINGS XdpSettings = {0};
    XdpSettings.XdpEnabled = TRUE;
    XdpSettings.IsSet.XdpEnabled = TRUE;
    Status = MsQuic->SetParam(NULL, QUIC_PARAM_GLOBAL_SETTINGS, sizeof(XdpSettings), &XdpSettings);
    if (QUIC_FAILED(Status)) {
        printf("Failed to enable XDP globally, 0x%x!\n", Status);
        return FALSE;
    }

    QUIC_CREDENTIAL_CONFIG CredConfig;
    memset(&CredConfig, 0, sizeof(CredConfig));
    CredConfig.Type = QUIC_CREDENTIAL_TYPE_NONE;
    CredConfig.Flags = QUIC_CREDENTIAL_FLAG_CLIENT | QUIC_CREDENTIAL_FLAG_NO_CERTIFICATE_VALIDATION;

    if (QUIC_FAILED(Status = MsQuic->ConfigurationOpen(Registration, &Alpn, 1, &Settings, sizeof(Settings), NULL, &Configuration))) {
        printf("ConfigurationOpen failed, 0x%x!\n", Status);
        return FALSE;
    }

    if (QUIC_FAILED(Status = MsQuic->ConfigurationLoadCredential(Configuration, &CredConfig))) {
        printf("ConfigurationLoadCredential failed, 0x%x!\n", Status);
        return FALSE;
    }

    return TRUE;
}

static
BOOLEAN
ConfigureXdpMap(
    _In_ int argc,
    _In_reads_(argc) _Null_terminated_ char* argv[]
    )
{
    const char* MapIfIndexStr = GetValue(argc, argv, "xdp_map_ifindex");
    if (MapIfIndexStr == NULL) {
        printf("Missing required argument '-xdp_map_ifindex:<N>'.\n");
        return FALSE;
    }

    UINT32 MapIfIndex = (UINT32)atoi(MapIfIndexStr);
    if (MapIfIndex == 0) {
        printf("Invalid interface index '%s'.\n", MapIfIndexStr);
        return FALSE;
    }

    char InputBuf[64];
    UINT_PTR HandleValue;

    printf("=== XDP Map Mode (Consumer) ===\n");
    printf("  PID: %u\n", (unsigned)GetCurrentProcessId());
    printf("  IfIndex: %u\n\n", MapIfIndex);
    printf("Start orchestrator in another terminal:\n");

    const char* CibirHint = GetValue(argc, argv, "cibir_id");
    if (CibirHint != NULL) {
        printf("  orchestrator -TargetPid %u -IfIndex %u -UdpPort %u -CibirId %s\n",
            (unsigned)GetCurrentProcessId(), MapIfIndex, UdpPort, CibirHint);
    } else {
        printf("  orchestrator -TargetPid %u -IfIndex %u -UdpPort %u\n",
            (unsigned)GetCurrentProcessId(), MapIfIndex, UdpPort);
    }

    printf("\nPaste XSKMAP handle value here (hex): ");
    fflush(stdout);

    if (fgets(InputBuf, sizeof(InputBuf), stdin) == NULL) {
        printf("Failed to read input.\n");
        return FALSE;
    }

    HandleValue = (UINT_PTR)_strtoui64(InputBuf, NULL, 16);
    if (HandleValue == 0 || HandleValue == (UINT_PTR)INVALID_HANDLE_VALUE) {
        printf("Invalid handle value: %s\n", InputBuf);
        return FALSE;
    }

    QUIC_XDP_MAP_CONFIG MapConfig;
    MapConfig.InterfaceIndex = MapIfIndex;
    MapConfig.MapHandle = (QUIC_XDP_MAP_HANDLE)HandleValue;

    QUIC_STATUS Status = MsQuic->SetParam(
        NULL,
        QUIC_PARAM_GLOBAL_XDP_MAP_CONFIG,
        sizeof(MapConfig),
        &MapConfig);
    if (QUIC_FAILED(Status)) {
        printf("SetParam(QUIC_PARAM_GLOBAL_XDP_MAP_CONFIG) failed, 0x%x!\n", Status);
        return FALSE;
    }

    printf("XDP map config set (IfIndex=%u, MapHandle=0x%IX).\n\n", MapIfIndex, HandleValue);
    return TRUE;
}

static
void
RunServer(
    _In_ int argc,
    _In_reads_(argc) _Null_terminated_ char* argv[]
    )
{
    QUIC_STATUS Status;
    HQUIC Listener = NULL;

    if (!LoadServerConfiguration(argc, argv)) {
        return;
    }

    QUIC_ADDR Address = {0};
    QuicAddrSetFamily(&Address, QUIC_ADDRESS_FAMILY_UNSPEC);
    QuicAddrSetPort(&Address, UdpPort);

    if (QUIC_FAILED(Status = MsQuic->ListenerOpen(Registration, ServerListenerCallback, NULL, &Listener))) {
        printf("ListenerOpen failed, 0x%x!\n", Status);
        goto Error;
    }

    const char* CibirIdHex = GetValue(argc, argv, "cibir_id");
    if (CibirIdHex != NULL) {
        uint8_t CibirId[XDPMAP_CIBIR_RAW_MAX_LEN];
        uint32_t CibirIdLen = DecodeHexBuffer(CibirIdHex, sizeof(CibirId), CibirId);
        if (CibirIdLen < 2) {
            printf("CIBIR ID too short (need offset + >=1 CID byte).\n");
            goto Error;
        }

        if (QUIC_FAILED(Status = MsQuic->SetParam(Listener, QUIC_PARAM_LISTENER_CIBIR_ID, CibirIdLen, CibirId))) {
            printf("SetParam(QUIC_PARAM_LISTENER_CIBIR_ID) failed, 0x%x!\n", Status);
            goto Error;
        }
    }

    if (QUIC_FAILED(Status = MsQuic->ListenerStart(Listener, &Alpn, 1, &Address))) {
        printf("ListenerStart failed, 0x%x!\n", Status);
        goto Error;
    }

    printf("Listening on UDP/%u with XDP map mode enabled.\n", UdpPort);
    printf("Press Enter to exit.\n");
    (void)getchar();

Error:
    if (Listener != NULL) {
        MsQuic->ListenerClose(Listener);
    }
}

static
void
RunClient(
    _In_ int argc,
    _In_reads_(argc) _Null_terminated_ char* argv[]
    )
{
    QUIC_STATUS Status;
    HQUIC Connection = NULL;

    const char* Target = GetValue(argc, argv, "target");
    if (Target == NULL) {
        printf("Missing required argument '-target:<host_or_ip>' in client mode.\n");
        return;
    }

    if (!LoadClientConfiguration()) {
        return;
    }

    if (QUIC_FAILED(Status = MsQuic->ConnectionOpen(Registration, ClientConnectionCallback, NULL, &Connection))) {
        printf("ConnectionOpen failed, 0x%x!\n", Status);
        goto Error;
    }

    printf("[conn][%p] Connecting to %s:%u...\n", Connection, Target, UdpPort);
    if (QUIC_FAILED(Status = MsQuic->ConnectionStart(Connection, Configuration, QUIC_ADDRESS_FAMILY_UNSPEC, Target, UdpPort))) {
        printf("ConnectionStart failed, 0x%x!\n", Status);
        goto Error;
    }

    printf("Client started. Press Enter to exit.\n");
    (void)getchar();

    return;

Error:
    if (Connection != NULL) {
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
    QUIC_STATUS Status = QUIC_STATUS_SUCCESS;
    BOOLEAN ClientMode = GetFlag(argc, argv, "client");

    if (GetFlag(argc, argv, "help") || GetFlag(argc, argv, "?")) {
        PrintUsage();
        return 0;
    }

    if (QUIC_FAILED(Status = MsQuicOpen2(&MsQuic))) {
        printf("MsQuicOpen2 failed, 0x%x!\n", Status);
        goto Error;
    }

    if (!ConfigureXdpMap(argc, argv)) {
        Status = QUIC_STATUS_INVALID_PARAMETER;
        goto Error;
    }

    if (QUIC_FAILED(Status = MsQuic->RegistrationOpen(&RegConfig, &Registration))) {
        printf("RegistrationOpen failed, 0x%x!\n", Status);
        goto Error;
    }

    if (ClientMode) {
        RunClient(argc, argv);
    } else {
        RunServer(argc, argv);
    }

Error:
    if (MsQuic != NULL) {
        if (Configuration != NULL) {
            MsQuic->ConfigurationClose(Configuration);
        }
        if (Registration != NULL) {
            MsQuic->RegistrationClose(Registration);
        }
        MsQuicClose(MsQuic);
    }

    return (int)Status;
}
