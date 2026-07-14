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
            quicxdpmapserver.exe -xdp_map_ifindex:<N> -cert_hash:<hash>
            (will print to stdout the PID)

        2. On a separate terminal, run the trusted orchestrator:
            orchestrator.exe -TargetPid <PID> -IfIndex <N> -UdpPort <port>
            (will print the duplicated XSKMAP handle value to stdout)

        3. Paste the printed handle value into the quicxdpmapserver's stdin
        4. Press Enter in the orchestrator terminal to attach the XDP program
        5. The quicxdpmapserver process can now start talking to other MsQuic clients via XDP maps with ALPN == 'sample'


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

const QUIC_REGISTRATION_CONFIG RegConfig = { "quicxdpmapserver", QUIC_EXECUTION_PROFILE_LOW_LATENCY };
const QUIC_BUFFER Alpn = { sizeof("sample") - 1, (uint8_t*)"sample" };
const uint16_t UdpPort = 4567;

const QUIC_API_TABLE* MsQuic;
HQUIC Registration;

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
void
PrintUsage(void)
{
    printf(
        "\n"
        "quicxdpmapserver: minimal XDP map consumer server.\n"
        "\n"
        "Usage:\n"
        "  quicxdpmapserver.exe -xdp_map_ifindex:<N> -cert_hash:<THUMBPRINT> [-cibir_id:<hex>]\n"
        "  quicxdpmapserver.exe -xdp_map_ifindex:<N> -cert_file:<path> -key_file:<path> [-password:<pwd>] [-cibir_id:<hex>]\n"
        "\n"
        "Required:\n"
        "  -xdp_map_ifindex:<N>  Interface index for XDP map mode.\n"
        "  -cert_hash:<...>      or -cert_file:<...> with -key_file:<...>.\n"
        "\n"
        "Optional:\n"
        "  -cibir_id:<hex>       CIBIR ID (offset byte + CID prefix bytes).\n"
    );
}

typedef struct SERVER_ARGS {
    UINT32 XdpMapIfIndex;
    const char* CertHash;
    const char* CertFile;
    const char* KeyFile;
    const char* Password;
    const char* CibirIdHex;
} SERVER_ARGS;

static
BOOLEAN
ParseArgs(
    _In_ int argc,
    _In_reads_(argc) _Null_terminated_ char* argv[],
    _Out_ SERVER_ARGS* Args
    )
{
    memset(Args, 0, sizeof(*Args));

    const char* IfIndexStr = GetValue(argc, argv, "xdp_map_ifindex");
    if (IfIndexStr == NULL) {
        printf("Missing required argument '-xdp_map_ifindex:<N>'.\n");
        return FALSE;
    }
    Args->XdpMapIfIndex = (UINT32)atoi(IfIndexStr);
    if (Args->XdpMapIfIndex == 0) {
        printf("Invalid interface index '%s'.\n", IfIndexStr);
        return FALSE;
    }

    Args->CertHash = GetValue(argc, argv, "cert_hash");
    Args->CertFile = GetValue(argc, argv, "cert_file");
    Args->KeyFile = GetValue(argc, argv, "key_file");
    Args->Password = GetValue(argc, argv, "password");
    Args->CibirIdHex = GetValue(argc, argv, "cibir_id");

    if (Args->CertHash == NULL &&
        (Args->CertFile == NULL || Args->KeyFile == NULL)) {
        printf("Must specify '-cert_hash' or '-cert_file' with '-key_file'.\n");
        return FALSE;
    }

    return TRUE;
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

    if (Event->Type == QUIC_LISTENER_EVENT_NEW_CONNECTION) {
        HQUIC Config = (HQUIC)Context;
        MsQuic->SetCallbackHandler(Event->NEW_CONNECTION.Connection, (void*)ServerConnectionCallback, NULL);
        return MsQuic->ConnectionSetConfiguration(Event->NEW_CONNECTION.Connection, Config);
    }

    return QUIC_STATUS_NOT_SUPPORTED;
}

static
BOOLEAN
LoadServerConfiguration(
    _In_ const SERVER_ARGS* Args,
    _Out_ HQUIC* ConfigurationOut
    )
{
    QUIC_SETTINGS Settings = {0};
    QUIC_STATUS Status;
    HQUIC Config = NULL;

    QUIC_SETTINGS XdpSettings = {0};
    XdpSettings.XdpEnabled = TRUE;
    XdpSettings.IsSet.XdpEnabled = TRUE;
    Status = MsQuic->SetParam(NULL, QUIC_PARAM_GLOBAL_SETTINGS, sizeof(XdpSettings), &XdpSettings);
    if (QUIC_FAILED(Status)) {
        printf("Failed to enable XDP globally, 0x%x!\n", Status);
        return FALSE;
    }

    QUIC_CREDENTIAL_CONFIG_HELPER CredHelper;
    memset(&CredHelper, 0, sizeof(CredHelper));
    CredHelper.CredConfig.Flags = QUIC_CREDENTIAL_FLAG_NONE;

    if (Args->CertHash != NULL) {
        uint32_t CertHashLen =
            XdpMapDecodeHexBuffer(
                Args->CertHash,
                sizeof(CredHelper.CertHash.ShaHash),
                CredHelper.CertHash.ShaHash);
        if (CertHashLen != sizeof(CredHelper.CertHash.ShaHash)) {
            printf("Invalid cert hash length.\n");
            return FALSE;
        }
        CredHelper.CredConfig.Type = QUIC_CREDENTIAL_TYPE_CERTIFICATE_HASH;
        CredHelper.CredConfig.CertificateHash = &CredHelper.CertHash;
    } else {
        if (Args->Password != NULL) {
            CredHelper.CertFileProtected.CertificateFile = (char*)Args->CertFile;
            CredHelper.CertFileProtected.PrivateKeyFile = (char*)Args->KeyFile;
            CredHelper.CertFileProtected.PrivateKeyPassword = (char*)Args->Password;
            CredHelper.CredConfig.Type = QUIC_CREDENTIAL_TYPE_CERTIFICATE_FILE_PROTECTED;
            CredHelper.CredConfig.CertificateFileProtected = &CredHelper.CertFileProtected;
        } else {
            CredHelper.CertFile.CertificateFile = (char*)Args->CertFile;
            CredHelper.CertFile.PrivateKeyFile = (char*)Args->KeyFile;
            CredHelper.CredConfig.Type = QUIC_CREDENTIAL_TYPE_CERTIFICATE_FILE;
            CredHelper.CredConfig.CertificateFile = &CredHelper.CertFile;
        }
    }

    if (QUIC_FAILED(Status = MsQuic->ConfigurationOpen(Registration, &Alpn, 1, &Settings, sizeof(Settings), NULL, &Config))) {
        printf("ConfigurationOpen failed, 0x%x!\n", Status);
        return FALSE;
    }

    if (QUIC_FAILED(Status = MsQuic->ConfigurationLoadCredential(Config, &CredHelper.CredConfig))) {
        printf("ConfigurationLoadCredential failed, 0x%x!\n", Status);
        MsQuic->ConfigurationClose(Config);
        return FALSE;
    }

    *ConfigurationOut = Config;
    return TRUE;
}

static
BOOLEAN
PromptForXdpMapHandle(
    _In_ const SERVER_ARGS* Args,
    _Out_ UINT_PTR* HandleValueOut
    )
{
    char InputBuf[64];

    printf("=== XDP Map Mode (Consumer) ===\n");
    printf("  PID: %u\n", (unsigned)GetCurrentProcessId());
    printf("  IfIndex: %u\n\n", Args->XdpMapIfIndex);
    printf("Start orchestrator in another terminal:\n");

    if (Args->CibirIdHex != NULL) {
        printf("  ./orchestrator.exe -TargetPid %u -IfIndex %u -UdpPort %u -CibirId %s\n",
            (unsigned)GetCurrentProcessId(), Args->XdpMapIfIndex, UdpPort, Args->CibirIdHex);
    } else {
        printf("  ./orchestrator.exe -TargetPid %u -IfIndex %u -UdpPort %u\n",
            (unsigned)GetCurrentProcessId(), Args->XdpMapIfIndex, UdpPort);
    }

    printf("\nPaste XSKMAP handle value here (hex): ");
    fflush(stdout);

    if (fgets(InputBuf, sizeof(InputBuf), stdin) == NULL) {
        printf("Failed to read input.\n");
        return FALSE;
    }

    *HandleValueOut = (UINT_PTR)_strtoui64(InputBuf, NULL, 16);
    if (*HandleValueOut == 0 || *HandleValueOut == (UINT_PTR)INVALID_HANDLE_VALUE) {
        printf("Invalid handle value: %s\n", InputBuf);
        return FALSE;
    }

    return TRUE;
}

static
BOOLEAN
ConfigureXdpMap(
    _In_ UINT32 IfIndex,
    _In_ QUIC_XDP_MAP_HANDLE MapHandle
    )
{
    QUIC_XDP_MAP_CONFIG MapConfig;
    MapConfig.InterfaceIndex = IfIndex;
    MapConfig.MapHandle = MapHandle;

    QUIC_STATUS Status = MsQuic->SetParam(
        NULL,
        QUIC_PARAM_GLOBAL_XDP_MAP_CONFIG,
        sizeof(MapConfig),
        &MapConfig);
    if (QUIC_FAILED(Status)) {
        printf("SetParam(QUIC_PARAM_GLOBAL_XDP_MAP_CONFIG) failed, 0x%x!\n", Status);
        return FALSE;
    }

    printf("XDP map config set (IfIndex=%u, MapHandle=0x%IX).\n\n", IfIndex, (UINT_PTR)MapHandle);
    return TRUE;
}

static
void
RunServer(
    _In_ const SERVER_ARGS* Args
    )
{
    QUIC_STATUS Status;
    HQUIC Listener = NULL;
    HQUIC Configuration = NULL;

    if (!LoadServerConfiguration(Args, &Configuration)) {
        return;
    }

    QUIC_ADDR Address = {0};
    QuicAddrSetFamily(&Address, QUIC_ADDRESS_FAMILY_UNSPEC);
    QuicAddrSetPort(&Address, UdpPort);

    if (QUIC_FAILED(Status = MsQuic->ListenerOpen(Registration, ServerListenerCallback, Configuration, &Listener))) {
        printf("ListenerOpen failed, 0x%x!\n", Status);
        goto Error;
    }

    if (Args->CibirIdHex != NULL) {
        uint8_t CibirId[XDPMAP_CIBIR_RAW_MAX_LEN];
        uint32_t CibirIdLen = XdpMapDecodeHexBuffer(Args->CibirIdHex, sizeof(CibirId), CibirId);
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
    if (Configuration != NULL) {
        MsQuic->ConfigurationClose(Configuration);
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

    if (GetFlag(argc, argv, "help") || GetFlag(argc, argv, "?")) {
        PrintUsage();
        return 0;
    }

    SERVER_ARGS Args;
    if (!ParseArgs(argc, argv, &Args)) {
        PrintUsage();
        return (int)QUIC_STATUS_INVALID_PARAMETER;
    }

    if (QUIC_FAILED(Status = MsQuicOpen2(&MsQuic))) {
        printf("MsQuicOpen2 failed, 0x%x!\n", Status);
        goto Error;
    }

    UINT_PTR MapHandleValue;
    if (!PromptForXdpMapHandle(&Args, &MapHandleValue)) {
        Status = QUIC_STATUS_INVALID_PARAMETER;
        goto Error;
    }

    if (!ConfigureXdpMap(Args.XdpMapIfIndex, (QUIC_XDP_MAP_HANDLE)MapHandleValue)) {
        Status = QUIC_STATUS_INVALID_PARAMETER;
        goto Error;
    }

    if (QUIC_FAILED(Status = MsQuic->RegistrationOpen(&RegConfig, &Registration))) {
        printf("RegistrationOpen failed, 0x%x!\n", Status);
        goto Error;
    }

    RunServer(&Args);

Error:
    if (MsQuic != NULL) {
        if (Registration != NULL) {
            MsQuic->RegistrationClose(Registration);
        }
        MsQuicClose(MsQuic);
    }

    return (int)Status;
}
