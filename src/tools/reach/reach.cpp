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

#define QUIC_API_ENABLE_PREVIEW_FEATURES

#include "quic_datapath.h"
#include "msquic.h"

uint16_t Port = 443;
const char* ServerName = "localhost";
const char* ServerIp = nullptr;
QUIC_ADDR ServerAddress = {0};
std::vector<const char*> ALPNs({ "h3", "h3-29", "hq-interop", "hq-29", "smb" });
const char* InputAlpn = nullptr;
uint32_t InputVersion = 0;

const QUIC_API_TABLE* MsQuic;
HQUIC Registration;

struct ConnectionContext {
    bool GotConnected;
    uint32_t QuicVersion;
    CXPLAT_EVENT Complete;
};

_IRQL_requires_max_(PASSIVE_LEVEL)
_Function_class_(QUIC_CONNECTION_CALLBACK)
QUIC_STATUS
QUIC_API
ConnectionHandler(
    _In_ HQUIC Connection,
    _In_opt_ void* _Context,
    _Inout_ QUIC_CONNECTION_EVENT* Event
    )
{
    auto Context = (ConnectionContext*)_Context;
    switch (Event->Type) {
    case QUIC_CONNECTION_EVENT_CONNECTED: {
        Context->GotConnected = true;
        MsQuic->ConnectionShutdown(Connection, QUIC_CONNECTION_SHUTDOWN_FLAG_NONE, 0);
        uint32_t Size = sizeof(Context->QuicVersion);
        MsQuic->GetParam(Connection, QUIC_PARAM_CONN_QUIC_VERSION, &Size, &Context->QuicVersion);
        break;
    }
    case QUIC_CONNECTION_EVENT_SHUTDOWN_COMPLETE:
        MsQuic->ConnectionClose(Connection);
        CxPlatEventSet(Context->Complete);
        break;
    case QUIC_CONNECTION_EVENT_PEER_STREAM_STARTED:
        return QUIC_STATUS_NOT_SUPPORTED;
    default:
        break;
    }
    return QUIC_STATUS_SUCCESS;
}

CXPLAT_THREAD_CALLBACK(TestReachability, _Alpn)
{
    QUIC_BUFFER Alpn;
    Alpn.Buffer = (uint8_t*)_Alpn;
    Alpn.Length = (uint32_t)strlen((char*)_Alpn);

    QUIC_SETTINGS Settings{0};
    Settings.PeerUnidiStreamCount = 100;
    Settings.IsSet.PeerUnidiStreamCount = TRUE;
    Settings.IdleTimeoutMs = 10 * 1000;
    Settings.IsSet.IdleTimeoutMs = TRUE;

    HQUIC Configuration = nullptr;
    if (QUIC_FAILED(MsQuic->ConfigurationOpen(Registration, &Alpn, 1, &Settings, sizeof(Settings), nullptr, &Configuration))) {
        printf("ConfigurationOpen failed.\n");
        exit(1);
    }

    if (InputVersion) {
        QUIC_VERSION_SETTINGS VersionSettings{0};
        VersionSettings.AcceptableVersions = &InputVersion;
        VersionSettings.AcceptableVersionsLength = 1;
        if (QUIC_FAILED(MsQuic->SetParam(Configuration, QUIC_PARAM_CONFIGURATION_VERSION_SETTINGS, sizeof(VersionSettings), &VersionSettings))) {
            printf("Version SetParam failed.\n");
            exit(1);
        }
    }

    QUIC_CREDENTIAL_CONFIG CredConfig;
    CxPlatZeroMemory(&CredConfig, sizeof(CredConfig));
    CredConfig.Flags = QUIC_CREDENTIAL_FLAG_CLIENT; // TODO - Disable certificate validation?

    if (QUIC_FAILED(MsQuic->ConfigurationLoadCredential(Configuration, &CredConfig))) {
        printf("ConfigurationOpen failed.\n");
        exit(1);
    }

    ConnectionContext Context = { false };
    CxPlatEventInitialize(&Context.Complete, TRUE, FALSE);

    HQUIC Connection = nullptr;
    if (QUIC_FAILED(MsQuic->ConnectionOpen(Registration, ConnectionHandler, &Context, &Connection))) {
        printf("ConnectionOpen failed.\n");
        exit(1);
    }

    if (QUIC_FAILED(MsQuic->SetParam(Connection, QUIC_PARAM_CONN_REMOTE_ADDRESS, sizeof(ServerAddress), &ServerAddress))) {
        printf("SetParam QUIC_PARAM_CONN_REMOTE_ADDRESS failed.\n");
        exit(1);
    }

    if (QUIC_FAILED(MsQuic->ConnectionStart(Connection, Configuration, QUIC_ADDRESS_FAMILY_UNSPEC, ServerName, Port))) {
        printf("ConnectionStart failed.\n");
        exit(1);
    }

    MsQuic->ConfigurationClose(Configuration);
    CxPlatEventWaitForever(Context.Complete);
    CxPlatEventUninitialize(Context.Complete);

    if (Context.GotConnected) {
        printf("  0x%08x %12s    reachable\n", Context.QuicVersion, (char*)_Alpn);
    } else {
        printf("             %12s  unreachable\n", (char*)_Alpn);
    }

    CXPLAT_THREAD_RETURN(0);
}

inline
_Ret_maybenull_ _Null_terminated_ const char*
GetValue(
    _In_ int argc,
    _In_reads_(argc) _Null_terminated_ char* argv[],
    _In_z_ const char* name
    )
{
    const size_t nameLen = strlen(name);
    for (int i = 0; i < argc; i++) {
        if (_strnicmp(argv[i] + 1, name, nameLen) == 0
            && strlen(argv[i]) > 1 + nameLen + 1
            && *(argv[i] + 1 + nameLen) == ':') {
            return argv[i] + 1 + nameLen + 1;
        }
    }
    return nullptr;
}

inline
_Success_(return != false)
bool
TryGetValue(
    _In_ int argc,
    _In_reads_(argc) _Null_terminated_ char* argv[],
    _In_z_ const char* name,
    _Out_ _Null_terminated_ const char** pValue
    )
{
    auto value = GetValue(argc, argv, name);
    if (!value) return false;
    *pValue = value;
    return true;
}

inline
_Success_(return != false)
bool
TryGetValue(
    _In_ int argc,
    _In_reads_(argc) _Null_terminated_ char* argv[],
    _In_z_ const char* name,
    _Out_ uint16_t* pValue
    )
{
    auto value = GetValue(argc, argv, name);
    if (!value) return false;
    *pValue = (uint16_t)atoi(value);
    return true;
}

inline
_Success_(return != false)
bool
TryGetValue(
    _In_ int argc,
    _In_reads_(argc) _Null_terminated_ char* argv[],
    _In_z_ const char* name,
    _Out_ uint32_t* pValue
    )
{
    auto value = GetValue(argc, argv, name);
    if (!value) return false;
    char* End;
#ifdef _WIN32
    *pValue = (uint32_t)_strtoui64(value, &End, 10);
#else
    *pValue = (uint32_t)strtoull(value, &End, 10);
#endif
    return true;
}

int
QUIC_MAIN_EXPORT
main(int argc, char **argv)
{
    if (argc > 1 &&
        (
            !strcmp(argv[1], "?") ||
            !strcmp(argv[1], "-?") ||
            !strcmp(argv[1], "--?") ||
            !strcmp(argv[1], "/?") ||
            !strcmp(argv[1], "help")
        )) {
        printf("Usage: quicreach.exe [-server:<name>] [-ip:<ip>] [-port:<number>] [-alpn:<alpn>] [-version:<quic_version>]\n");
        exit(1);
    }

    TryGetValue(argc, argv, "server", &ServerName);
    TryGetValue(argc, argv, "ip", &ServerIp);
    TryGetValue(argc, argv, "port", &Port);
    TryGetValue(argc, argv, "alpn", &InputAlpn);
    TryGetValue(argc, argv, "version", &InputVersion);

    CxPlatSystemLoad();
    CxPlatInitialize();

    if (ServerIp == nullptr) {
        CXPLAT_DATAPATH* Datapath = nullptr;
        if (QUIC_FAILED(
            CxPlatDataPathInitialize(
                0,
                NULL,
                NULL,
                &Datapath))) {
            printf("CxPlatDataPathInitialize failed.\n");
            exit(1);
        }
        if (QUIC_FAILED(
            CxPlatDataPathResolveAddress(
                Datapath,
                ServerName,
                &ServerAddress))) {
            printf("Failed to resolve IP address of '%s'.\n", ServerName);
            exit(1);
        }
        CxPlatDataPathUninitialize(Datapath);
    } else {
        if (!QuicAddrFromString(ServerIp, Port, &ServerAddress)) {
            printf("QuicAddrFromString failed.\n");
            exit(1);
        }
    }

    if (QUIC_FAILED(MsQuicOpen2(&MsQuic))) {
        printf("MsQuicOpen2 failed.\n");
        exit(1);
    }

    const QUIC_REGISTRATION_CONFIG RegConfig = { "reach", QUIC_EXECUTION_PROFILE_LOW_LATENCY };
    if (QUIC_FAILED(MsQuic->RegistrationOpen(&RegConfig, &Registration))) {
        printf("RegistrationOpen failed.\n");
        exit(1);
    }

    printf("\n%s:%hu:\n\n", ServerName, Port);

    std::vector<CXPLAT_THREAD> Threads;
    CXPLAT_THREAD_CONFIG Config = { 0, 0, "reach_worker", TestReachability, nullptr };

    if (InputAlpn != nullptr) {
        Config.Context = (void*)InputAlpn;
        CXPLAT_THREAD Thread;
        if (QUIC_FAILED(CxPlatThreadCreate(&Config, &Thread))) {
            printf("CxPlatThreadCreate failed.\n");
            exit(1);
        }
        Threads.push_back(Thread);
    } else {
        for (auto ALPN : ALPNs) {
            Config.Context = (void*)ALPN;
            CXPLAT_THREAD Thread;
            if (QUIC_FAILED(CxPlatThreadCreate(&Config, &Thread))) {
                printf("CxPlatThreadCreate failed.\n");
                exit(1);
            }
            Threads.push_back(Thread);
        }
    }

    for (auto Thread : Threads) {
        CxPlatThreadWait(&Thread);
        CxPlatThreadDelete(&Thread);
    }

    MsQuic->RegistrationClose(Registration);

    MsQuicClose(MsQuic);

    CxPlatUninitialize();
    CxPlatSystemUnload();

    return 0;
}
