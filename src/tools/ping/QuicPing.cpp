/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.

Abstract:

    QUIC PING Server/Client tool.

--*/

#include "QuicPing.h"
#include "quicip.h"
#if _WIN32
#include "QuicUPnP.h"
#endif

const QUIC_API_TABLE* MsQuic;
HQUIC Registration;
QUIC_SEC_CONFIG* SecurityConfig;
HQUIC Session;
PingTracker Tracker;
QUIC_PING_CONFIG PingConfig;

extern "C" void QuicTraceRundown(void) { }

void
PrintUsage()
{
    printf("quicping is a tool for sending and receiving data between a client and"
           " server via the QUIC networking protocol.\n");

    printf("\n  quicping.exe [options]\n");

    printf("\nServer options:\n");
    printf(
        "  -listen:<addr or *>         The local IP address to listen on, or * for all IP addresses.\n"
        "  -thumbprint:<cert_hash>     The hash or thumbprint of the certificate to use.\n"
        "  -cert_store:<store name>    The certificate store to search for the thumbprint in.\n"
        "  -machine_cert:<0/1>         Use the machine, or current user's, certificate store. (def:0)\n");

    printf("\nClient options:\n");
    printf(
        "  -target:<hostname>          The remote hostname or IP address to connect to.\n"
        "  -ip:<0/4/6>                 A hint for the resolving the hostname to an IP address. (def:0)\n"
        "  -remote:<addr>              A remote IP address to connect to.\n"
        "  -bind:<addr>                A local IP address to bind to.\n"
        "  -ver:<initial version>      The initial QUIC version number to use.\n"
        "  -resume:<bytes>             Resumption bytes for 0-RTT.\n"
        "  -connections:<####>         The number of connections to create. (def:%u)\n"
        "  -wait:<####>                The time the app waits for completion. (def:%u ms)\n"
        "  -psci:<0/1> (def:0)         Reconnect using preshared connection info.\n",
        DEFAULT_CLIENT_CONNECTION_COUNT,
        DEFAULT_WAIT_TIMEOUT);

    printf("\nCommon options:\n");
    printf(
#if _WIN32
        "  -comp:<####>                The compartment ID to run in.\n"
        "  -core:<####>                The CPU core to use for the main thread.\n"
#endif
        "  -alpn:<str>                 The ALPN to use. (def:%s)\n"
        "  -port:<####>                The UDP port of the server. (def:%u)\n"
        "  -encrypt:<0/1>              Enables/disables encryption. (def:%u)\n"
        "  -sendbuf:<0/1>              Whether to use send buffering. (def:%u)\n"
        "  -pacing:<0/1>               Enables/disables pacing. (def:%u)\n"
        "  -stats:<0/1>                Enables/disables printing statistics. (def:%u)\n"
        "  -exec:<0/1/2/3>             The execution profile to use. (def:%u)\n"
        "  -uni:<####>                 The number of unidirectional streams to open locally. (def:0)\n"
        "  -bidi:<####>                The number of bidirectional streams to open locally. (def:0)\n"
        "  -peer_uni:<####>            The number of unidirectional streams for the peer to open. (def:0)\n"
        "  -peer_bidi:<####>           The number of bidirectional streams for the peer to open. (def:0)\n"
        "  -length:<####>              The length of streams opened locally. (def:0)\n"
        "  -iosize:<####>              The size of each send request queued. (buffered def:%u) (nonbuffered def:%u)\n"
        "  -iocount:<####>             The number of outstanding send requests to queue per stream. (buffered def:%u) (nonbuffered def:%u)\n"
        "  -datagrams:<####>           The number of datagrams to open locally. (def:0)\n"
        "  -dlength:<####>             The max length of each datagram. (def:%u)\n"
        "  -timeout:<####>             Disconnect timeout for connection. (def:%u ms)\n"
        "  -idle:<####>                Idle timeout for connection. (def:%u ms)\n"
        "  -key_bytes:<####>           The number of bytes encrypted per key.\n"
        "  -selfsign:<0/1>             Use self signed test certificates.\n",
        DEFAULT_ALPN,
        DEFAULT_PORT,
        DEFAULT_USE_ENCRYPTION,
        DEFAULT_USE_SEND_BUF,
        DEFAULT_USE_PACING,
        DEFAULT_PRINT_STATISTICS,
        DEFAULT_EXECUTION_PROFILE,
        DEFAULT_SEND_IO_SIZE_BUFFERED, DEFAULT_SEND_IO_SIZE_NONBUFFERED,
        DEFAULT_SEND_COUNT_BUFFERED, DEFAULT_SEND_COUNT_NONBUFFERED,
        DEFAULT_DATAGRAM_MAX_LENGTH,
        DEFAULT_DISCONNECT_TIMEOUT,
        DEFAULT_IDLE_TIMEOUT);

    printf("\nServer Examples:\n");
    printf("  quicping.exe -listen:* -thumbprint:175342733b39d81c997817296c9b691172ca6b6e -bidi:10\n");
    printf("  quicping.exe -listen:2001:4898:d8:34:b912:426d:1c88:5859 -thumbprint:175342733b39d81c997817296c9b691172ca6b6e\n");

    printf("\nClient Examples:\n");
    printf("  quicping.exe -target:localhost -port:443 -ip:6 -uni:0\n");
    printf("  quicping.exe -target:localhost -connections:12 -uni:2 -length:100000\n");
}

void
ParseCommonCommands(
    _In_ int argc,
    _In_reads_(argc) _Null_terminated_ char* argv[]
    )
{
#if _WIN32
    uint16_t compartmentid;
    if (TryGetValue(argc, argv, "comp",  &compartmentid)) {
        NETIO_STATUS status;
        if (!NETIO_SUCCESS(status = SetCurrentThreadCompartmentId(compartmentid))) {
            printf("Failed to set compartment ID = %d: 0x%x\n", compartmentid, status);
            return;
        } else {
            printf("Running in Compartment %d\n", compartmentid);
        }
    }

    uint8_t cpuCore;
    if (TryGetValue(argc, argv, "core",  &cpuCore)) {
        SetThreadAffinityMask(GetCurrentThread(), (DWORD_PTR)(1ull << cpuCore));
    }
#endif

    if (PingConfig.PsciAddrSet) {
        PingConfig.ALPN[0].Buffer = (uint8_t*)PSCI_ALPN;
        PingConfig.ALPN[0].Length = (uint32_t)strlen(PSCI_ALPN);
        PingConfig.AlpnCount++;
    }

    const char* alpn = DEFAULT_ALPN;
    TryGetValue(argc, argv, "alpn", &alpn);
    PingConfig.ALPN[PingConfig.AlpnCount].Buffer = (uint8_t*)alpn;
    PingConfig.ALPN[PingConfig.AlpnCount].Length = (uint32_t)strlen(alpn);
    PingConfig.AlpnCount++;

    uint16_t port = DEFAULT_PORT;
    TryGetValue(argc, argv, "port", &port);
    if (PingConfig.ServerMode) {
        QuicAddrSetPort(&PingConfig.LocalIpAddr, port);
    } else {
        QuicAddrSetPort(&PingConfig.Client.RemoteIpAddr, port);
    }

    uint16_t useEncryption = DEFAULT_USE_ENCRYPTION;
    TryGetValue(argc, argv, "encrypt", &useEncryption);
    PingConfig.UseEncryption = useEncryption != 0;

    uint16_t useSendBuffer = DEFAULT_USE_SEND_BUF;
    TryGetValue(argc, argv, "sendbuf", &useSendBuffer);
    PingConfig.UseSendBuffer = useSendBuffer != 0;

    uint16_t usePacing = DEFAULT_USE_PACING;
    TryGetValue(argc, argv, "pacing", &usePacing);
    PingConfig.UsePacing = usePacing != 0;

    uint16_t printStats = DEFAULT_PRINT_STATISTICS;
    TryGetValue(argc, argv, "stats", &printStats);
    PingConfig.PrintStats = printStats != 0;

    uint64_t uniStreams = 0;
    TryGetValue(argc, argv, "uni", &uniStreams);
    PingConfig.LocalUnidirStreamCount = uniStreams;

    uint64_t bidiStreams = 0;
    TryGetValue(argc, argv, "bidi", &bidiStreams);
    PingConfig.LocalBidirStreamCount = bidiStreams;

    uint16_t peerUniStreams = 0;
    TryGetValue(argc, argv, "peer_uni", &peerUniStreams);
    PingConfig.PeerUnidirStreamCount = peerUniStreams;

    uint16_t peerBidiStreams = 0;
    TryGetValue(argc, argv, "peer_bidi", &peerBidiStreams);
    PingConfig.PeerBidirStreamCount = peerBidiStreams;

    uint64_t streamLength = 0;
    TryGetValue(argc, argv, "length", &streamLength);
    PingConfig.StreamPayloadLength = streamLength;

    uint32_t ioSize = PingConfig.UseSendBuffer ? DEFAULT_SEND_IO_SIZE_BUFFERED : DEFAULT_SEND_IO_SIZE_NONBUFFERED;
    TryGetValue(argc, argv, "iosize", &ioSize);
    PingConfig.IoSize = ioSize;

    uint32_t ioCount = PingConfig.UseSendBuffer ? DEFAULT_SEND_COUNT_BUFFERED : DEFAULT_SEND_COUNT_NONBUFFERED;
    TryGetValue(argc, argv, "iocount", &ioCount);
    PingConfig.IoCount = ioCount;

    uint64_t datagrams = 0;
    TryGetValue(argc, argv, "datagrams", &datagrams);
    PingConfig.LocalDatagramCount = datagrams;

    uint16_t datagramMaxLength = DEFAULT_DATAGRAM_MAX_LENGTH;
    TryGetValue(argc, argv, "dlength", &datagramMaxLength);
    PingConfig.DatagramMaxLength = datagramMaxLength;

    uint32_t disconnectTimeout = DEFAULT_DISCONNECT_TIMEOUT;
    TryGetValue(argc, argv, "timeout", &disconnectTimeout);
    PingConfig.DisconnectTimeout = disconnectTimeout;

    uint64_t idleTimeout = DEFAULT_IDLE_TIMEOUT;
    TryGetValue(argc, argv, "idle", &idleTimeout);
    PingConfig.IdleTimeout = idleTimeout;

    PingConfig.MaxBytesPerKey = UINT64_MAX;
    TryGetValue(argc, argv, "key_bytes", &PingConfig.MaxBytesPerKey);

    uint32_t connections = PingConfig.ConnectionCount;
    TryGetValue(argc, argv, "connections", &connections);
    PingConfig.ConnectionCount = connections;

    //
    // Initialize internal memory structures based on the configuration.
    //

    QuicPingRawIoBuffer = new uint8_t[PingConfig.IoSize];
}

void
ParseServerCommand(
    _In_ int argc,
    _In_reads_(argc) _Null_terminated_ char* argv[]
    )
{
    PingConfig.ServerMode = true;

    const char* localAddress = nullptr;
    if (!TryGetValue(argc, argv, "listen", &localAddress)) {
        printf("Must specify -listen for server mode\n");
        return;
    }
    if (!ConvertArgToAddress(localAddress, 0, &PingConfig.LocalIpAddr)) {
        printf("Failed to decode IP address: '%s'!\nMust be *, a IPv4 or a IPv6 address.\n", localAddress);
        return;
    }

    QUIC_SEC_CONFIG_PARAMS* selfSignedCertParams = nullptr;

    uint16_t useSelfSigned = 0;
    if (!TryGetValue(argc, argv, "selfsign", &useSelfSigned)) {

#if _WIN32
        const char* certThumbprint;
        if (!TryGetValue(argc, argv, "thumbprint", &certThumbprint)) {
            printf("Must specify -thumbprint: for server mode.\n");
            return;
        }
        const char* certStoreName;
        if (!TryGetValue(argc, argv, "cert_store", &certStoreName)) {
            SecurityConfig = GetSecConfigForThumbprint(MsQuic, Registration, certThumbprint);
            if (SecurityConfig == nullptr) {
                printf("Failed to create security configuration for thumbprint:'%s'.\n", certThumbprint);
                return;
            }
        } else {
            uint32_t machineCert = 0;
            TryGetValue(argc, argv, "machine_cert", &machineCert);
            QUIC_CERTIFICATE_HASH_STORE_FLAGS flags =
                machineCert ? QUIC_CERTIFICATE_HASH_STORE_FLAG_MACHINE_STORE : QUIC_CERTIFICATE_HASH_STORE_FLAG_NONE;

            SecurityConfig = GetSecConfigForThumbprintAndStore(MsQuic, Registration, flags, certThumbprint, certStoreName);
            if (SecurityConfig == nullptr) {
                printf(
                    "Failed to create security configuration for thumbprint:'%s' and store: '%s'.\n",
                    certThumbprint,
                    certStoreName);
                return;
            }
        }
#else
        // TODO - Support getting sec config on Linux.
        printf("Loading sec config on Linux unsupported right now.\n");
        return;
#endif
    } else {
        selfSignedCertParams = QuicPlatGetSelfSignedCert(QUIC_SELF_SIGN_CERT_USER);
        if (!selfSignedCertParams) {
            printf("Failed to create platform self signed certificate\n");
            return;
        }

        SecurityConfig = GetSecConfigForSelfSigned(MsQuic, Registration, selfSignedCertParams);
        if (!SecurityConfig) {
            printf("Failed to create security config for self signed certificate\n");
            QuicPlatFreeSelfSignedCert(selfSignedCertParams);
            return;
        }
    }

    PingConfig.ConnectionCount = 0;
    ParseCommonCommands(argc, argv);
    QuicPingServerRun();

    MsQuic->SecConfigDelete(SecurityConfig);
    if (selfSignedCertParams) {
        QuicPlatFreeSelfSignedCert(selfSignedCertParams);
    }
}

void
ParseClientCommand(
    _In_ int argc,
    _In_reads_(argc) _Null_terminated_ char* argv[]
    )
{
    PingConfig.ServerMode = false;

    TryGetValue(argc, argv, "target", &PingConfig.Client.Target);

    uint16_t ip;
    if (TryGetValue(argc, argv, "ip", &ip)) {
        switch (ip) {
        case 4: QuicAddrSetFamily(&PingConfig.Client.RemoteIpAddr, AF_INET); break;
        case 6: QuicAddrSetFamily(&PingConfig.Client.RemoteIpAddr, AF_INET6); break;
        }
    }

    const char* remoteAddress;
    if (TryGetValue(argc, argv, "remote", &remoteAddress)) {
        PingConfig.Client.UseExplicitRemoteAddr = true;
        if (!ConvertArgToAddress(remoteAddress, 0, &PingConfig.Client.RemoteIpAddr)) {
            printf("Failed to decode IP address: '%s'!\nMust be *, a IPv4 or a IPv6 address.\n", remoteAddress);
            return;
        }
    }

    const char* localAddress;
    if (TryGetValue(argc, argv, "bind", &localAddress)) {
        if (!ConvertArgToAddress(localAddress, 0, &PingConfig.LocalIpAddr)) {
            printf("Failed to decode IP address: '%s'!\nMust be *, a IPv4 or a IPv6 address.\n", localAddress);
            return;
        }
    }

    uint32_t version = 0;
    TryGetValue(argc, argv, "ver", &version);
    PingConfig.Client.Version = version;

    TryGetValue(argc, argv, "resume", &PingConfig.Client.ResumeToken);

    uint32_t waitTimeout = DEFAULT_WAIT_TIMEOUT;
    TryGetValue(argc, argv, "wait", &waitTimeout);
    PingConfig.Client.WaitTimeout = waitTimeout;

    uint16_t usePsci = FALSE;
    TryGetValue(argc, argv, "psci", &usePsci);
    PingConfig.PsciAddrSet = PingConfig.PsciAddrSet && usePsci != 0;

    PingConfig.ConnectionCount = DEFAULT_CLIENT_CONNECTION_COUNT;
    ParseCommonCommands(argc, argv);
    QuicPingClientRun();
}

#if _WIN32
bool
AddUPnPMapping(
    QUIC_UPNP* UPnP
    )
{
    QUIC_ADDR_STR ExternalIP = { 0 };
    if (PingConfig.PublicPsciAddr.si_family == AF_INET) {
        RtlIpv4AddressToStringA(
            &PingConfig.PublicPsciAddr.Ipv4.sin_addr,
            ExternalIP.Address);
    } else {
        RtlIpv6AddressToStringA(
            &PingConfig.PublicPsciAddr.Ipv6.sin6_addr,
            ExternalIP.Address);
    }

    QUIC_ADDR_STR InternalIP = { 0 };
    if (PingConfig.PublicPsciAddr.si_family == AF_INET) {
        RtlIpv4AddressToStringA(
            &PingConfig.LocalPsciAddr.Ipv4.sin_addr,
            InternalIP.Address);
    } else {
        RtlIpv6AddressToStringA(
            &PingConfig.LocalPsciAddr.Ipv6.sin6_addr,
            InternalIP.Address);
    }

    char Description[64];
    sprintf(Description, "QUIC :%hu", QuicAddrGetPort(&PingConfig.LocalPsciAddr));

    return
        0 ==
        QuicUPnPAddStaticMapping(
            UPnP,
            "UDP",
            ExternalIP.Address,
            QuicAddrGetPort(&PingConfig.PublicPsciAddr),
            InternalIP.Address,
            QuicAddrGetPort(&PingConfig.LocalPsciAddr),
            Description);
}
#endif

int
QUIC_MAIN_EXPORT
main(
    _In_ int argc,
    _In_reads_(argc) _Null_terminated_ char* argv[]
    )
{
    int ErrorCode = -1;
    uint16_t execProfile = DEFAULT_EXECUTION_PROFILE;
    QUIC_REGISTRATION_CONFIG RegConfig = { "quicping", DEFAULT_EXECUTION_PROFILE };
#if _WIN32
    QUIC_UPNP* UPnP = nullptr;
    bool MappingAdded = false;
#endif

    QuicPlatformSystemLoad();
    QuicPlatformInitialize();

    if (argc < 2) {
        PrintUsage();
        goto Error;
    }

    if (QUIC_FAILED(MsQuicOpen(&MsQuic))) {
        printf("MsQuicOpen failed!\n");
        goto Error;
    }

    TryGetValue(argc, argv, "exec", &execProfile);
    RegConfig.ExecutionProfile = (QUIC_EXECUTION_PROFILE)execProfile;

    if (QUIC_FAILED(MsQuic->RegistrationOpen(&RegConfig, &Registration))) {
        printf("RegistrationOpen failed!\n");
        MsQuicClose(MsQuic);
        goto Error;
    }

    if (QUIC_FAILED(
        MsQuicGetPublicIPEx(
            MsQuic,
            Registration,
            "quic.westus.cloudapp.azure.com",
            TRUE,
            &PingConfig.LocalPsciAddr,
            &PingConfig.PublicPsciAddr))) {
        printf("Failed to resolve public IP address. 'psci' feature will not work.\n");
    } else {
        PingConfig.PsciAddrSet = true;
        QUIC_ADDR_STR AddrStr = { 0 };
        //QuicAddrToString(&PingConfig.LocalPsciAddr, &AddrStr);
        //printf(" Local IP: %s\n", AddrStr.Address);
        QuicAddrToString(&PingConfig.PublicPsciAddr, &AddrStr);
        printf("Public IP: %s\n", AddrStr.Address);
#if _WIN32
        UPnP = QuicUPnPInitialize();
        if (UPnP) {
            QuicUPnPRemoveStaticMappingByPrefix(UPnP, "QUIC");
            MappingAdded = AddUPnPMapping(UPnP);
        }
#endif
    }

    //
    // Parse input to see if we are a client or server
    //
    if (GetValue(argc, argv, "listen")) {
        ParseServerCommand(argc, argv);
    } else if (GetValue(argc, argv, "target")) {
        ParseClientCommand(argc, argv);
    } else {
        printf("Invalid usage!\n\n");
        PrintUsage();
    }

    ErrorCode = 0;
    delete [] QuicPingRawIoBuffer;
    MsQuic->RegistrationClose(Registration);
    MsQuicClose(MsQuic);

Error:

#if _WIN32
    if (MappingAdded) {
        QuicUPnPRemoveStaticMapping(UPnP, "UDP", QuicAddrGetPort(&PingConfig.PublicPsciAddr));
    }
    QuicUPnPUninitialize(UPnP);
#endif

    QuicPlatformUninitialize();
    QuicPlatformSystemUnload();

    return ErrorCode;
}
