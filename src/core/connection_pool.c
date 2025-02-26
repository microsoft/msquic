/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.

Abstract:

    Definitions for the MsQuic Connection Pool API, which allows clients to
    create a pool of connections that are spread across RSS cores.

--*/

#include "precomp.h"

#ifdef QUIC_CLOG
#include "connection_pool.c.clog.h"
#endif

#define MAX_CONNECTION_POOL_RETRY_MULTIPLIER 2

_IRQL_requires_max_(PASSIVE_LEVEL)
QUIC_STATUS
QuicConnPoolGetStartingLocalAddress(
    _In_ QUIC_ADDR* RemoteAddress,
    _Out_ QUIC_ADDR* LocalAddress
    )
{
    CXPLAT_SOCKET* Socket = NULL;
    CXPLAT_UDP_CONFIG UdpConfig = { .RemoteAddress = RemoteAddress, };
    QUIC_STATUS Status =
        CxPlatSocketCreateUdp(MsQuicLib.Datapath, &UdpConfig, &Socket);
    if (QUIC_FAILED(Status)) {
        goto Error;
    }

    CxPlatSocketGetLocalAddress(Socket, LocalAddress);

Error:
    if (Socket != NULL) {
        CxPlatSocketDelete(Socket);
    }

    return Status;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
QUIC_STATUS
QuicConnPoolGetInterfaceIndexForLocalAddress(
    _In_ QUIC_ADDR* LocalAddress,
    _Out_ uint32_t* InterfaceIndex
    )
{
    CXPLAT_ADAPTER_ADDRESS* Addresses = NULL;
    uint32_t AddressesCount;

    *InterfaceIndex = 0;

    QUIC_STATUS Status =
        CxPlatDataPathGetLocalAddresses(
            MsQuicLib.Datapath,
            &Addresses,
            &AddressesCount);
    if (QUIC_FAILED(Status)) {
        goto Error;
    }

    for (uint32_t i = 0; i < AddressesCount; i++) {
        if (QuicAddrCompareIp(LocalAddress, &Addresses[i].Address)) {
            *InterfaceIndex = Addresses[i].InterfaceIndex;
            break;
        }
    }

    if (InterfaceIndex == 0) {
        Status = QUIC_STATUS_NOT_FOUND;
        QuicTraceLogError(
            ConnPoolLocalAddressNotFound,
            "[conp] Failed to find local address, 0x%x",
            Status);
        goto Error;
    }

Error:

    if (Addresses != NULL) {
        CXPLAT_FREE(Addresses, QUIC_POOL_DATAPATH_ADDRESSES);
    }

    return Status;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
QUIC_STATUS
QUIC_API
MsQuicConnectionPoolCreate(
    _In_ QUIC_CONNECTION_POOL_CONFIG* Config,
    _Out_writes_(Config->NumberOfConnections)
        HQUIC* ConnectionPool
    )
{
    QUIC_CONNECTION** Connections = NULL;
    CXPLAT_RSS_CONFIG* RssConfig = NULL;
    uint32_t* RssProcessors = NULL;
    uint32_t* ConnectionCounts = NULL;
    CXPLAT_TOEPLITZ_HASH ToeplitzHash;
    QUIC_STATUS Status = QUIC_STATUS_SUCCESS;
    uint32_t CreatedConnections = 0;

    if (Config == NULL || Config->NumberOfConnections == 0 || Config->Handler == NULL ||
        Config->ServerName == NULL || Config->ServerPort == 0 || ConnectionPool == NULL) {
        Status = QUIC_STATUS_INVALID_PARAMETER;
        QuicTraceLogError(
            ConnPoolInvalidParam,
            "[conp] Invalid parameter, 0x%x",
            Status);
        goto Error;
    }

    QuicTraceEvent(
        ApiEnter,
        "[ api] Enter %u (%p).",
        QUIC_TRACE_API_CONNECTION_POOL_CREATE,
        Config->Registration);

    CxPlatZeroMemory(ConnectionPool, sizeof(HQUIC) * Config->NumberOfConnections);

    //
    // Resolve the server name or use the remote address.
    //
    QUIC_ADDR ResolvedRemoteAddress = {.si_family = Config->Family, };
    if (Config->ServerAddress != NULL) {
         ResolvedRemoteAddress = *Config->ServerAddress;
    } else {
        Status =
            CxPlatDataPathResolveAddress(
                MsQuicLib.Datapath,
                Config->ServerName,
                &ResolvedRemoteAddress);
        if (QUIC_FAILED(Status)) {
            QuicTraceLogError(
                ConnPoolResolveAddress,
                "[conp] Failed to resolve address, 0x%x",
                Status);
            goto Error;
        }
    }

    QuicAddrSetPort(&ResolvedRemoteAddress, Config->ServerPort);

    //
    // Get the local address and a port to start from.
    //
    QUIC_ADDR LocalAddress;
    Status = QuicConnPoolGetStartingLocalAddress(&ResolvedRemoteAddress, &LocalAddress);
    if (QUIC_FAILED(Status)) {
        QuicTraceLogError(
            ConnPoolGetLocalAddress,
            "[conp] Failed to get local address, 0x%x",
            Status);
        goto Error;
    }

    uint32_t InterfaceIndex;
    Status = QuicConnPoolGetInterfaceIndexForLocalAddress(&LocalAddress, &InterfaceIndex);
    if (QUIC_FAILED(Status)) {
        goto Error;
    }

    Status = CxPlatDataPathRssConfigGet(InterfaceIndex, &RssConfig);
    if (QUIC_FAILED(Status)) {
        QuicTraceLogError(
            ConnPoolGetRssConfig,
            "[conp] Failed to get RSS config, 0x%x",
            Status);
        goto Error;
    }

    if ((LocalAddress.si_family == QUIC_ADDRESS_FAMILY_INET &&
            (RssConfig->HashTypes & CXPLAT_RSS_HASH_TYPE_UDP_IPV4) == 0) ||
        (LocalAddress.si_family == QUIC_ADDRESS_FAMILY_INET6 &&
            (RssConfig->HashTypes & CXPLAT_RSS_HASH_TYPE_UDP_IPV6) == 0)) {
        //
        // This RSS implementation doesn't support hashing UDP ports, which
        // means the connection pool can't spread connections across CPUs.
        //
        Status = QUIC_STATUS_NOT_SUPPORTED;
        QuicTraceLogError(
            ConnPoolRssNotSupported,
            "[conp] RSS not supported for UDP, 0x%x",
            Status);
        goto Error;
    }

    //
    // Prepare array of unique RSS processors.
    //
    RssProcessors =
        (uint32_t*)CXPLAT_ALLOC_PAGED(
            RssConfig->RssIndirectionTableLength,
            QUIC_POOL_TMP_ALLOC);
    if (RssProcessors == NULL) {
        Status = QUIC_STATUS_OUT_OF_MEMORY;
        QuicTraceEvent(
            AllocFailure,
            "Allocation of '%s' failed. (%llu bytes)",
            "RSS Processor List",
            RssConfig->RssIndirectionTableLength);
        goto Error;
    }

    uint32_t RssProcessorCount = 0;
    for (uint32_t i = 0; i < RssConfig->RssIndirectionTableLength / sizeof(uint32_t); i++) {
        uint32_t j;
        for (j = 0; j < RssProcessorCount; j++) {
            if (RssProcessors[j] == RssConfig->RssIndirectionTable[i]) {
                break;
            }
        }
        //
        // This is safe because the RssProcessor array is the same size as the indirection table.
        //
        if (j == RssProcessorCount) {
            CXPLAT_DBG_ASSERT(RssProcessorCount < RssConfig->RssIndirectionTableLength / sizeof(uint32_t));
            RssProcessors[RssProcessorCount++] = RssConfig->RssIndirectionTable[i];
        }
    }

    CXPLAT_DBG_ASSERT(RssProcessorCount <= RssConfig->RssIndirectionTableLength / sizeof(uint32_t));

    ConnectionCounts =
        (uint32_t*)CXPLAT_ALLOC_PAGED(
            sizeof(uint32_t) * RssProcessorCount,
            QUIC_POOL_TMP_ALLOC);
    if (ConnectionCounts == NULL) {
        Status = QUIC_STATUS_OUT_OF_MEMORY;
        QuicTraceEvent(
            AllocFailure,
            "Allocation of '%s' failed. (%llu bytes)",
            "RSS Connection Counts",
            sizeof(uint32_t) * RssProcessorCount);
        goto Error;
    }

    CxPlatZeroMemory(ConnectionCounts, sizeof(uint32_t) * RssProcessorCount);

    //
    // Initialize the Toeplitz hash.
    //
    if (RssConfig->RssSecretKeyLength > CXPLAT_TOEPLITZ_KEY_SIZE_MAX) {
        Status = QUIC_STATUS_INTERNAL_ERROR;
        QuicTraceLogError(
            ConnPoolRssSecretKeyTooLong,
            "[conp] RSS secret key too long, 0x%x",
            Status);
        goto Error;
    }
    CxPlatCopyMemory(&ToeplitzHash.HashKey, RssConfig->RssSecretKey, RssConfig->RssSecretKeyLength);
    ToeplitzHash.InputSize = CXPLAT_TOEPLITZ_INPUT_SIZE_IP;
    CxPlatToeplitzHashInitialize(&ToeplitzHash);

    Connections =
        (QUIC_CONNECTION**)CXPLAT_ALLOC_PAGED(
            sizeof(QUIC_CONNECTION*) * Config->NumberOfConnections,
            QUIC_POOL_TMP_ALLOC);
    if (Connections == NULL) {
        Status = QUIC_STATUS_OUT_OF_MEMORY;
        QuicTraceEvent(
            AllocFailure,
            "Allocation of '%s' failed. (%llu bytes)",
            "Temp Connection Pool",
            sizeof(QUIC_CONNECTION*) * Config->NumberOfConnections);
        goto Error;
    }

    //
    // Start creating connections and starting them.
    //

    const uint32_t ConnectionsPerProc = (Config->NumberOfConnections / RssProcessorCount) + 1;

    for (uint32_t i = 0; i < Config->NumberOfConnections; i++) {
        const uint32_t MaxCreationRetries = RssProcessorCount * MAX_CONNECTION_POOL_RETRY_MULTIPLIER;
        uint32_t RetryCount = 0;
        uint32_t RssProcIndex;
        for (; RetryCount < MaxCreationRetries; RetryCount++) {

            uint32_t NewPort = QuicAddrGetPort(&LocalAddress) + 1;
            if (NewPort > QUIC_ADDR_EPHEMERAL_PORT_MAX) {
                NewPort = QUIC_ADDR_EPHEMERAL_PORT_MIN;
            }
            QuicAddrSetPort(&LocalAddress, (uint16_t)NewPort);

            uint32_t RssHash = 0, Offset;
            //
            // Calculate the Toeplitz Hash as if receiving packets from the
            // ResolvedRemoteAddress to find the RSS processor.
            //
            CxPlatToeplitzHashComputeRss(
                &ToeplitzHash,
                &ResolvedRemoteAddress,
                &LocalAddress,
                &RssHash,
                &Offset);
            uint32_t Mask = (RssConfig->RssIndirectionTableLength / sizeof(uint32_t)) - 1;
            RssProcIndex = RssProcessorCount;
            CXPLAT_DBG_ASSERT((RssHash & Mask) < RssConfig->RssIndirectionTableLength / sizeof(uint32_t));
            uint32_t RssProc = RssConfig->RssIndirectionTable[RssHash & Mask];
            for (uint32_t j = 0; j < RssProcessorCount; j++) {
                if (RssProcessors[j] == RssProc) {
                    RssProcIndex = j;
                    break;
                }
            }
            CXPLAT_DBG_ASSERT(RssProcIndex < RssProcessorCount);
            if (ConnectionCounts[RssProcIndex] >= ConnectionsPerProc) {
                //
                // This processor already has enough connections on it, so try another port number.
                //
                continue;
            }

            uint16_t PartitionIndex =
                QuicLibraryGetPartitionFromProcessorIndex(RssProcessors[RssProcIndex]);

            Status =
                QuicConnAlloc(
                    (QUIC_REGISTRATION*)Config->Registration,
                    NULL,
                    NULL,
                    &PartitionIndex,
                    &Connections[i]);
            if (QUIC_FAILED(Status)) {
                QuicTraceLogError(
                    ConnPoolOpenConnection,
                    "[conp] Failed to open connection[%u], 0x%x",
                    i,
                    Status);
                goto Error;
            }
            CreatedConnections++;
            Connections[i]->ClientCallbackHandler = Config->Handler;
            if (Config->Context != NULL) {
                Connections[i]->ClientContext = Config->Context[i];
            }

            Status =
                QuicConnParamSet(
                    Connections[i],
                    QUIC_PARAM_CONN_REMOTE_ADDRESS,
                    sizeof(ResolvedRemoteAddress),
                    &ResolvedRemoteAddress);
            CXPLAT_DBG_ASSERT(QUIC_SUCCEEDED(Status));
            if (QUIC_FAILED(Status)) {
                QuicTraceLogError(
                    ConnPoolSetRemoteAddress,
                    "[conp] Failed to set remote address on connection[%u], 0x%x",
                    i,
                    Status);
                goto Error;
            }
            Status =
                QuicConnParamSet(
                    Connections[i],
                    QUIC_PARAM_CONN_LOCAL_ADDRESS,
                    sizeof(LocalAddress),
                    &LocalAddress);
            CXPLAT_DBG_ASSERT(QUIC_SUCCEEDED(Status));
            if (QUIC_FAILED(Status)) {
                QuicTraceLogError(
                    ConnPoolSetLocalAddress,
                    "[conp] Failed to set local address on connection[%u], 0x%x",
                    i,
                    Status);
                goto Error;
            }

            Status = QuicConnStart(
                Connections[i],
                (QUIC_CONFIGURATION*)Config->Configuration,
                Config->Family,
                Config->ServerName,
                Config->ServerPort,
                QUIC_CONN_START_FLAG_FAIL_SILENTLY);
            if (QUIC_FAILED(Status)) {
                QuicTraceLogError(
                    ConnPoolStartConnection,
                    "[conp] Failed to start connection[%u], 0x%x",
                    i,
                    Status);
                QuicConnRelease(Connections[i], QUIC_CONN_REF_HANDLE_OWNER);
                Connections[i] = NULL;
                CreatedConnections--;
                continue;
            }

            //
            // The connection was created successfully, add it to the count for this processor.
            //
            ConnectionCounts[RssProcIndex]++;
            break;
        }

        if (RetryCount == MaxCreationRetries) {
            Status = QUIC_STATUS_ADDRESS_IN_USE;
            QuicTraceLogError(
                ConnPoolMaxRetries,
                "[conp] Ran out of retries. MaxRetries %u, Iteration %u, Port %u, 0x%x",
                MaxCreationRetries,
                i,
                QuicAddrGetPort(&LocalAddress),
                Status);
            goto Error;
        }
    }

    CxPlatCopyMemory(ConnectionPool, Connections, sizeof(HQUIC) * Config->NumberOfConnections);

Error:
    if (Connections != NULL) {
        if (QUIC_FAILED(Status)) {
            for (uint32_t i = 0; i < CreatedConnections; i++) {
                MsQuicConnectionClose((HQUIC)Connections[i]);
            }
        }
        CXPLAT_FREE(Connections, QUIC_POOL_TMP_ALLOC);
        Connections = NULL;
    }
    if (ConnectionCounts != NULL) {
        CXPLAT_FREE(ConnectionCounts, QUIC_POOL_TMP_ALLOC);
    }
    if (RssProcessors != NULL) {
        CXPLAT_FREE(RssProcessors, QUIC_POOL_TMP_ALLOC);
    }
    if (RssConfig != NULL) {
        CxPlatDataPathRssConfigFree(RssConfig);
    }

    QuicTraceEvent(
        ApiExitStatus,
        "[ api] Exit %u",
        Status);

    return Status;
}
