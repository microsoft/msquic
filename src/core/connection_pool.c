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
QUIC_API
MsQuicConnectionPoolCreate(
    _In_ QUIC_CONNECTION_POOL_CONFIG* Config,
    _Out_writes_(Config->NumberOfConnections)
        HQUIC* ConnectionPool
    )
{
    QUIC_CONNECTION** Connections = NULL;
    CXPLAT_SOCKET* Socket = NULL;
    CXPLAT_RSS_CONFIG* RssConfig = NULL;
    CXPLAT_PROCESSOR_INFO* RssProcessors = NULL;
    uint32_t* ConnectionCounts = NULL;
    CXPLAT_TOEPLITZ_HASH ToeplitzHash;
    QUIC_STATUS Status = QUIC_STATUS_SUCCESS;
    uint32_t CreatedConnections = 0;

    if (Config->NumberOfConnections == 0 || Config->ServerPort == 0 || ConnectionPool == NULL) {
        Status = QUIC_STATUS_INVALID_PARAMETER;
        QuicTraceLogError(
            ConnPoolInvalidParam,
            "[conp] Invalid parameter, 0x%x",
            Status);
        goto Error;
    }

    CxPlatZeroMemory(ConnectionPool, sizeof(HQUIC) * Config->NumberOfConnections);

    //
    // Resolve the server name or use the remote address.
    //
    QUIC_ADDR ResolvedRemoteAddress = {};
    if (Config->ServerAddress != NULL) {
         ResolvedRemoteAddress = *Config->ServerAddress;
    } else if (Config->ServerName != NULL) {
        Status =
            CxPlatDataPathResolveAddress(
                MsQuicLib.Datapath,
                Config->ServerName,
                &ResolvedRemoteAddress);
    } else {
        Status = QUIC_STATUS_INVALID_PARAMETER;
        QuicTraceLogError(
            ConnPoolInvalidParamNeedRemoteAddress,
            "[conp] Neither ServerName nor ServerAddress were set, 0x%x",
            Status);
        goto Error;
    }

    QuicAddrSetPort(&ResolvedRemoteAddress, Config->ServerPort);

    CXPLAT_UDP_CONFIG UdpConfig = {.RemoteAddress = &ResolvedRemoteAddress, };
    Status = CxPlatSocketCreateUdp(MsQuicLib.Datapath, &UdpConfig, &Socket);
    if (QUIC_FAILED(Status)) {
        QuicTraceLogError(
            ConnPoolCreateSocket,
            "[conp] Failed to create socket, 0x%x",
            Status);
        goto Error;
    }

    //
    // Get the local address and a port to start from.
    //
    QUIC_ADDR LocalAddress;
    CxPlatSocketGetLocalAddress(Socket, &LocalAddress);
    CxPlatSocketDelete(Socket);
    Socket = NULL;

    //
    // Get the interface index from the local address to get the RSS config
    //
    CXPLAT_ADAPTER_ADDRESS* Addresses;
    uint32_t AddressesCount;
    Status = CxPlatDataPathGetLocalAddresses(MsQuicLib.Datapath, &Addresses, &AddressesCount);
    if (QUIC_FAILED(Status)) {
        QuicTraceLogError(
            ConnPoolGetLocalAddresses,
            "[conp] Failed to get local address info, 0x%x",
            Status);
        goto Error;
    }
    uint32_t InterfaceIndex = 0;
    for (uint32_t i = 0; i < AddressesCount; i++) {
        if (QuicAddrCompareIp(&LocalAddress, &Addresses[i].Address)) {
            InterfaceIndex = Addresses[i].InterfaceIndex;
            break;
        }
    }
    CXPLAT_FREE(Addresses, QUIC_POOL_DATAPATH_ADDRESSES);
    if (InterfaceIndex == 0) {
        Status = QUIC_STATUS_NOT_FOUND;
        QuicTraceLogError(
            ConnPoolLocalAddressNotFound,
            "[conp] Failed to find local address, 0x%x",
            Status);
        goto Error;
    }

    //
    // Actually get the RSS config
    //
    Status = CxPlatDataPathRssConfigGet(InterfaceIndex, &RssConfig);
    if (QUIC_FAILED(Status)) {
        QuicTraceLogError(
            ConnPoolGetRssConfig,
            "[conp] Failed to get RSS config, 0x%x",
            Status);
        goto Error;
    }

    if ((RssConfig->HashTypes & (CXPLAT_RSS_HASH_TYPE_UDP_IPV4 | CXPLAT_RSS_HASH_TYPE_UDP_IPV6)) == 0) {
        //
        // This RSS implementation doesn't support hashing UDP ports, which
        // means the connection pool can't spread connections across CPUs.
        //
        Status = QUIC_STATUS_NOT_SUPPORTED;
        QuicTraceLogError(
            ConnPoolRssNotSupported,
            "[conp] RSS not supported, 0x%x",
            Status);
        goto Error;
    }

    //
    // Prepare array of unique RSS processors.
    //
    RssProcessors =
        (CXPLAT_PROCESSOR_INFO*)CXPLAT_ALLOC_PAGED(
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
    for (uint32_t i = 0; i < RssConfig->RssIndirectionTableLength / sizeof(CXPLAT_PROCESSOR_INFO); i++) {
        uint32_t j;
        for (j = 0; j < RssProcessorCount; j++) {
            if (RssProcessors[j].Group == RssConfig->RssIndirectionTable[i].Group &&
                RssProcessors[j].Index == RssConfig->RssIndirectionTable[i].Index) {
                break;
            }
        }
        //
        // This is safe because the RssProcessor array is the same size as the indirection table.
        //
        if (j == RssProcessorCount) {
            CXPLAT_DBG_ASSERT(RssProcessorCount < RssConfig->RssIndirectionTableLength / sizeof(CXPLAT_PROCESSOR_INFO));
            RssProcessors[RssProcessorCount++] = RssConfig->RssIndirectionTable[i];
        }
    }

    CXPLAT_DBG_ASSERT(RssProcessorCount <= RssConfig->RssIndirectionTableLength / sizeof(CXPLAT_PROCESSOR_INFO));

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
    // Start testing ports and creating connections.
    //

    const uint32_t ConnectionsPerProc = (Config->NumberOfConnections / RssProcessorCount) + 1;

    for (uint32_t i = 0; i < Config->NumberOfConnections; i++) {
        const uint32_t MaxCreationRetries = RssProcessorCount * MAX_CONNECTION_POOL_RETRY_MULTIPLIER;
        uint32_t RetryCount = 0;
        uint32_t RssProcIndex;
        for (; RetryCount < MaxCreationRetries; RetryCount++) {

            uint32_t NewPort = QuicAddrGetPort(&LocalAddress);
            NewPort += 1;
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
            uint32_t Mask = (RssConfig->RssIndirectionTableLength / sizeof(CXPLAT_PROCESSOR_INFO)) - 1;
            RssProcIndex = RssProcessorCount;
            CXPLAT_DBG_ASSERT((RssHash & Mask) < RssConfig->RssIndirectionTableLength / sizeof(CXPLAT_PROCESSOR_INFO));
            CXPLAT_PROCESSOR_INFO* RssProc = &RssConfig->RssIndirectionTable[RssHash & Mask];
            for (uint32_t j = 0; j < RssProcessorCount; j++) {
                if (RssProcessors[j].Group == RssProc->Group && RssProcessors[j].Index == RssProc->Index) {
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
            QuicLibraryGetPartitionFromProcessorIndex(
                (uint16_t)CxPlatProcNumberToIndex(&RssProcessors[RssProcIndex]));

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

            Status = QuicConnParamSet(Connections[i], QUIC_PARAM_CONN_REMOTE_ADDRESS, sizeof(ResolvedRemoteAddress), &ResolvedRemoteAddress);
            CXPLAT_DBG_ASSERT(QUIC_SUCCEEDED(Status));
            if (QUIC_FAILED(Status)) {
                QuicTraceLogError(
                    ConnPoolSetRemoteAddress,
                    "[conp] Failed to set remote address on connection[%u], 0x%x",
                    i,
                    Status);
                goto Error;
            }
            Status = QuicConnParamSet(Connections[i], QUIC_PARAM_CONN_LOCAL_ADDRESS, sizeof(LocalAddress), &LocalAddress);
            CXPLAT_DBG_ASSERT(QUIC_SUCCEEDED(Status));
            if (QUIC_FAILED(Status)) {
                QuicTraceLogError(
                    ConnPoolSetLocalAddress,
                    "[conp] Failed to set local address on connection[%u], 0x%x",
                    i,
                    Status);
                goto Error;
            }

            Status = QuicConnStart( // REVIEW CLOSELY -- can this be called on a non-worker thread?
                Connections[i],
                (QUIC_CONFIGURATION*)Config->Configuration,
                Config->Family,
                Config->ServerName,
                Config->ServerPort,
                QUIC_CONN_START_SILENT_FAILURE);
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
                "[conp] Ran out of retries. Iteration %u, Port %u, 0x%x",
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
    return Status;
}
