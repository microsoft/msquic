/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.

Abstract:

    Connection pools allow client application to create a pool of connections
    spread across RSS cores.

    To create connection spread over RSS cores, the connection pool tries multiple
    port numbers, until the connection lands on a new RSS core. To know where a
    connection will land, the connection pool compute the RSS core based on the
    connection parameters. To do so, it needs to query the driver RSS configuration,
    and use the exact same RSS hash algorithm.

    There is also a chance that a port number found by the connection pool is not
    available, preventing the connection from starting successfully. To work around
    this, the connection pool starts connection imediately, and retries with a different
    port on failure. Special care is taken to avoid any app notification on a connection
    that will not be in the final pool. Note that a connection might still fail to start
    for other reasons and be kept in the pool (no guarantee that all connection in the
    pool are successful).

    Connection pools are currently only supported on Windows XDP datapath,
    since this is the only datapath that supports querying the RSS configuration parameters.

--*/

#include "precomp.h"

#ifdef QUIC_CLOG
#include "connection_pool.c.clog.h"
#endif

#define MAX_CONNECTION_POOL_RETRY_MULTIPLIER 8

typedef struct QUIC_CONN_POOL_RSS_PROC_INFO {

    //
    // The CPU index, converted into MsQuic's CPU index abstraction
    //
    uint32_t ProcIndex;

    //
    // The number of connections assigned to this CPU.
    //
    uint32_t ConnectionCount;
} QUIC_CONN_POOL_RSS_PROC_INFO;

static
_IRQL_requires_max_(PASSIVE_LEVEL)
QUIC_STATUS
QuicConnPoolAllocUniqueRssProcInfo(
    _In_ const CXPLAT_RSS_CONFIG* RssConfig,
    _Outptr_result_buffer_(*RssProcCount) _At_(*RssProcInfo, __drv_allocatesMem(Mem))
        QUIC_CONN_POOL_RSS_PROC_INFO** RssProcInfo,
    _Out_ uint32_t* RssProcCount
    )
{
    QUIC_STATUS Status = QUIC_STATUS_SUCCESS;
    CXPLAT_DBG_ASSERT(RssConfig->RssIndirectionTableCount > 0);
    //
    // Prepare array of unique RSS processors.
    // We allocate the maximum number of RSS processors here, because we don't
    // know how many are unique yet (and potentially they all are unique).
    //
    QUIC_CONN_POOL_RSS_PROC_INFO* RssProcessors =
        (QUIC_CONN_POOL_RSS_PROC_INFO*)CXPLAT_ALLOC_PAGED(
            RssConfig->RssIndirectionTableCount * sizeof(QUIC_CONN_POOL_RSS_PROC_INFO),
            QUIC_POOL_TMP_ALLOC);
    if (RssProcessors == NULL) {
        Status = QUIC_STATUS_OUT_OF_MEMORY;
        QuicTraceEvent(
            AllocFailure,
            "Allocation of '%s' failed. (%llu bytes)",
            "RSS Processor List",
            RssConfig->RssIndirectionTableCount * sizeof(QUIC_CONN_POOL_RSS_PROC_INFO));
        return Status;
    }

    uint32_t RssProcessorCount = 0;
    for (uint32_t i = 0; i < RssConfig->RssIndirectionTableCount; i++) {
        uint32_t j;
        for (j = 0; j < RssProcessorCount; j++) {
            if (RssProcessors[j].ProcIndex == RssConfig->RssIndirectionTable[i]) {
                break;
            }
        }
        //
        // This is safe because the RssProcessor array is the same count as the indirection table.
        //
        if (j == RssProcessorCount) {
            CXPLAT_DBG_ASSERT(RssProcessorCount < RssConfig->RssIndirectionTableCount);
            RssProcessors[RssProcessorCount].ConnectionCount = 0;
            RssProcessors[RssProcessorCount++].ProcIndex = RssConfig->RssIndirectionTable[i];
        }
    }

    CXPLAT_DBG_ASSERT(RssProcessorCount > 0);
    CXPLAT_DBG_ASSERT(RssProcessorCount <= RssConfig->RssIndirectionTableCount);

    *RssProcInfo = RssProcessors;
    *RssProcCount = RssProcessorCount;
    return Status;
}

static
_IRQL_requires_max_(DISPATCH_LEVEL)
QUIC_CONN_POOL_RSS_PROC_INFO*
QuicConnPoolGetRssProcForTuple(
    _In_ const CXPLAT_TOEPLITZ_HASH* ToeplitzHash,
    _In_ const QUIC_ADDR* RemoteAddress,
    _In_ const QUIC_ADDR* LocalAddress,
    _In_ QUIC_CONN_POOL_RSS_PROC_INFO* RssProcessors,
    _In_ uint32_t RssProcessorCount,
    _In_reads_(RssIndirectionTableCount)
        uint32_t* RssIndirectionTable,
    _In_ uint32_t RssIndirectionTableCount
    )
{
    //
    // Calculate the RSS Hash in the same way a NIC/miniport would when receiving packets from
    // RemoteAddress to find the RSS processor.
    //
    uint32_t RssHash = 0, Offset;
    CxPlatToeplitzHashComputeRss(
        ToeplitzHash,
        RemoteAddress,
        LocalAddress,
        &RssHash,
        &Offset);

    const uint32_t Mask = RssIndirectionTableCount - 1;

    CXPLAT_DBG_ASSERT((RssHash & Mask) < RssIndirectionTableCount);

    uint32_t Index = 0;
    for (; Index < RssProcessorCount; Index++) {
        if (RssProcessors[Index].ProcIndex == RssIndirectionTable[RssHash & Mask]) {
            break;
        }
    }

    CXPLAT_DBG_ASSERT(Index < RssProcessorCount);
    return &RssProcessors[Index];
}

static
_IRQL_requires_max_(PASSIVE_LEVEL)
const char*
QuicConnPoolAllocServerNameCopy(
    _In_ const char* ServerName,
    _In_ size_t ServerNameLength
    )
{
    char* ServerNameCopy = CXPLAT_ALLOC_NONPAGED(ServerNameLength + 1, QUIC_POOL_SERVERNAME);
    if (ServerNameCopy == NULL) {
        QuicTraceEvent(
            AllocFailure,
            "Allocation of '%s' failed. (%llu bytes)",
            "Server name",
            ServerNameLength + 1);
    } else {
        CxPlatCopyMemory(ServerNameCopy, ServerName, ServerNameLength);
        ServerNameCopy[ServerNameLength] = 0;
    }

    return ServerNameCopy;
}

static
_IRQL_requires_max_(PASSIVE_LEVEL)
QUIC_STATUS
QuicConnPoolGetStartingLocalAddress(
    _In_ QUIC_ADDR* RemoteAddress,
    _Out_ QUIC_ADDR* LocalAddress,
    _In_ CXPLAT_SOCKET_FLAGS SocketFlags
    )
{
    CXPLAT_SOCKET* Socket = NULL;
    CXPLAT_UDP_CONFIG UdpConfig;
    CxPlatZeroMemory(&UdpConfig, sizeof(UdpConfig));
    UdpConfig.Flags = SocketFlags;
    UdpConfig.RemoteAddress = RemoteAddress;
    QUIC_STATUS Status =
        CxPlatSocketCreateUdp(MsQuicLib.Datapath, &UdpConfig, &Socket);
    if (QUIC_SUCCEEDED(Status)) {
        CXPLAT_DBG_ASSERT(Socket != NULL);
        CxPlatSocketGetLocalAddress(Socket, LocalAddress);
        CxPlatSocketDelete(Socket);
    }

    return Status;
}

static
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
    if (QUIC_SUCCEEDED(Status)) {

        for (uint32_t i = 0; i < AddressesCount; i++) {
            if (QuicAddrCompareIp(LocalAddress, &Addresses[i].Address)) {
                *InterfaceIndex = Addresses[i].InterfaceIndex;
                break;
            }
        }

        if (*InterfaceIndex == 0) {
            Status = QUIC_STATUS_NOT_FOUND;
            QuicTraceEvent(
                LibraryErrorStatus,
                "[ lib] ERROR, %u, %s.",
                Status,
                "Connection Pool Local Address Interface");
        }

        CXPLAT_FREE(Addresses, QUIC_POOL_DATAPATH_ADDRESSES);
    }

    return Status;
}

//
// Queue a close operation on the connection worker thread,
// optionally waiting for its completion.
//
static
_IRQL_requires_max_(PASSIVE_LEVEL)
void
QuicConnPoolQueueConnectionClose(
    _In_ QUIC_CONNECTION* Connection,
    _In_ const BOOLEAN WaitForCompletion
    )
{
    CXPLAT_EVENT CompletionEvent = {0};

    Connection->CloseOper.Type = QUIC_OPER_TYPE_API_CALL;
    Connection->CloseOper.FreeAfterProcess = FALSE;
    Connection->CloseOper.API_CALL.Context = &Connection->CloseApiContext;
    Connection->CloseApiContext.Type = QUIC_API_TYPE_CONN_CLOSE;
    Connection->CloseApiContext.Status = NULL;

    if (WaitForCompletion) {
        CxPlatEventInitialize(&CompletionEvent, TRUE, FALSE);
        Connection->CloseApiContext.Completed = &CompletionEvent;
    }

    QuicConnQueueOper(Connection, &Connection->CloseOper);

    if (WaitForCompletion) {
        CxPlatEventWaitForever(CompletionEvent);
        CxPlatEventUninitialize(CompletionEvent);
    }
}


static
_IRQL_requires_max_(PASSIVE_LEVEL)
QUIC_STATUS
QuicConnPoolTryCreateConnection(
    _In_ QUIC_REGISTRATION* Registration,
    _In_ QUIC_CONFIGURATION* Configuration,
    _In_ QUIC_PARTITION* Partition,
    _In_ QUIC_CONNECTION_CALLBACK_HANDLER Handler,
    _In_opt_ void* Context,
    _In_ QUIC_ADDR* RemoteAddress,
    _In_ QUIC_ADDR* LocalAddress,
    _In_z_ const char* ServerName,
    _In_ uint16_t ServerPort,
    _In_ QUIC_ADDRESS_FAMILY Family,
    _In_ uint16_t CibirIdLength,
    _In_reads_bytes_opt_(CibirIdLength)
        const uint8_t* CibirId,
    _Outptr_ _At_(*Connection, __drv_allocatesMem(Mem))
        QUIC_CONNECTION** Connection
    )
{
    *Connection = NULL;

    QUIC_STATUS Status =
        QuicConnAlloc(
            Registration,
            Partition,
            NULL,
            NULL,
            Connection);
    if (QUIC_FAILED(Status)) {
        goto Error;
    }
    (*Connection)->ClientCallbackHandler = Handler;
    (*Connection)->ClientContext = Context;

    //
    // Set the calculated remote address and local address to get the desired
    // RSS CPU.
    //
    Status =
        QuicConnParamSet(
            *Connection,
            QUIC_PARAM_CONN_REMOTE_ADDRESS,
            sizeof(*RemoteAddress),
            RemoteAddress);
    CXPLAT_DBG_ASSERT(QUIC_SUCCEEDED(Status));
    if (QUIC_FAILED(Status)) {
        QuicTraceEvent(
            LibraryErrorStatus,
            "[ lib] ERROR, %u, %s.",
            Status,
            "Connection Pool set Remote Address");
        goto Error;
    }

    Status =
        QuicConnParamSet(
            *Connection,
            QUIC_PARAM_CONN_LOCAL_ADDRESS,
            sizeof(*LocalAddress),
            LocalAddress);
    CXPLAT_DBG_ASSERT(QUIC_SUCCEEDED(Status));
    if (QUIC_FAILED(Status)) {
        QuicTraceEvent(
            LibraryErrorStatus,
            "[ lib] ERROR, %u, %s.",
            Status,
            "Connection Pool set Local Address");
        goto Error;
    }

    if (CibirId) {
        uint8_t True = TRUE;
        Status =
            QuicConnParamSet(
                *Connection,
                QUIC_PARAM_CONN_SHARE_UDP_BINDING,
                sizeof(True),
                &True);
        CXPLAT_DBG_ASSERT(QUIC_SUCCEEDED(Status));
        if (QUIC_FAILED(Status)) {
            goto Error;
        }

        Status =
            QuicConnParamSet(
                *Connection,
                QUIC_PARAM_CONN_CIBIR_ID,
                CibirIdLength,
                CibirId);
        CXPLAT_DBG_ASSERT(QUIC_SUCCEEDED(Status));
        if (QUIC_FAILED(Status)) {
            QuicTraceEvent(
                LibraryErrorStatus,
                "[ lib] ERROR, %u, %s.",
                Status,
                "Connection Pool set CIBIR ID");
            goto Error;
        }
    }

    Status = QuicConnStart(
        *Connection,
        Configuration,
        Family,
        ServerName,
        ServerPort,
        QUIC_CONN_START_FLAG_FAIL_SILENTLY);

    ServerName = NULL; // The connection now owns the ServerName.

Error:
    //
    // If QuicConnStart has been called, the connection owns ServerName now.
    // In the failure cases, we need to free ServerName.
    //
    if (ServerName != NULL) {
        CXPLAT_FREE(ServerName, QUIC_POOL_SERVERNAME);
    }

    if (QUIC_FAILED(Status) && *Connection != NULL) {
        //
        // This connection has never left MsQuic back to the application.
        // Mark it as internally owned so no notification is sent to the app,
        // the closing logic will handle the final deref.
        //
        (*Connection)->State.ExternalOwner = FALSE;
        QuicConnPoolQueueConnectionClose(*Connection, FALSE);
        *Connection = NULL;
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
    QUIC_CONNECTION** Connections = (QUIC_CONNECTION**)ConnectionPool;
    CXPLAT_RSS_CONFIG* RssConfig = NULL;
    QUIC_CONN_POOL_RSS_PROC_INFO* RssProcessors = NULL;
    const char* ServerNameCopy = NULL;
    CXPLAT_TOEPLITZ_HASH ToeplitzHash;
    QUIC_STATUS Status = QUIC_STATUS_SUCCESS;
    uint32_t CreatedConnections = 0;

    QuicTraceEvent(
        ApiEnter,
        "[ api] Enter %u (%p).",
        QUIC_TRACE_API_CONNECTION_POOL_CREATE,
        NULL);

    if (Config == NULL || ConnectionPool == NULL) {
        Status = QUIC_STATUS_INVALID_PARAMETER;
        QuicTraceEvent(
            LibraryErrorStatus,
            "[ lib] ERROR, %u, %s.",
            Status,
            "Connection Pool Parameter");
        goto Error;
    }

    if (Config->Registration == NULL ||
        Config->Configuration == NULL|| Config->NumberOfConnections == 0 ||
        Config->Handler == NULL || Config->ServerName == NULL || Config->ServerPort == 0 ||
        (Config->Family != QUIC_ADDRESS_FAMILY_UNSPEC &&
            Config->Family != QUIC_ADDRESS_FAMILY_INET &&
            Config->Family != QUIC_ADDRESS_FAMILY_INET6)) {
        Status = QUIC_STATUS_INVALID_PARAMETER;
        QuicTraceEvent(
            LibraryErrorStatus,
            "[ lib] ERROR, %u, %s.",
            Status,
            "Connection Pool Config");
        goto Error;
    }

    if (((QUIC_CONFIGURATION*)Config->Configuration)->SecurityConfig == NULL) {
        Status = QUIC_STATUS_INVALID_PARAMETER;
        QuicTraceEvent(
            LibraryErrorStatus,
            "[ lib] ERROR, %u, %s.",
            Status,
            "Connection Pool SecurityConfig");
        goto Error;
    }

    if ((Config->CibirIds != NULL && Config->CibirIdLength == 0) ||
        (Config->CibirIds == NULL && Config->CibirIdLength != 0)) {
        Status = QUIC_STATUS_INVALID_PARAMETER;
        QuicTraceEvent(
            LibraryErrorStatus,
            "[ lib] ERROR, %u, %s.",
            Status,
            "Connection Pool CIBIR config");
        goto Error;
    }

    const size_t ServerNameLength = strnlen(Config->ServerName, QUIC_MAX_SNI_LENGTH + 1);
    if (ServerNameLength == QUIC_MAX_SNI_LENGTH + 1) {
        Status = QUIC_STATUS_INVALID_PARAMETER;
        QuicTraceEvent(
            LibraryErrorStatus,
            "[ lib] ERROR, %u, %s.",
            (uint32_t)ServerNameLength,
            "Connection Pool ServerName too long");
        goto Error;
    }

    CxPlatZeroMemory(ConnectionPool, sizeof(HQUIC) * Config->NumberOfConnections);

    //
    // Resolve the server name or use the remote address.
    //
    QUIC_ADDR ResolvedRemoteAddress = { 0 };
    QuicAddrSetFamily(&ResolvedRemoteAddress, Config->Family);
    if (Config->ServerAddress != NULL) {
         ResolvedRemoteAddress = *Config->ServerAddress;
    } else {
        Status =
            CxPlatDataPathResolveAddress(
                MsQuicLib.Datapath,
                Config->ServerName,
                &ResolvedRemoteAddress);
        if (QUIC_FAILED(Status)) {
            goto Error;
        }
    }

    QuicAddrSetPort(&ResolvedRemoteAddress, Config->ServerPort);

    //
    // Copying how Connection Settings flow downwards. It will first inherit the global settings,
    // if a global setting field is not set, but the configuration setting is set, override the global.
    //
    QUIC_CONFIGURATION* ConnectionConfig =
        (QUIC_CONFIGURATION*)Config->Configuration;
    CXPLAT_SOCKET_FLAGS SocketFlags = CXPLAT_SOCKET_FLAG_NONE;

    if (MsQuicLib.Settings.XdpEnabled) {
        SocketFlags |= CXPLAT_SOCKET_FLAG_XDP;
    }
    if (ConnectionConfig->Settings.IsSet.XdpEnabled) {
        if (ConnectionConfig->Settings.XdpEnabled) {
            SocketFlags |= CXPLAT_SOCKET_FLAG_XDP;
        } else {
            SocketFlags &= ~CXPLAT_SOCKET_FLAG_XDP;
        }
    }

    if (MsQuicLib.Settings.QTIPEnabled) {
        SocketFlags |= CXPLAT_SOCKET_FLAG_QTIP;
    }
    if (ConnectionConfig->Settings.IsSet.QTIPEnabled) {
        if (ConnectionConfig->Settings.QTIPEnabled) {
            SocketFlags |= CXPLAT_SOCKET_FLAG_QTIP;
        } else {
            SocketFlags &= ~CXPLAT_SOCKET_FLAG_QTIP;
        }
    }

    //
    // Get the local address and a port to start from.
    //
    QUIC_ADDR LocalAddress;
    Status = QuicConnPoolGetStartingLocalAddress(&ResolvedRemoteAddress, &LocalAddress, SocketFlags);
    if (QUIC_FAILED(Status)) {
        goto Error;
    }

    uint32_t InterfaceIndex;
    Status = QuicConnPoolGetInterfaceIndexForLocalAddress(&LocalAddress, &InterfaceIndex);
    if (QUIC_FAILED(Status)) {
        goto Error;
    }

    Status = CxPlatDataPathRssConfigGet(InterfaceIndex, &RssConfig);
    if (QUIC_FAILED(Status)) {
        goto Error;
    }

    if (RssConfig->RssIndirectionTableCount == 0) {
        //
        // No RSS cores configured.
        //
        Status = QUIC_STATUS_INTERNAL_ERROR;
        QuicTraceEvent(
            LibraryErrorStatus,
            "[ lib] ERROR, %u, %s.",
            RssConfig->RssIndirectionTableCount,
            "Connection Pool RssIndirectionTable too small");
        goto Error;
    }

    if (RssConfig->RssSecretKeyLength > CXPLAT_TOEPLITZ_KEY_SIZE_MAX) {
        Status = QUIC_STATUS_INTERNAL_ERROR;
        QuicTraceEvent(
            LibraryErrorStatus,
            "[ lib] ERROR, %u, %s.",
            RssConfig->RssSecretKeyLength,
            "Connection pool RSS secret key too long");
        goto Error;
    } else if (RssConfig->RssSecretKeyLength < CXPLAT_TOEPLITZ_KEY_SIZE_MIN) {
        Status = QUIC_STATUS_INTERNAL_ERROR;
        QuicTraceEvent(
            LibraryErrorStatus,
            "[ lib] ERROR, %u, %s.",
            RssConfig->RssSecretKeyLength,
            "Connection Pool RSS secret key too short");
        goto Error;
    }

    //
    // Get unique RSS processors.
    //
    uint32_t RssProcessorCount = 0;
    Status =
        QuicConnPoolAllocUniqueRssProcInfo(
            RssConfig,
            &RssProcessors,
            &RssProcessorCount);
    if (QUIC_FAILED(Status)) {
        goto Error;
    }

    //
    // Initialize the Toeplitz hash.
    //
    CxPlatCopyMemory(&ToeplitzHash.HashKey, RssConfig->RssSecretKey, RssConfig->RssSecretKeyLength);
    ToeplitzHash.InputSize = CXPLAT_TOEPLITZ_INPUT_SIZE_IP;
    CxPlatToeplitzHashInitialize(&ToeplitzHash);

    const uint32_t ConnectionsPerProc =
        Config->NumberOfConnections % RssProcessorCount != 0 ?
            (Config->NumberOfConnections / RssProcessorCount) + 1:
            (Config->NumberOfConnections / RssProcessorCount);

    //
    // Begin creating and starting connections.
    //
    for (uint32_t i = 0; i < Config->NumberOfConnections; i++) {
        const uint32_t MaxCreationRetries = RssProcessorCount * MAX_CONNECTION_POOL_RETRY_MULTIPLIER;
        uint32_t RetryCount = 0;

        for (; RetryCount < MaxCreationRetries; RetryCount++) {

            //
            // The connection takes ownership of the ServerName parameter, so we must
            // allocate a copy of it for each connection (attempt).
            //
            if (ServerNameCopy == NULL) {
                ServerNameCopy =
                    QuicConnPoolAllocServerNameCopy(
                        Config->ServerName,
                        ServerNameLength);
                if (ServerNameCopy == NULL) {
                    Status = QUIC_STATUS_OUT_OF_MEMORY;
                    goto CleanUpConnections;
                }
            }

            uint32_t NewPort = QuicAddrGetPort(&LocalAddress) + 1;
            if (NewPort > QUIC_ADDR_EPHEMERAL_PORT_MAX) {
                NewPort = QUIC_ADDR_EPHEMERAL_PORT_MIN;
            }
            QuicAddrSetPort(&LocalAddress, (uint16_t)NewPort);

            QUIC_CONN_POOL_RSS_PROC_INFO* CurrentProc =
                QuicConnPoolGetRssProcForTuple(
                    &ToeplitzHash,
                    &ResolvedRemoteAddress,
                    &LocalAddress,
                    RssProcessors,
                    RssProcessorCount,
                    RssConfig->RssIndirectionTable,
                    RssConfig->RssIndirectionTableCount);

            if (CurrentProc->ConnectionCount >= ConnectionsPerProc) {
                //
                // This processor already has enough connections on it, so try another port number.
                //
                continue;
            }

            QUIC_PARTITION* Partition =
                QuicLibraryGetPartitionFromProcessorIndex(CurrentProc->ProcIndex);

            Status =
                QuicConnPoolTryCreateConnection(
                    (QUIC_REGISTRATION*)Config->Registration,
                    (QUIC_CONFIGURATION*)Config->Configuration,
                    Partition,
                    Config->Handler,
                    Config->Context ? Config->Context[i] : NULL,
                    &ResolvedRemoteAddress,
                    &LocalAddress,
                    ServerNameCopy,
                    Config->ServerPort,
                    Config->Family,
                    Config->CibirIdLength,
                    Config->CibirIds ? Config->CibirIds[i] : NULL,
                    &Connections[i]);

            //
            // The connection either owns the ServerNameCopy, or it was freed.
            //
            ServerNameCopy = NULL;
            if (QUIC_FAILED(Status)) {
                continue;
            }

            //
            // The connection was created successfully, add it to the count for this processor.
            //
            CurrentProc->ConnectionCount++;
            CreatedConnections++;
            break;
        }

        if (RetryCount == MaxCreationRetries) {
            Status = QUIC_STATUS_ADDRESS_IN_USE;
            QuicTraceEvent(
                LibraryErrorStatus,
                "[ lib] ERROR, %u, %s.",
                RetryCount,
                "Connection Pool out of retries");
            goto CleanUpConnections;
        }
    }

CleanUpConnections:
    if (QUIC_FAILED(Status) &&
        (Config->Flags & QUIC_CONNECTION_POOL_FLAG_CLOSE_ON_FAILURE) != 0) {

        //
        // Close every connection that was created.
        // The application will receive the shutdown notification.
        // Wait for the task to complete so that when this function returns to the app,
        // all connections are already closed (since the shutdown notification is visible).
        //
        for (uint32_t i = 0; i < CreatedConnections; i++) {
            QuicConnPoolQueueConnectionClose(Connections[i], TRUE);
            QuicConnRelease(Connections[i], QUIC_CONN_REF_HANDLE_OWNER);
            Connections[i] = NULL;
        }
    }

Error:
    if (ServerNameCopy != NULL) {
        CXPLAT_FREE(ServerNameCopy, QUIC_POOL_SERVERNAME);
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
