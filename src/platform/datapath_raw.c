/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.

Abstract:

    QUIC Raw (i.e. DPDK or XDP) Datapath Implementation (User Mode)

--*/

#include "datapath_raw.h"
#ifdef QUIC_CLOG
#include "datapath_raw.c.clog.h"
#endif

#pragma warning(disable:4116) // unnamed type definition in parentheses
#pragma warning(disable:4100) // unreferenced formal parameter

_IRQL_requires_max_(PASSIVE_LEVEL)
QUIC_STATUS
CxPlatDataPathInitialize(
    _In_ uint32_t ClientRecvContextLength,
    _In_opt_ const CXPLAT_UDP_DATAPATH_CALLBACKS* UdpCallbacks,
    _In_opt_ const CXPLAT_TCP_DATAPATH_CALLBACKS* TcpCallbacks,
    _Out_ CXPLAT_DATAPATH** NewDataPath
    )
{
    QUIC_STATUS Status = QUIC_STATUS_SUCCESS;
    const size_t DatapathSize = CxPlatDpRawGetDapathSize();
    CXPLAT_FRE_ASSERT(DatapathSize > sizeof(CXPLAT_DATAPATH));

    UNREFERENCED_PARAMETER(TcpCallbacks);

    *NewDataPath = CXPLAT_ALLOC_PAGED(DatapathSize, QUIC_POOL_DATAPATH);
    if (*NewDataPath == NULL) {
        QuicTraceEvent(
            AllocFailure,
            "Allocation of '%s' failed. (%llu bytes)",
            "CXPLAT_DATAPATH",
            DatapathSize);
        Status = QUIC_STATUS_OUT_OF_MEMORY;
        goto Error;
    }
    CxPlatZeroMemory(*NewDataPath, DatapathSize);

    if (UdpCallbacks) {
        (*NewDataPath)->UdpHandlers = *UdpCallbacks;
    }

    if (!CxPlatSockPoolInitialize(&(*NewDataPath)->SocketPool)) {
        Status = QUIC_STATUS_OUT_OF_MEMORY;
        goto Error;
    }

    Status = CxPlatDpRawInitialize(*NewDataPath, ClientRecvContextLength);
    if (QUIC_FAILED(Status)) {
        CxPlatSockPoolUninitialize(&(*NewDataPath)->SocketPool);
        goto Error;
    }

Error:

    if (QUIC_FAILED(Status)) {
        if (*NewDataPath != NULL) {
            CXPLAT_FREE(*NewDataPath, QUIC_POOL_DATAPATH);
            *NewDataPath = NULL;
        }
    }

    return Status;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
void
CxPlatDataPathUninitialize(
    _In_ CXPLAT_DATAPATH* Datapath
    )
{
    if (Datapath == NULL) {
        return;
    }
    CxPlatDpRawUninitialize(Datapath);
    CxPlatSockPoolUninitialize(&Datapath->SocketPool);
    CXPLAT_FREE(Datapath, QUIC_POOL_DATAPATH);
}

_IRQL_requires_max_(PASSIVE_LEVEL)
void
CxPlatDpRawGenerateCpuTable(
    _Inout_ CXPLAT_DATAPATH* Datapath
    )
{
    Datapath->NumaNode = (uint8_t)CxPlatProcessorInfo[Datapath->Cpu].NumaNode;

    //
    // Build up the set of CPUs that are on the same NUMA node as this one.
    //
    Datapath->CpuTableSize = 0;
    for (uint16_t i = 0; i < CxPlatProcMaxCount(); i++) {
        if (i != Datapath->Cpu && // Skip raw layer's CPU
            CxPlatProcessorInfo[i].NumaNode == Datapath->NumaNode) {
            Datapath->CpuTable[Datapath->CpuTableSize++] = i;
        }
    }
}

_IRQL_requires_max_(DISPATCH_LEVEL)
uint32_t
CxPlatDataPathGetSupportedFeatures(
    _In_ CXPLAT_DATAPATH* Datapath
    )
{
    return 0;
}

_IRQL_requires_max_(DISPATCH_LEVEL)
BOOLEAN
CxPlatDataPathIsPaddingPreferred(
    _In_ CXPLAT_DATAPATH* Datapath
    )
{
    return FALSE;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
_Success_(QUIC_SUCCEEDED(return))
QUIC_STATUS
CxPlatDataPathGetLocalAddresses(
    _In_ CXPLAT_DATAPATH* Datapath,
    _Outptr_ _At_(*Addresses, __drv_allocatesMem(Mem))
        CXPLAT_ADAPTER_ADDRESS** Addresses,
    _Out_ uint32_t* AddressesCount
    )
{
    return QUIC_STATUS_NOT_SUPPORTED;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
_Success_(QUIC_SUCCEEDED(return))
QUIC_STATUS
CxPlatDataPathGetGatewayAddresses(
    _In_ CXPLAT_DATAPATH* Datapath,
    _Outptr_ _At_(*GatewayAddresses, __drv_allocatesMem(Mem))
        QUIC_ADDR** GatewayAddresses,
    _Out_ uint32_t* GatewayAddressesCount
    )
{
    return QUIC_STATUS_NOT_SUPPORTED;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
QUIC_STATUS
CxPlatDataPathResolveAddress(
    _In_ CXPLAT_DATAPATH* Datapath,
    _In_z_ const char* HostName,
    _Inout_ QUIC_ADDR* Address
    )
{
    if (QuicAddrFromString(HostName, 0, Address)) {
        return QUIC_STATUS_SUCCESS;
    }
    return QUIC_STATUS_NOT_SUPPORTED; // TODO - Support name resolution
}

_IRQL_requires_max_(PASSIVE_LEVEL)
QUIC_STATUS
CxPlatSocketCreateUdp(
    _In_ CXPLAT_DATAPATH* Datapath,
    _In_ const CXPLAT_UDP_CONFIG* Config,
    _Out_ CXPLAT_SOCKET** NewSocket
    )
{
    QUIC_STATUS Status = QUIC_STATUS_SUCCESS;

    *NewSocket = CXPLAT_ALLOC_PAGED(sizeof(CXPLAT_SOCKET), QUIC_POOL_SOCKET);
    if (*NewSocket == NULL) {
        QuicTraceEvent(
            AllocFailure,
            "Allocation of '%s' failed. (%llu bytes)",
            "CXPLAT_SOCKET",
            sizeof(CXPLAT_SOCKET));
        Status = QUIC_STATUS_OUT_OF_MEMORY;
        goto Error;
    }

    QuicTraceEvent(
        DatapathCreated,
        "[data][%p] Created, local=%!ADDR!, remote=%!ADDR!",
        *NewSocket,
        CASTED_CLOG_BYTEARRAY(Config->LocalAddress ? sizeof(*Config->LocalAddress) : 0, Config->LocalAddress),
        CASTED_CLOG_BYTEARRAY(Config->RemoteAddress ? sizeof(*Config->RemoteAddress) : 0, Config->RemoteAddress));

    CxPlatZeroMemory(*NewSocket, sizeof(CXPLAT_SOCKET));
    CxPlatRundownInitialize(&(*NewSocket)->Rundown);
    (*NewSocket)->Datapath = Datapath;
    (*NewSocket)->CallbackContext = Config->CallbackContext;

    if (Config->RemoteAddress) {
        CXPLAT_FRE_ASSERT(!QuicAddrIsWildCard(Config->RemoteAddress));  // No wildcard remote addresses allowed.
        (*NewSocket)->Connected = TRUE;
        (*NewSocket)->RemoteAddress = *Config->RemoteAddress;
    }

    if (Config->LocalAddress) {
        (*NewSocket)->LocalAddress = *Config->LocalAddress;
        if (QuicAddrIsWildCard(Config->LocalAddress)) {
            if (!(*NewSocket)->Connected) {
                (*NewSocket)->Wildcard = TRUE;
            }
        } else {
            CXPLAT_FRE_ASSERT((*NewSocket)->Connected); // Assumes only connected sockets fully specify local address
        }
    } else {
        QuicAddrSetFamily(&(*NewSocket)->LocalAddress, QUIC_ADDRESS_FAMILY_INET6);
        if (!(*NewSocket)->Connected) {
            (*NewSocket)->Wildcard = TRUE;
        }
    }

    CXPLAT_FRE_ASSERT((*NewSocket)->Wildcard ^ (*NewSocket)->Connected); // Assumes either a pure wildcard listener or a
                                                                         // connected socket; not both.

    if (!CxPlatTryAddSocket(&Datapath->SocketPool, *NewSocket)) {
        Status = QUIC_STATUS_ADDRESS_IN_USE;
        goto Error;
    }

Error:

    if (QUIC_FAILED(Status)) {
        if (*NewSocket != NULL) {
            CxPlatRundownUninitialize(&(*NewSocket)->Rundown);
            CXPLAT_FREE(*NewSocket, QUIC_POOL_SOCKET);
            *NewSocket = NULL;
        }
    }

    return Status;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
QUIC_STATUS
CxPlatSocketCreateTcp(
    _In_ CXPLAT_DATAPATH* Datapath,
    _In_opt_ const QUIC_ADDR* LocalAddress,
    _In_ const QUIC_ADDR* RemoteAddress,
    _In_opt_ void* CallbackContext,
    _Out_ CXPLAT_SOCKET** Socket
    )
{
    return QUIC_STATUS_NOT_SUPPORTED;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
QUIC_STATUS
CxPlatSocketCreateTcpListener(
    _In_ CXPLAT_DATAPATH* Datapath,
    _In_opt_ const QUIC_ADDR* LocalAddress,
    _In_opt_ void* RecvCallbackContext,
    _Out_ CXPLAT_SOCKET** NewSocket
    )
{
    return QUIC_STATUS_NOT_SUPPORTED;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
void
CxPlatSocketDelete(
    _In_ CXPLAT_SOCKET* Socket
    )
{
    CxPlatRemoveSocket(&Socket->Datapath->SocketPool, Socket);
    CxPlatRundownReleaseAndWait(&Socket->Rundown);
    CXPLAT_FREE(Socket, QUIC_POOL_SOCKET);
}

_IRQL_requires_max_(DISPATCH_LEVEL)
UINT16
CxPlatSocketGetLocalMtu(
    _In_ CXPLAT_SOCKET* Socket
    )
{
    return 1500;
}

_IRQL_requires_max_(DISPATCH_LEVEL)
void
CxPlatSocketGetLocalAddress(
    _In_ CXPLAT_SOCKET* Socket,
    _Out_ QUIC_ADDR* Address
    )
{
    *Address = Socket->LocalAddress;
}

_IRQL_requires_max_(DISPATCH_LEVEL)
void
CxPlatSocketGetRemoteAddress(
    _In_ CXPLAT_SOCKET* Socket,
    _Out_ QUIC_ADDR* Address
    )
{
    *Address = Socket->RemoteAddress;
}

_IRQL_requires_max_(DISPATCH_LEVEL)
void
CxPlatDpRawRxEthernet(
    _In_ CXPLAT_DATAPATH* Datapath,
    _In_reads_(PacketCount)
        CXPLAT_RECV_DATA** Packets,
    _In_ uint16_t PacketCount
    )
{
    for (uint16_t i = 0; i < PacketCount; i++) {
        CXPLAT_SOCKET* Socket = NULL;
        CXPLAT_RECV_DATA* PacketChain = Packets[i];
        CXPLAT_DBG_ASSERT(PacketChain->Next == NULL);

        if (PacketChain->Reserved == L4_TYPE_UDP) {
            Socket =
                CxPlatGetSocket(
                    &Datapath->SocketPool,
                    &PacketChain->Route->LocalAddress,
                    &PacketChain->Route->RemoteAddress);
        }
        if (Socket) {
            //
            // Found a match. Chain and deliver contiguous packets with the same 4-tuple.
            //
            while (i < PacketCount) {
                QuicTraceEvent(
                    DatapathRecv,
                    "[data][%p] Recv %u bytes (segment=%hu) Src=%!ADDR! Dst=%!ADDR!",
                    Socket,
                    Packets[i]->BufferLength,
                    Packets[i]->BufferLength,
                    CASTED_CLOG_BYTEARRAY(sizeof(Packets[i]->Route->LocalAddress), &Packets[i]->Route->LocalAddress),
                    CASTED_CLOG_BYTEARRAY(sizeof(Packets[i]->Route->RemoteAddress), &Packets[i]->Route->RemoteAddress));
                if (i == PacketCount - 1 ||
                    Packets[i+1]->Reserved != L4_TYPE_UDP ||
                    Packets[i+1]->Route->LocalAddress.Ipv4.sin_port != Socket->LocalAddress.Ipv4.sin_port ||
                    !CxPlatSocketCompare(Socket, &Packets[i+1]->Route->LocalAddress, &Packets[i+1]->Route->RemoteAddress)) {
                    break;
                }
                Packets[i]->Next = Packets[i+1];
                CXPLAT_DBG_ASSERT(Packets[i+1]->Next == NULL);
                i++;
            }
            Datapath->UdpHandlers.Receive(Socket, Socket->CallbackContext, (CXPLAT_RECV_DATA*)PacketChain);
            CxPlatRundownRelease(&Socket->Rundown);
        } else {
            CxPlatDpRawRxFree(PacketChain);
        }
    }
}

_IRQL_requires_max_(DISPATCH_LEVEL)
void
CxPlatRecvDataReturn(
    _In_opt_ CXPLAT_RECV_DATA* RecvDataChain
    )
{
    CxPlatDpRawRxFree((const CXPLAT_RECV_DATA*)RecvDataChain);
}

_IRQL_requires_max_(DISPATCH_LEVEL)
_Success_(return != NULL)
CXPLAT_SEND_DATA*
CxPlatSendDataAlloc(
    _In_ CXPLAT_SOCKET* Socket,
    _In_ CXPLAT_ECN_TYPE ECN,
    _In_ uint16_t MaxPacketSize,
    _In_ QUIC_ADDRESS_FAMILY Family
    )
{
    return CxPlatDpRawTxAlloc(
        Socket->Datapath, ECN, MaxPacketSize, Family);
}

_IRQL_requires_max_(DISPATCH_LEVEL)
_Success_(return != NULL)
QUIC_BUFFER*
CxPlatSendDataAllocBuffer(
    _In_ CXPLAT_SEND_DATA* SendData,
    _In_ uint16_t MaxBufferLength
    )
{
    SendData->Buffer.Length = MaxBufferLength;
    return &SendData->Buffer;
}

_IRQL_requires_max_(DISPATCH_LEVEL)
void
CxPlatSendDataFree(
    _In_ CXPLAT_SEND_DATA* SendData
    )
{
    CxPlatDpRawTxFree(SendData);
}

_IRQL_requires_max_(DISPATCH_LEVEL)
void
CxPlatSendDataFreeBuffer(
    _In_ CXPLAT_SEND_DATA* SendData,
    _In_ QUIC_BUFFER* Buffer
    )
{
    // No-op
}

_IRQL_requires_max_(DISPATCH_LEVEL)
BOOLEAN
CxPlatSendDataIsFull(
    _In_ CXPLAT_SEND_DATA* SendData
    )
{
    return TRUE;
}

_IRQL_requires_max_(DISPATCH_LEVEL)
inline
QUIC_STATUS
CxPlatResolveRoute(
    _In_ CXPLAT_SOCKET* Socket,
    _Inout_ CXPLAT_ROUTE* Route
    )
{
    NETIO_STATUS Status = 0;
    MIB_IPFORWARD_ROW2 IpforwardRow = {0};

    CXPLAT_FRE_ASSERT(!QuicAddrIsWildCard(&Route->RemoteAddress));

    //
    // Find the best next hop IP address.
    //
    uint16_t SavedLocalPort = Route->LocalAddress.Ipv4.sin_port;
    Status =
        GetBestRoute2(
            NULL, // InterfaceLuid
            IFI_UNSPECIFIED, // InterfaceIndex
            &Route->LocalAddress, // SourceAddress
            &Route->RemoteAddress, // DestinationAddress
            0, // AddressSortOptions
            &IpforwardRow,
            &Route->LocalAddress); // BestSourceAddress
    Route->LocalAddress.Ipv4.sin_port = SavedLocalPort;
    if (Status != ERROR_SUCCESS) {
        QuicTraceEvent(
            DatapathErrorStatus,
            "[data][%p] ERROR, %u, %s.",
            Socket,
            Status,
            "GetBestRoute2");
        goto Done;
    }

    //
    // Look up the source interface link-layer address.
    //
    MIB_IF_ROW2 IfRow = {0};
    IfRow.InterfaceIndex = IpforwardRow.InterfaceIndex;
    Status = GetIfEntry2(&IfRow);
    if (Status != ERROR_SUCCESS) {
        QuicTraceEvent(
            DatapathErrorStatus,
            "[data][%p] ERROR, %u, %s.",
            Socket,
            Status,
            "GetIfEntry2");
        goto Done;
    }
    CXPLAT_FRE_ASSERT(IfRow.PhysicalAddressLength == sizeof(Route->LocalLinkLayerAddress));
    CxPlatCopyMemory(&Route->LocalLinkLayerAddress, IfRow.PhysicalAddress, sizeof(Route->LocalLinkLayerAddress));

    //
    // Map the next hop IP address to a link-layer address.
    //
    MIB_IPNET_ROW2 IpnetRow = {0};
    IpnetRow.InterfaceIndex = IpforwardRow.InterfaceIndex;
    if (QuicAddrIsWildCard(&IpforwardRow.NextHop)) { // On-link?
        IpnetRow.Address = Route->RemoteAddress;
    } else {
        IpnetRow.Address = IpforwardRow.NextHop;
    }
    Status = GetIpNetEntry2(&IpnetRow);
    if (Status != ERROR_SUCCESS) {
        Status =
            ResolveIpNetEntry2(
                &IpnetRow,
                &Route->LocalAddress);
        if (Status != 0) {
            QuicTraceEvent(
                DatapathErrorStatus,
                "[data][%p] ERROR, %u, %s.",
                Socket,
                Status,
                "ResolveIpNetEntry2");
            goto Done;
        }
    }
    CXPLAT_FRE_ASSERT(IpnetRow.PhysicalAddressLength == sizeof(Route->NextHopLinkLayerAddress));
    CxPlatCopyMemory(&Route->NextHopLinkLayerAddress, IpnetRow.PhysicalAddress, sizeof(Route->NextHopLinkLayerAddress));

    Route->Resolved = TRUE;

Done:

    // TODO: convert NETIO_STATUS to QUIC_STATUS
    return Status;
}

_IRQL_requires_max_(DISPATCH_LEVEL)
QUIC_STATUS
CxPlatSocketSend(
    _In_ CXPLAT_SOCKET* Socket,
    _Inout_ CXPLAT_ROUTE* Route,
    _In_ CXPLAT_SEND_DATA* SendData,
    _In_ uint16_t IdealProcessor
    )
{
    QUIC_STATUS Status = QUIC_STATUS_SUCCESS;

    if (!Route->Resolved) {
        Status = CxPlatResolveRoute(Socket, Route);
        if (QUIC_FAILED(Status)) {
            goto Done;
        }
    }

    QuicTraceEvent(
        DatapathSend,
        "[data][%p] Send %u bytes in %hhu buffers (segment=%hu) Dst=%!ADDR!, Src=%!ADDR!",
        Socket,
        SendData->Buffer.Length,
        1,
        (uint16_t)SendData->Buffer.Length,
        CASTED_CLOG_BYTEARRAY(sizeof(Route->RemoteAddress), &Route->RemoteAddress),
        CASTED_CLOG_BYTEARRAY(sizeof(Route->LocalAddress), &Route->LocalAddress));

    CxPlatFramingWriteHeaders(
        Socket, Route, &SendData->Buffer,
        Socket->Datapath->OffloadStatus.Transmit.NetworkLayerXsum,
        Socket->Datapath->OffloadStatus.Transmit.TransportLayerXsum);
    CxPlatDpRawTxEnqueue(SendData);

Done:

    return Status;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
QUIC_STATUS
CxPlatSocketSetParam(
    _In_ CXPLAT_SOCKET* Socket,
    _In_ uint32_t Param,
    _In_ uint32_t BufferLength,
    _In_reads_bytes_(BufferLength) const UINT8 * Buffer
    )
{
    UNREFERENCED_PARAMETER(Socket);
    UNREFERENCED_PARAMETER(Param);
    UNREFERENCED_PARAMETER(BufferLength);
    UNREFERENCED_PARAMETER(Buffer);
    return QUIC_STATUS_NOT_SUPPORTED;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
QUIC_STATUS
CxPlatSocketGetParam(
    _In_ CXPLAT_SOCKET* Socket,
    _In_ uint32_t Param,
    _Inout_ PUINT32 BufferLength,
    _Out_writes_bytes_opt_(*BufferLength) UINT8 * Buffer
    )
{
    UNREFERENCED_PARAMETER(Socket);
    UNREFERENCED_PARAMETER(Param);
    UNREFERENCED_PARAMETER(BufferLength);
    UNREFERENCED_PARAMETER(Buffer);
    return QUIC_STATUS_NOT_SUPPORTED;
}

#ifdef QUIC_USE_EXECUTION_CONTEXTS

// TODO - Add synchronization around this stuff.
uint32_t ExecutionContextCount = 0;
CXPLAT_EXECUTION_CONTEXT* ExecutionContexts[8];

void CxPlatAddExecutionContext(CXPLAT_EXECUTION_CONTEXT* Context)
{
    CXPLAT_FRE_ASSERT(ExecutionContextCount < ARRAYSIZE(ExecutionContexts));
    ExecutionContexts[ExecutionContextCount] = Context;
    ExecutionContextCount++;
}

BOOLEAN CxPlatRunExecutionContexts(_In_ CXPLAT_THREAD_ID ThreadID)
{
    if (ExecutionContextCount == 0) {
        return FALSE;
    }

    uint64_t TimeNow = CxPlatTimeUs64();
    for (uint32_t i = 0; i < ExecutionContextCount; i++) {
        CXPLAT_EXECUTION_CONTEXT* Context = ExecutionContexts[i];
        if (Context->Ready || Context->NextTimeUs <= TimeNow) {
            if (!Context->Callback(Context->Context, &TimeNow, ThreadID)) {
                // Remove the context from the array.
                if (i + 1 < ExecutionContextCount) {
                    ExecutionContexts[i] = ExecutionContexts[--ExecutionContextCount];
                } else {
                    ExecutionContextCount--;
                }
            }
        }
    }

    return TRUE;
}

#endif
