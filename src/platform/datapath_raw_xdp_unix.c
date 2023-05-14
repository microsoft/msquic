/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.

Abstract:

    QUIC XDP Datapath Implementation (User Mode)

--*/

#define _CRT_SECURE_NO_WARNINGS 1 // TODO - Remove

#include "datapath_raw_unix.h"
#include "datapath_raw_xdp_unix.h"
#ifdef QUIC_CLOG
#include "datapath_raw_xdp.c.clog.h"
#endif

// -> defined in quic_datapath.h
CXPLAT_RECV_DATA*
CxPlatDataPathRecvPacketToRecvData(
    _In_ const CXPLAT_RECV_PACKET* const Context
    )
{
    return (CXPLAT_RECV_DATA*)(((uint8_t*)Context) - sizeof(XDP_RX_PACKET));
}

// -> defined in quic_datapath.h
CXPLAT_RECV_PACKET*
CxPlatDataPathRecvDataToRecvPacket(
    _In_ const CXPLAT_RECV_DATA* const Datagram
    )
{
    return (CXPLAT_RECV_PACKET*)(((uint8_t*)Datagram) + sizeof(XDP_RX_PACKET));
}

// -> xdp_common.h or just internal
QUIC_STATUS
CxPlatGetInterfaceRssQueueCount(
    _In_ uint32_t InterfaceIndex,
    _Out_ uint16_t* Count
    )
{
    UNREFERENCED_PARAMETER(InterfaceIndex);
    UNREFERENCED_PARAMETER(Count);
    return QUIC_STATUS_NOT_SUPPORTED;
}

// -> xdp_common.h or just internal
_IRQL_requires_max_(PASSIVE_LEVEL)
void
CxPlatXdpReadConfig(
    _Inout_ XDP_DATAPATH* Xdp
    )
{
    //
    // Default config.
    //
    Xdp->RxBufferCount = 8192;
    Xdp->RxRingSize = 256;
    Xdp->TxBufferCount = 8192;
    Xdp->TxRingSize = 256;
    Xdp->TxAlwaysPoke = FALSE;

    // TODO
}

// -> xdp_common.h or just internal
_IRQL_requires_max_(PASSIVE_LEVEL)
void
CxPlatDpRawInterfaceUninitialize(
    _Inout_ XDP_INTERFACE* Interface
    )
{
    UNREFERENCED_PARAMETER(Interface);

}

// -> xdp_common.h or just internal
_IRQL_requires_max_(PASSIVE_LEVEL)
QUIC_STATUS
CxPlatDpRawInterfaceInitialize(
    _In_ XDP_DATAPATH* Xdp,
    _Inout_ XDP_INTERFACE* Interface,
    _In_ uint32_t ClientRecvContextLength
    )
{
    UNREFERENCED_PARAMETER(Xdp);
    UNREFERENCED_PARAMETER(Interface);
    UNREFERENCED_PARAMETER(ClientRecvContextLength);

    return QUIC_STATUS_NOT_SUPPORTED;
}

// -> xdp_common.h or just internal
_IRQL_requires_max_(PASSIVE_LEVEL)
//_Requires_lock_held_(Interface->RuleLock)
void
CxPlatDpRawInterfaceUpdateRules(
    _In_ XDP_INTERFACE* Interface
    )
{
    UNREFERENCED_PARAMETER(Interface);
}

// -> xdp_common.h or just internal
// _IRQL_requires_max_(PASSIVE_LEVEL)
// void
// CxPlatDpRawInterfaceAddRules(
//     _In_ XDP_INTERFACE* Interface,
//     _In_reads_(Count) const XDP_RULE* Rules,
//     _In_ uint8_t Count
//     )
// {
// #pragma warning(push)
// #pragma warning(disable:6386) // Buffer overrun while writing to 'NewRules' - FALSE POSITIVE

//     CxPlatLockAcquire(&Interface->RuleLock);
//     // TODO - Don't always allocate a new array?

//     if ((uint32_t)Interface->RuleCount + (uint32_t)Count > UINT8_MAX) {
//         QuicTraceEvent(
//             LibraryError,
//             "[ lib] ERROR, %s.",
//             "No more room for rules");
//         CxPlatLockRelease(&Interface->RuleLock);
//         return;
//     }

//     const size_t OldSize = sizeof(XDP_RULE) * (size_t)Interface->RuleCount;
//     const size_t NewSize = sizeof(XDP_RULE) * ((size_t)Interface->RuleCount + Count);

//     XDP_RULE* NewRules = CxPlatAlloc(NewSize, RULE_TAG);
//     if (NewRules == NULL) {
//         QuicTraceEvent(
//             AllocFailure,
//             "Allocation of '%s' failed. (%llu bytes)",
//             "XDP_RULE",
//             NewSize);
//         CxPlatLockRelease(&Interface->RuleLock);
//         return;
//     }

//     if (Interface->RuleCount > 0) {
//         memcpy(NewRules, Interface->Rules, OldSize);
//     }
//     for (uint8_t i = 0; i < Count; i++) {
//         NewRules[Interface->RuleCount++] = Rules[i];
//     }

//     if (Interface->Rules != NULL) {
//         CxPlatFree(Interface->Rules, RULE_TAG);
//     }
//     Interface->Rules = NewRules;

//     CxPlatDpRawInterfaceUpdateRules(Interface);

//     CxPlatLockRelease(&Interface->RuleLock);

// #pragma warning(pop)
// }

// -> xdp_commoh.h ? or just internal
// _IRQL_requires_max_(PASSIVE_LEVEL)
// void
// CxPlatDpRawInterfaceRemoveRules(
//     _In_ XDP_INTERFACE* Interface,
//     _In_reads_(Count) const XDP_RULE* Rules,
//     _In_ uint8_t Count
//     )
// {
//     CxPlatLockAcquire(&Interface->RuleLock);

//     BOOLEAN UpdateRules = FALSE;

//     for (uint8_t j = 0; j < Count; j++) {
//         for (uint8_t i = 0; i < Interface->RuleCount; i++) {
//             if (Interface->Rules[i].Match != Rules[j].Match) {
//                 continue;
//             }

//             if (Rules[j].Match == XDP_MATCH_UDP_DST || Rules[j].Match == XDP_MATCH_TCP_CONTROL_DST || Rules[j].Match == XDP_MATCH_TCP_DST) {
//                 if (Rules[j].Pattern.Port != Interface->Rules[i].Pattern.Port) {
//                     continue;
//                 }
//             } else if (Rules[j].Match == XDP_MATCH_QUIC_FLOW_SRC_CID || Rules[j].Match == XDP_MATCH_QUIC_FLOW_DST_CID ||
//                        Rules[j].Match == XDP_MATCH_TCP_QUIC_FLOW_SRC_CID || Rules[j].Match == XDP_MATCH_TCP_QUIC_FLOW_DST_CID) {
//                 if (Rules[j].Pattern.QuicFlow.UdpPort != Interface->Rules[i].Pattern.QuicFlow.UdpPort ||
//                     Rules[j].Pattern.QuicFlow.CidLength != Interface->Rules[i].Pattern.QuicFlow.CidLength ||
//                     Rules[j].Pattern.QuicFlow.CidOffset != Interface->Rules[i].Pattern.QuicFlow.CidOffset ||
//                     memcmp(Rules[j].Pattern.QuicFlow.CidData, Interface->Rules[i].Pattern.QuicFlow.CidData, Rules[j].Pattern.QuicFlow.CidLength) != 0) {
//                     continue;
//                 }
//             } else if (Rules[j].Match == XDP_MATCH_IPV4_UDP_TUPLE) {
//                 if (Rules[j].Pattern.Tuple.DestinationPort != Interface->Rules[i].Pattern.Tuple.DestinationPort ||
//                     Rules[j].Pattern.Tuple.SourcePort != Interface->Rules[i].Pattern.Tuple.SourcePort ||
//                     memcmp(&Rules[j].Pattern.Tuple.DestinationAddress.Ipv4, &Interface->Rules[i].Pattern.Tuple.DestinationAddress.Ipv4, sizeof(IN_ADDR)) != 0 ||
//                     memcmp(&Rules[j].Pattern.Tuple.SourceAddress.Ipv4, &Interface->Rules[i].Pattern.Tuple.SourceAddress.Ipv4, sizeof(IN_ADDR)) != 0) {
//                     continue;
//                 }
//             } else if (Rules[j].Match == XDP_MATCH_IPV6_UDP_TUPLE) {
//                 if (Rules[j].Pattern.Tuple.DestinationPort != Interface->Rules[i].Pattern.Tuple.DestinationPort ||
//                     Rules[j].Pattern.Tuple.SourcePort != Interface->Rules[i].Pattern.Tuple.SourcePort ||
//                     memcmp(&Rules[j].Pattern.Tuple.DestinationAddress.Ipv6, &Interface->Rules[i].Pattern.Tuple.DestinationAddress.Ipv6, sizeof(IN6_ADDR)) != 0 ||
//                     memcmp(&Rules[j].Pattern.Tuple.SourceAddress.Ipv6, &Interface->Rules[i].Pattern.Tuple.SourceAddress.Ipv6, sizeof(IN6_ADDR)) != 0) {
//                     continue;
//                 }
//             } else {
//                 CXPLAT_FRE_ASSERT(FALSE); // Should not be possible!
//             }

//             if (i < Interface->RuleCount - 1) {
//                 memmove(&Interface->Rules[i], &Interface->Rules[i + 1], sizeof(XDP_RULE) * (Interface->RuleCount - i - 1));
//             }
//             Interface->RuleCount--;
//             UpdateRules = TRUE;
//             break;
//         }
//     }

//     if (UpdateRules) {
//         CxPlatDpRawInterfaceUpdateRules(Interface);
//     }

//     CxPlatLockRelease(&Interface->RuleLock);
// }

// raw_commoh.h
_IRQL_requires_max_(PASSIVE_LEVEL)
size_t
CxPlatDpRawGetDatapathSize(
    _In_opt_ const QUIC_EXECUTION_CONFIG* Config
    )
{
    const uint32_t WorkerCount =
        (Config && Config->ProcessorCount) ? Config->ProcessorCount : CxPlatProcMaxCount();
    return sizeof(XDP_DATAPATH) + (WorkerCount * sizeof(XDP_WORKER));
}

// -> raw_commoh.h
_IRQL_requires_max_(PASSIVE_LEVEL)
QUIC_STATUS
CxPlatDpRawInitialize(
    _Inout_ CXPLAT_DATAPATH* Datapath,
    _In_ uint32_t ClientRecvContextLength,
    _In_opt_ const QUIC_EXECUTION_CONFIG* Config
    )
{
    UNREFERENCED_PARAMETER(Datapath);
    UNREFERENCED_PARAMETER(ClientRecvContextLength);
    UNREFERENCED_PARAMETER(Config);
    return QUIC_STATUS_NOT_SUPPORTED;
}

// xdp_common.h rename?
_IRQL_requires_max_(PASSIVE_LEVEL)
void
CxPlatDpRawRelease(
    _In_ XDP_DATAPATH* Xdp
    )
{
    UNREFERENCED_PARAMETER(Xdp);
}

// raw_common.h
_IRQL_requires_max_(PASSIVE_LEVEL)
void
CxPlatDpRawUninitialize(
    _In_ CXPLAT_DATAPATH* Datapath
    )
{
    XDP_DATAPATH* Xdp = (XDP_DATAPATH*)Datapath;
    QuicTraceLogVerbose(
        XdpUninitialize,
        "[ xdp][%p] XDP uninitialize",
        Xdp);
    Xdp->Running = FALSE;
    for (uint32_t i = 0; i < Xdp->WorkerCount; i++) {
        Xdp->Workers[i].Ec.Ready = TRUE;
        CxPlatWakeExecutionContext(&Xdp->Workers[i].Ec);
    }
    CxPlatDpRawRelease(Xdp);
}

// -> xdp_common.h direct?
_IRQL_requires_max_(PASSIVE_LEVEL)
void
CxPlatDpRawSetPortBit(
    _Inout_ uint8_t *BitMap,
    _In_ uint16_t Port
    )
{
    BitMap[Port >> 3] |= (1 << (Port & 0x7));
}

// -> xdp_common.h direct?
_IRQL_requires_max_(PASSIVE_LEVEL)
void
CxPlatDpRawClearPortBit(
    _Inout_ uint8_t *BitMap,
    _In_ uint16_t Port
    )
{
    BitMap[Port >> 3] &= (uint8_t)~(1 << (Port & 0x7));
}

// -> raw_common.h
_IRQL_requires_max_(PASSIVE_LEVEL)
void
CxPlatDpRawPlumbRulesOnSocket(
    _In_ CXPLAT_SOCKET* Socket,
    _In_ BOOLEAN IsCreated
    )
{
    UNREFERENCED_PARAMETER(Socket);
    UNREFERENCED_PARAMETER(IsCreated);
}

// -> raw_common.h
_IRQL_requires_max_(PASSIVE_LEVEL)
void
CxPlatDpRawAssignQueue(
    _In_ const CXPLAT_INTERFACE* _Interface,
    _Inout_ CXPLAT_ROUTE* Route
    )
{
    const XDP_INTERFACE* Interface = (const XDP_INTERFACE*)_Interface;
    Route->Queue = &Interface->Queues[0];
}

// -> raw_common.h
_IRQL_requires_max_(DISPATCH_LEVEL)
const CXPLAT_INTERFACE*
CxPlatDpRawGetInterfaceFromQueue(
    _In_ const void* Queue
    )
{
    return (const CXPLAT_INTERFACE*)((XDP_QUEUE*)Queue)->Interface;
}

// static
// BOOLEAN // Did work?
// CxPlatXdpRx(
//     _In_ const XDP_DATAPATH* Xdp,
//     _In_ XDP_QUEUE* Queue,
//     _In_ uint16_t ProcIndex
//     )
// {
//     UNREFERENCED_PARAMETER(Xdp);
//     UNREFERENCED_PARAMETER(Queue);
//     UNREFERENCED_PARAMETER(ProcIndex);
//     return FALSE;
// }

// -> raw_common.h
_IRQL_requires_max_(DISPATCH_LEVEL)
void
CxPlatDpRawRxFree(
    _In_opt_ const CXPLAT_RECV_DATA* PacketChain
    )
{
    UNREFERENCED_PARAMETER(PacketChain);
    // uint32_t Count = 0;
    // SLIST_ENTRY* Head = NULL;
    // SLIST_ENTRY** Tail = &Head;
    // SLIST_HEADER* Pool = NULL;

    // while (PacketChain) {
    //     const XDP_RX_PACKET* Packet = (XDP_RX_PACKET*)PacketChain;
    //     PacketChain = PacketChain->Next;
    //     // Packet->Allocated = FALSE; (other data paths don't clear this flag?)

    //     if (Pool != &Packet->Queue->RxPool) {
    //         if (Count > 0) {
    //             InterlockedPushListSList(
    //                 Pool, Head, CXPLAT_CONTAINING_RECORD(Tail, SLIST_ENTRY, Next), Count);
    //             Head = NULL;
    //             Tail = &Head;
    //             Count = 0;
    //         }

    //         Pool = &Packet->Queue->RxPool;
    //     }

    //     *Tail = (SLIST_ENTRY*)Packet;
    //     Tail = &((SLIST_ENTRY*)Packet)->Next;
    //     Count++;
    // }

    // if (Count > 0) {
    //     InterlockedPushListSList(Pool, Head, CXPLAT_CONTAINING_RECORD(Tail, SLIST_ENTRY, Next), Count);
    // }
}

// -> raw_common.h
_IRQL_requires_max_(DISPATCH_LEVEL)
CXPLAT_SEND_DATA*
CxPlatDpRawTxAlloc(
    _In_ CXPLAT_SOCKET* Socket,
    _Inout_ CXPLAT_SEND_CONFIG* Config
    )
{
    UNREFERENCED_PARAMETER(Socket);
    UNREFERENCED_PARAMETER(Config);
    // QUIC_ADDRESS_FAMILY Family = QuicAddrGetFamily(&Config->Route->RemoteAddress);
    // XDP_QUEUE* Queue = Config->Route->Queue;
    // XDP_TX_PACKET* Packet = (XDP_TX_PACKET*)InterlockedPopEntrySList(&Queue->TxPool);

    // if (Packet) {
    //     HEADER_BACKFILL HeaderBackfill = CxPlatDpRawCalculateHeaderBackFill(Family, Socket->UseTcp); // TODO - Cache in Route?
    //     CXPLAT_DBG_ASSERT(Config->MaxPacketSize <= sizeof(Packet->FrameBuffer) - HeaderBackfill.AllLayer);
    //     Packet->Queue = Queue;
    //     Packet->Buffer.Length = Config->MaxPacketSize;
    //     Packet->Buffer.Buffer = &Packet->FrameBuffer[HeaderBackfill.AllLayer];
    //     Packet->ECN = Config->ECN;
    // }

    // return (CXPLAT_SEND_DATA*)Packet;
    return NULL;
}

// -> raw_common.h
_IRQL_requires_max_(DISPATCH_LEVEL)
void
CxPlatDpRawTxFree(
    _In_ CXPLAT_SEND_DATA* SendData
    )
{
    UNREFERENCED_PARAMETER(SendData);
    // XDP_TX_PACKET* Packet = (XDP_TX_PACKET*)SendData;
    // InterlockedPushEntrySList(&Packet->Queue->TxPool, (PSLIST_ENTRY)Packet);
}

// -> raw_common.h
_IRQL_requires_max_(DISPATCH_LEVEL)
void
CxPlatDpRawTxEnqueue(
    _In_ CXPLAT_SEND_DATA* SendData
    )
{
    XDP_TX_PACKET* Packet = (XDP_TX_PACKET*)SendData;
    XDP_WORKER* Worker = Packet->Queue->Worker;

    CxPlatLockAcquire(&Packet->Queue->TxLock);
    CxPlatListInsertTail(&Packet->Queue->TxQueue, &Packet->Link);
    CxPlatLockRelease(&Packet->Queue->TxLock);

    Worker->Ec.Ready = TRUE;
    CxPlatWakeExecutionContext(&Worker->Ec);
}

// static
// BOOLEAN // Did work?
// CxPlatXdpTx(
//     _In_ const XDP_DATAPATH* Xdp,
//     _In_ XDP_QUEUE* Queue
//     )
// {
//     UNREFERENCED_PARAMETER(Xdp);
//     UNREFERENCED_PARAMETER(Queue);
//     return FALSE;
// }

// -> xdp_commoh.h or just internal
_IRQL_requires_max_(PASSIVE_LEVEL)
BOOLEAN
CxPlatXdpExecute(
    _Inout_ void* Context,
    _Inout_ CXPLAT_EXECUTION_STATE* State
    )
{
    UNREFERENCED_PARAMETER(Context);
    UNREFERENCED_PARAMETER(State);
    return FALSE;
}

// -> defined in platform_internal.h
void
CxPlatDataPathProcessCqe(
    _In_ CXPLAT_CQE* Cqe
    )
{
    if (CxPlatCqeType(Cqe) == CXPLAT_CQE_TYPE_SOCKET_IO) {
        DATAPATH_IO_SQE* Sqe =
            CXPLAT_CONTAINING_RECORD(CxPlatCqeUserData(Cqe), DATAPATH_IO_SQE, DatapathSqe);
        XDP_QUEUE* Queue;

        if (Sqe->IoType == DATAPATH_IO_RECV) {
            Queue = CXPLAT_CONTAINING_RECORD(Sqe, XDP_QUEUE, RxIoSqe);
            QuicTraceLogVerbose(
                XdpQueueAsyncIoRxComplete,
                "[ xdp][%p] XDP async IO complete (RX)",
                Queue);
            Queue->RxQueued = FALSE;
        } else {
            CXPLAT_DBG_ASSERT(Sqe->IoType == DATAPATH_IO_SEND);
            Queue = CXPLAT_CONTAINING_RECORD(Sqe, XDP_QUEUE, TxIoSqe);
            QuicTraceLogVerbose(
                XdpQueueAsyncIoTxComplete,
                "[ xdp][%p] XDP async IO complete (TX)",
                Queue);
            Queue->TxQueued = FALSE;
        }
        Queue->Worker->Ec.Ready = TRUE;
    } else if (CxPlatCqeType(Cqe) == CXPLAT_CQE_TYPE_SOCKET_SHUTDOWN) {
        XDP_WORKER* Worker =
            CXPLAT_CONTAINING_RECORD(CxPlatCqeUserData(Cqe), XDP_WORKER, ShutdownSqe);
        QuicTraceLogVerbose(
            XdpWorkerShutdownComplete,
            "[ xdp][%p] XDP worker shutdown complete",
            Worker);
        CxPlatDpRawRelease((XDP_DATAPATH*)Worker->Xdp);
    }
}
