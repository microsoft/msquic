/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.

Abstract:

    QUIC XDP Datapath Implementation

--*/

#define _CRT_SECURE_NO_WARNINGS 1 // TODO - Remove

#include "datapath_raw_win.h"
#include "datapath_raw_xdp.h"
#include <afxdp_helper.h>
#include <xdpapi.h>
#include <xdpapi_experimental.h>
#include <stdio.h>

#ifdef QUIC_CLOG
#include "datapath_raw_xdp_win.c.clog.h"
#endif

typedef struct XDP_INTERFACE {
    CXPLAT_INTERFACE;
    HANDLE XdpHandle;
    uint16_t QueueCount;
    uint8_t RuleCount;
    CXPLAT_LOCK RuleLock;
    XDP_RULE* Rules;
    XDP_QUEUE* Queues; // An array of queues.
    const struct XDP_DATAPATH* Xdp;
} XDP_INTERFACE;

typedef struct DECLSPEC_ALIGN(MEMORY_ALLOCATION_ALIGNMENT) XDP_RX_PACKET {
    // N.B. This struct is also put in a SLIST, so it must be aligned.
    XDP_QUEUE* Queue;
    CXPLAT_ROUTE RouteStorage;
    CXPLAT_RECV_DATA RecvData;
    // Followed by:
    // uint8_t ClientContext[...];
    // uint8_t FrameBuffer[MAX_ETH_FRAME_SIZE];
} XDP_RX_PACKET;

typedef struct DECLSPEC_ALIGN(MEMORY_ALLOCATION_ALIGNMENT) XDP_TX_PACKET {
    CXPLAT_SEND_DATA;
    XDP_QUEUE* Queue;
    CXPLAT_LIST_ENTRY Link;
    uint8_t FrameBuffer[MAX_ETH_FRAME_SIZE];
} XDP_TX_PACKET;


void XdpWorkerAddQueue(_In_ XDP_PARTITION* Partition, _In_ XDP_QUEUE* Queue) {
    XDP_QUEUE** Tail = &Partition->Queues;
    while (*Tail != NULL) {
        Tail = &(*Tail)->Next;
    }
    *Tail = Queue;
    Queue->Next = NULL;
    Queue->Partition = Partition;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
BOOLEAN
CxPlatXdpExecute(
    _Inout_ void* Context,
    _Inout_ CXPLAT_EXECUTION_STATE* State
    );

_IRQL_requires_max_(PASSIVE_LEVEL)
void
CxPlatDpRawInterfaceUninitialize(
    _Inout_ XDP_INTERFACE* Interface
    )
{
    #pragma warning(push)
    #pragma warning(disable:6001) // Using uninitialized memory

    for (uint32_t i = 0; Interface->Queues != NULL && i < Interface->QueueCount; i++) {
        XDP_QUEUE *Queue = &Interface->Queues[i];

        if (Queue->TxXsk != NULL) {
            CxPlatXdpCloseXsk(Interface->Xdp, Queue->TxXsk);
        }

        if (Queue->TxBuffers != NULL) {
            CXPLAT_FREE(Queue->TxBuffers, TX_BUFFER_TAG);
        }

        if (Queue->RxProgram != NULL) {
            CxPlatXdpCloseProgram(Interface->Xdp, Queue->RxProgram);
        }

        if (Queue->RxXsk != NULL) {
            CxPlatXdpCloseXsk(Interface->Xdp, Queue->RxXsk);
        }

        if (Queue->RxBuffers != NULL) {
            CXPLAT_FREE(Queue->RxBuffers, RX_BUFFER_TAG);
        }

        CxPlatLockUninitialize(&Queue->TxLock);
    }

    if (Interface->Queues != NULL) {
        CXPLAT_FREE(Interface->Queues, QUEUE_TAG);
    }

    if (Interface->Rules != NULL) {
        for (uint8_t i = 0; i < Interface->RuleCount; ++i) {
            if (Interface->Rules[i].Pattern.IpPortSet.PortSet.PortSet) {
                CXPLAT_FREE(
                    (uint8_t*)Interface->Rules[i].Pattern.IpPortSet.PortSet.PortSet, PORT_SET_TAG);
            }
        }
        CXPLAT_FREE(Interface->Rules, RULE_TAG);
    }

    if (Interface->XdpHandle) {
        CxPlatXdpCloseInterface(Interface->Xdp, Interface->XdpHandle);
    }

    CxPlatLockUninitialize(&Interface->RuleLock);

    #pragma warning(pop)
}

_IRQL_requires_max_(PASSIVE_LEVEL)
QUIC_STATUS
CxPlatDpRawInterfaceInitialize(
    _In_ XDP_DATAPATH* Xdp,
    _Inout_ XDP_INTERFACE* Interface,
    _In_ uint32_t ClientRecvContextLength
    )
{
    const uint32_t RxHeadroom = sizeof(XDP_RX_PACKET) + ALIGN_UP(ClientRecvContextLength, uint32_t);
    const uint32_t RxPacketSize = ALIGN_UP(RxHeadroom + MAX_ETH_FRAME_SIZE, XDP_RX_PACKET);
    QUIC_STATUS Status;

    CxPlatLockInitialize(&Interface->RuleLock);
    Interface->OffloadStatus.Receive.NetworkLayerXsum = Xdp->SkipXsum;
    Interface->OffloadStatus.Receive.TransportLayerXsum = Xdp->SkipXsum;
    Interface->OffloadStatus.Transmit.NetworkLayerXsum = Xdp->SkipXsum;
    Interface->OffloadStatus.Transmit.NetworkLayerXsum = Xdp->SkipXsum;
    Interface->Xdp = Xdp;

    Status = CxPlatXdpOpenInterface(Xdp, Interface->ActualIfIndex, &Interface->XdpHandle);
    if (QUIC_FAILED(Status)) {
        QuicTraceEvent(
            LibraryErrorStatus,
            "[ lib] ERROR, %u, %s.",
            Status,
            "XdpInterfaceOpen");
        goto Error;
    }

    Status = CxPlatGetInterfaceRssQueueCount(Xdp, Interface->XdpHandle, Interface->ActualIfIndex, &Interface->QueueCount);
    if (QUIC_FAILED(Status)) {
        goto Error;
    }

    if (Interface->QueueCount == 0) {
        Status = QUIC_STATUS_INVALID_STATE;
        QuicTraceEvent(
            LibraryErrorStatus,
            "[ lib] ERROR, %u, %s.",
            Status,
            "CxPlatGetInterfaceRssQueueCount");
        goto Error;
    }

    Interface->Queues = CXPLAT_ALLOC_NONPAGED(Interface->QueueCount * sizeof(*Interface->Queues), QUEUE_TAG);
    if (Interface->Queues == NULL) {
        QuicTraceEvent(
            AllocFailure,
            "Allocation of '%s' failed. (%llu bytes)",
            "XDP Queues",
            Interface->QueueCount * sizeof(*Interface->Queues));
        Status = QUIC_STATUS_OUT_OF_MEMORY;
        goto Error;
    }

    CxPlatZeroMemory(Interface->Queues, Interface->QueueCount * sizeof(*Interface->Queues));

    for (uint8_t i = 0; i < Interface->QueueCount; i++) {
        XDP_QUEUE* Queue = &Interface->Queues[i];

        Queue->Interface = Interface;
        InitializeSListHead(&Queue->RxPool);
        InitializeSListHead(&Queue->TxPool);
        CxPlatLockInitialize(&Queue->TxLock);
        CxPlatListInitializeHead(&Queue->TxQueue);
        CxPlatListInitializeHead(&Queue->PartitionTxQueue);
        CxPlatDatapathSqeInitialize(&Queue->RxIoSqe.DatapathSqe, CXPLAT_CQE_TYPE_SOCKET_IO);
        Queue->RxIoSqe.IoType = DATAPATH_XDP_IO_RECV;
        CxPlatDatapathSqeInitialize(&Queue->TxIoSqe.DatapathSqe, CXPLAT_CQE_TYPE_SOCKET_IO);
        Queue->TxIoSqe.IoType = DATAPATH_XDP_IO_SEND;

        //
        // RX datapath.
        //

        Queue->RxBuffers = CXPLAT_ALLOC_NONPAGED(Xdp->RxBufferCount * RxPacketSize, RX_BUFFER_TAG);
        if (Queue->RxBuffers == NULL) {
            QuicTraceEvent(
                AllocFailure,
                "Allocation of '%s' failed. (%llu bytes)",
                "XDP RX Buffers",
                Xdp->RxBufferCount * RxPacketSize);
            Status = QUIC_STATUS_OUT_OF_MEMORY;
            goto Error;
        }

        Status = CxPlatXdpCreateXsk(Xdp, &Queue->RxXsk);
        if (QUIC_FAILED(Status)) {
            QuicTraceEvent(
                LibraryErrorStatus,
                "[ lib] ERROR, %u, %s.",
                Status,
                "XskCreate");
            goto Error;
        }

        XSK_UMEM_REG RxUmem = {0};
        RxUmem.Address = Queue->RxBuffers;
        RxUmem.ChunkSize = RxPacketSize;
        RxUmem.Headroom = RxHeadroom;
        RxUmem.TotalSize = Xdp->RxBufferCount * RxPacketSize;

        Status = CxPlatXdpXskSetSockopt(Xdp, Queue->RxXsk, XSK_SOCKOPT_UMEM_REG, &RxUmem, sizeof(RxUmem));
        if (QUIC_FAILED(Status)) {
            QuicTraceEvent(
                LibraryErrorStatus,
                "[ lib] ERROR, %u, %s.",
                Status,
                "XskSetSockopt(XSK_SOCKOPT_UMEM_REG)");
            goto Error;
        }

        Status =
            CxPlatXdpXskSetSockopt(
                Xdp, Queue->RxXsk, XSK_SOCKOPT_RX_FILL_RING_SIZE, &Xdp->RxRingSize,
                sizeof(Xdp->RxRingSize));
        if (QUIC_FAILED(Status)) {
            QuicTraceEvent(
                LibraryErrorStatus,
                "[ lib] ERROR, %u, %s.",
                Status,
                "XskSetSockopt(XSK_SOCKOPT_RX_FILL_RING_SIZE)");
            goto Error;
        }

        Status =
            CxPlatXdpXskSetSockopt(
                Xdp, Queue->RxXsk, XSK_SOCKOPT_RX_RING_SIZE, &Xdp->RxRingSize, sizeof(Xdp->RxRingSize));
        if (QUIC_FAILED(Status)) {
            QuicTraceEvent(
                LibraryErrorStatus,
                "[ lib] ERROR, %u, %s.",
                Status,
                "XskSetSockopt(XSK_SOCKOPT_RX_RING_SIZE)");
            goto Error;
        }

        uint32_t Flags = XSK_BIND_FLAG_RX;
        Status = CxPlatXdpXskBind(Xdp, Queue->RxXsk, Interface->ActualIfIndex, i, Flags);
        if (QUIC_FAILED(Status)) {
            QuicTraceEvent(
                LibraryErrorStatus,
                "[ lib] ERROR, %u, %s.",
                Status,
                "XskBind");
            goto Error;
        }

        Status = CxPlatXdpXskActivate(Xdp, Queue->RxXsk, 0);
        if (QUIC_FAILED(Status)) {
            QuicTraceEvent(
                LibraryErrorStatus,
                "[ lib] ERROR, %u, %s.",
                Status,
                "XskActivate");
            goto Error;
        }

        XSK_RING_INFO_SET RxRingInfo;
        uint32_t RxRingInfoSize = sizeof(RxRingInfo);
        Status = CxPlatXdpXskGetSockopt(Xdp, Queue->RxXsk, XSK_SOCKOPT_RING_INFO, &RxRingInfo, &RxRingInfoSize);
        if (QUIC_FAILED(Status)) {
            QuicTraceEvent(
                LibraryErrorStatus,
                "[ lib] ERROR, %u, %s.",
                Status,
                "XskGetSockopt(XSK_SOCKOPT_RING_INFO)");
            goto Error;
        }

        XskRingInitialize(&Queue->RxFillRing, &RxRingInfo.Fill);
        XskRingInitialize(&Queue->RxRing, &RxRingInfo.Rx);

        for (uint32_t j = 0; j < Xdp->RxBufferCount; j++) {
            InterlockedPushEntrySList(
                &Queue->RxPool, (PSLIST_ENTRY)&Queue->RxBuffers[j * RxPacketSize]);
        }

#ifndef _KERNEL_MODE
        //
        // Disable automatic IO completions being queued if the call completes
        // synchronously.
        //
        if (!SetFileCompletionNotificationModes(
                (HANDLE)Queue->RxXsk,
                FILE_SKIP_COMPLETION_PORT_ON_SUCCESS | FILE_SKIP_SET_EVENT_ON_HANDLE)) {
            QuicTraceEvent(
                LibraryErrorStatus,
                "[ lib] ERROR, %u, %s.",
                Status,
                "SetFileCompletionNotificationModes");
            goto Error;
        }
#endif

        //
        // TX datapath.
        //

        Queue->TxBuffers = CXPLAT_ALLOC_NONPAGED(Xdp->TxBufferCount * sizeof(XDP_TX_PACKET), TX_BUFFER_TAG);
        if (Queue->TxBuffers == NULL) {
            QuicTraceEvent(
                AllocFailure,
                "Allocation of '%s' failed. (%llu bytes)",
                "XDP TX Buffers",
                Xdp->TxBufferCount * sizeof(XDP_TX_PACKET));
            Status = QUIC_STATUS_OUT_OF_MEMORY;
            goto Error;
        }

        Status = CxPlatXdpCreateXsk(Xdp, &Queue->TxXsk);
        if (QUIC_FAILED(Status)) {
            QuicTraceEvent(
                LibraryErrorStatus,
                "[ lib] ERROR, %u, %s.",
                Status,
                "XskCreate");
            goto Error;
        }

        XSK_UMEM_REG TxUmem = {0};
        TxUmem.Address = Queue->TxBuffers;
        TxUmem.ChunkSize = sizeof(XDP_TX_PACKET);
        TxUmem.Headroom = FIELD_OFFSET(XDP_TX_PACKET, FrameBuffer);
        TxUmem.TotalSize = Xdp->TxBufferCount * sizeof(XDP_TX_PACKET);

        Status = CxPlatXdpXskSetSockopt(Xdp, Queue->TxXsk, XSK_SOCKOPT_UMEM_REG, &TxUmem, sizeof(TxUmem));
        if (QUIC_FAILED(Status)) {
            QuicTraceEvent(
                LibraryErrorStatus,
                "[ lib] ERROR, %u, %s.",
                Status,
                "XskSetSockopt(XSK_SOCKOPT_UMEM_REG)");
            goto Error;
        }

        Status =
            CxPlatXdpXskSetSockopt(
                Xdp, Queue->TxXsk, XSK_SOCKOPT_TX_RING_SIZE, &Xdp->TxRingSize, sizeof(Xdp->TxRingSize));
        if (QUIC_FAILED(Status)) {
            QuicTraceEvent(
                LibraryErrorStatus,
                "[ lib] ERROR, %u, %s.",
                Status,
                "XskSetSockopt(XSK_SOCKOPT_TX_RING_SIZE)");
            goto Error;
        }

        Status =
            CxPlatXdpXskSetSockopt(
                Xdp, Queue->TxXsk, XSK_SOCKOPT_TX_COMPLETION_RING_SIZE, &Xdp->TxRingSize,
                sizeof(Xdp->TxRingSize));
        if (QUIC_FAILED(Status)) {
            QuicTraceEvent(
                LibraryErrorStatus,
                "[ lib] ERROR, %u, %s.",
                Status,
                "XskSetSockopt(XSK_SOCKOPT_TX_COMPLETION_RING_SIZE)");
            goto Error;
        }

        Flags = XSK_BIND_FLAG_TX; // TODO: support native/generic forced flags.
        Status = CxPlatXdpXskBind(Xdp, Queue->TxXsk, Interface->ActualIfIndex, i, Flags);
        if (QUIC_FAILED(Status)) {
            QuicTraceEvent(
                LibraryErrorStatus,
                "[ lib] ERROR, %u, %s.",
                Status,
                "XskBind");
            goto Error;
        }

        Status = CxPlatXdpXskActivate(Xdp, Queue->TxXsk, 0);
        if (QUIC_FAILED(Status)) {
            QuicTraceEvent(
                LibraryErrorStatus,
                "[ lib] ERROR, %u, %s.",
                Status,
                "XskActivate");
            goto Error;
        }

        XSK_RING_INFO_SET TxRingInfo;
        uint32_t TxRingInfoSize = sizeof(TxRingInfo);
        Status = CxPlatXdpXskGetSockopt(Xdp, Queue->TxXsk, XSK_SOCKOPT_RING_INFO, &TxRingInfo, &TxRingInfoSize);
        if (QUIC_FAILED(Status)) {
            QuicTraceEvent(
                LibraryErrorStatus,
                "[ lib] ERROR, %u, %s.",
                Status,
                "XskGetSockopt(XSK_SOCKOPT_RING_INFO)");
            goto Error;
        }

        XskRingInitialize(&Queue->TxRing, &TxRingInfo.Tx);
        XskRingInitialize(&Queue->TxCompletionRing, &TxRingInfo.Completion);

        for (uint32_t j = 0; j < Xdp->TxBufferCount; j++) {
            InterlockedPushEntrySList(
                &Queue->TxPool, (PSLIST_ENTRY)&Queue->TxBuffers[j * sizeof(XDP_TX_PACKET)]);
        }

#ifndef _KERNEL_MODE
        //
        // Disable automatic IO completions being queued if the call completes
        // synchronously.
        //
        if (!SetFileCompletionNotificationModes(
                (HANDLE)Queue->TxXsk,
                FILE_SKIP_COMPLETION_PORT_ON_SUCCESS | FILE_SKIP_SET_EVENT_ON_HANDLE)) {
            QuicTraceEvent(
                LibraryErrorStatus,
                "[ lib] ERROR, %u, %s.",
                Status,
                "SetFileCompletionNotificationModes");
            goto Error;
        }
#endif
    }

    //
    // Add each queue to a partition (round robin).
    //
    for (uint8_t i = 0; i < Interface->QueueCount; i++) {
        XdpWorkerAddQueue(&Xdp->Partitions[i % Xdp->PartitionCount], &Interface->Queues[i]);
    }

Error:
    if (QUIC_FAILED(Status)) {
        CxPlatDpRawInterfaceUninitialize(Interface);
    }

    return Status;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
_Requires_lock_held_(Interface->RuleLock)
void
CxPlatDpRawInterfaceUpdateRules(
    _In_ XDP_INTERFACE* Interface
    )
{
    static const XDP_HOOK_ID RxHook = {
        .Layer = XDP_HOOK_L2,
        .Direction = XDP_HOOK_RX,
        .SubLayer = XDP_HOOK_INSPECT,
    };

    for (uint32_t i = 0; i < Interface->QueueCount; i++) {

        XDP_QUEUE* Queue = &Interface->Queues[i];
        for (uint8_t j = 0; j < Interface->RuleCount; j++) {
            Interface->Rules[j].Redirect.Target = Queue->RxXsk;
        }

        HANDLE NewRxProgram;
        QUIC_STATUS Status =
            CxPlatXdpCreateProgram(
                Interface->Xdp,
                Interface->ActualIfIndex,
                &RxHook,
                i,
                0,
                Interface->Rules,
                Interface->RuleCount,
                &NewRxProgram);
        if (QUIC_FAILED(Status)) {
            //
            // TODO - Figure out how to better handle failure and revert changes.
            // This will likely require working with XDP to get an improved API;
            // possibly to update all queues at once.
            //
            QuicTraceEvent(
                LibraryErrorStatus,
                "[ lib] ERROR, %u, %s.",
                Status,
                "XdpCreateProgram");
            continue;
        }

        if (Queue->RxProgram != NULL) {
            CxPlatXdpCloseProgram(Interface->Xdp, Queue->RxProgram);
        }

        Queue->RxProgram = NewRxProgram;
    }
}

_IRQL_requires_max_(PASSIVE_LEVEL)
void
CxPlatDpRawInterfaceAddRules(
    _In_ XDP_INTERFACE* Interface,
    _In_reads_(Count) const XDP_RULE* Rules,
    _In_ uint8_t Count
    )
{
#pragma warning(push)
#pragma warning(disable:6386) // Buffer overrun while writing to 'NewRules' - FALSE POSITIVE

    CxPlatLockAcquire(&Interface->RuleLock);
    // TODO - Don't always allocate a new array?

    if ((uint32_t)Interface->RuleCount + (uint32_t)Count > UINT8_MAX) {
        QuicTraceEvent(
            LibraryError,
            "[ lib] ERROR, %s.",
            "No more room for rules");
        CxPlatLockRelease(&Interface->RuleLock);
        return;
    }

    const size_t OldSize = sizeof(XDP_RULE) * (size_t)Interface->RuleCount;
    const size_t NewSize = sizeof(XDP_RULE) * ((size_t)Interface->RuleCount + Count);

    XDP_RULE* NewRules = CXPLAT_ALLOC_NONPAGED(NewSize, RULE_TAG);
    if (NewRules == NULL) {
        QuicTraceEvent(
            AllocFailure,
            "Allocation of '%s' failed. (%llu bytes)",
            "XDP_RULE",
            NewSize);
        CxPlatLockRelease(&Interface->RuleLock);
        return;
    }

    if (Interface->RuleCount > 0) {
        memcpy(NewRules, Interface->Rules, OldSize);
    }
    for (uint8_t i = 0; i < Count; i++) {
        NewRules[Interface->RuleCount++] = Rules[i];
    }

    if (Interface->Rules != NULL) {
        CXPLAT_FREE(Interface->Rules, RULE_TAG);
    }
    Interface->Rules = NewRules;

    CxPlatDpRawInterfaceUpdateRules(Interface);

    CxPlatLockRelease(&Interface->RuleLock);

#pragma warning(pop)
}

_IRQL_requires_max_(PASSIVE_LEVEL)
void
CxPlatDpRawInterfaceRemoveRules(
    _In_ XDP_INTERFACE* Interface,
    _In_reads_(Count) const XDP_RULE* Rules,
    _In_ uint8_t Count
    )
{
    CxPlatLockAcquire(&Interface->RuleLock);

    BOOLEAN UpdateRules = FALSE;

    for (uint8_t j = 0; j < Count; j++) {
        for (uint8_t i = 0; i < Interface->RuleCount; i++) {
            if (Interface->Rules[i].Match != Rules[j].Match) {
                continue;
            }

            if (Rules[j].Match == XDP_MATCH_UDP_DST || Rules[j].Match == XDP_MATCH_TCP_CONTROL_DST || Rules[j].Match == XDP_MATCH_TCP_DST) {
                if (Rules[j].Pattern.Port != Interface->Rules[i].Pattern.Port) {
                    continue;
                }
            } else if (Rules[j].Match == XDP_MATCH_QUIC_FLOW_SRC_CID || Rules[j].Match == XDP_MATCH_QUIC_FLOW_DST_CID ||
                       Rules[j].Match == XDP_MATCH_TCP_QUIC_FLOW_SRC_CID || Rules[j].Match == XDP_MATCH_TCP_QUIC_FLOW_DST_CID) {
                if (Rules[j].Pattern.QuicFlow.UdpPort != Interface->Rules[i].Pattern.QuicFlow.UdpPort ||
                    Rules[j].Pattern.QuicFlow.CidLength != Interface->Rules[i].Pattern.QuicFlow.CidLength ||
                    Rules[j].Pattern.QuicFlow.CidOffset != Interface->Rules[i].Pattern.QuicFlow.CidOffset ||
                    memcmp(Rules[j].Pattern.QuicFlow.CidData, Interface->Rules[i].Pattern.QuicFlow.CidData, Rules[j].Pattern.QuicFlow.CidLength) != 0) {
                    continue;
                }
            } else if (Rules[j].Match == XDP_MATCH_IPV4_UDP_TUPLE) {
                if (Rules[j].Pattern.Tuple.DestinationPort != Interface->Rules[i].Pattern.Tuple.DestinationPort ||
                    Rules[j].Pattern.Tuple.SourcePort != Interface->Rules[i].Pattern.Tuple.SourcePort ||
                    memcmp(&Rules[j].Pattern.Tuple.DestinationAddress.Ipv4, &Interface->Rules[i].Pattern.Tuple.DestinationAddress.Ipv4, sizeof(IN_ADDR)) != 0 ||
                    memcmp(&Rules[j].Pattern.Tuple.SourceAddress.Ipv4, &Interface->Rules[i].Pattern.Tuple.SourceAddress.Ipv4, sizeof(IN_ADDR)) != 0) {
                    continue;
                }
            } else if (Rules[j].Match == XDP_MATCH_IPV6_UDP_TUPLE) {
                if (Rules[j].Pattern.Tuple.DestinationPort != Interface->Rules[i].Pattern.Tuple.DestinationPort ||
                    Rules[j].Pattern.Tuple.SourcePort != Interface->Rules[i].Pattern.Tuple.SourcePort ||
                    memcmp(&Rules[j].Pattern.Tuple.DestinationAddress.Ipv6, &Interface->Rules[i].Pattern.Tuple.DestinationAddress.Ipv6, sizeof(IN6_ADDR)) != 0 ||
                    memcmp(&Rules[j].Pattern.Tuple.SourceAddress.Ipv6, &Interface->Rules[i].Pattern.Tuple.SourceAddress.Ipv6, sizeof(IN6_ADDR)) != 0) {
                    continue;
                }
            } else {
                CXPLAT_FRE_ASSERT(FALSE); // Should not be possible!
            }

            if (i < Interface->RuleCount - 1) {
                memmove(&Interface->Rules[i], &Interface->Rules[i + 1], sizeof(XDP_RULE) * (Interface->RuleCount - i - 1));
            }
            Interface->RuleCount--;
            UpdateRules = TRUE;
            break;
        }
    }

    if (UpdateRules) {
        CxPlatDpRawInterfaceUpdateRules(Interface);
    }

    CxPlatLockRelease(&Interface->RuleLock);
}

_IRQL_requires_max_(PASSIVE_LEVEL)
size_t
CxPlatDpRawGetDatapathSize(
    _In_opt_ const QUIC_EXECUTION_CONFIG* Config
    )
{
    const uint32_t PartitionCount =
        (Config && Config->ProcessorCount) ? Config->ProcessorCount : CxPlatProcCount();
    return sizeof(XDP_DATAPATH) + (PartitionCount * sizeof(XDP_PARTITION));
}

_IRQL_requires_max_(PASSIVE_LEVEL)
QUIC_STATUS
CxPlatDpRawXdpCreateInterface(
    _In_ XDP_DATAPATH* Xdp,
    _In_ uint32_t IfIndex,
    _In_ uint32_t ActualIfIndex,
    _In_ uint8_t* PhysicalAddress,
    _In_ uint32_t ClientRecvContextLength
    )
{
    QUIC_STATUS Status;
    XDP_INTERFACE* Interface = CXPLAT_ALLOC_NONPAGED(sizeof(XDP_INTERFACE), IF_TAG);
    if (Interface == NULL) {
        QuicTraceEvent(
            AllocFailure,
            "Allocation of '%s' failed. (%llu bytes)",
            "XDP interface",
            sizeof(*Interface));
        Status = QUIC_STATUS_OUT_OF_MEMORY;
        goto Exit;
    }
    CxPlatZeroMemory(Interface, sizeof(*Interface));
    Interface->IfIndex = IfIndex;
    Interface->ActualIfIndex = ActualIfIndex;

    memcpy(
        Interface->PhysicalAddress, PhysicalAddress,
        sizeof(Interface->PhysicalAddress));

    Status =
        CxPlatDpRawInterfaceInitialize(
            Xdp, Interface, ClientRecvContextLength);
    if (QUIC_FAILED(Status)) {
        QuicTraceEvent(
            LibraryErrorStatus,
            "[ lib] ERROR, %u, %s.",
            Status,
            "CxPlatDpRawInterfaceInitialize");
        CXPLAT_FREE(Interface, IF_TAG);
        Status = QUIC_STATUS_SUCCESS;
        goto Exit;
    }
    CxPlatListInsertTail(&Xdp->Interfaces, &Interface->Link);
    Status = QUIC_STATUS_SUCCESS;

Exit:
    return Status;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
QUIC_STATUS
CxPlatDpRawInitialize(
    _Inout_ CXPLAT_DATAPATH_RAW* Datapath,
    _In_ uint32_t ClientRecvContextLength,
    _In_opt_ const QUIC_EXECUTION_CONFIG* Config
    )
{
    XDP_DATAPATH* Xdp = (XDP_DATAPATH*)Datapath;
    QUIC_STATUS Status;

    CxPlatListInitializeHead(&Xdp->Interfaces);

    Status = CxPlatXdpInitialize(Xdp);
    if (QUIC_FAILED(Status)) {
        goto Error;
    }

    CxPlatXdpReadConfig(Xdp);
    Xdp->PollingIdleTimeoutUs = Config ? Config->PollingIdleTimeoutUs : 0;

    if (Config && Config->ProcessorCount) {
        Xdp->PartitionCount = Config->ProcessorCount;
    } else {
        Xdp->PartitionCount = CxPlatProcCount();
    }

    QuicTraceLogVerbose(
        XdpInitialize,
        "[ xdp][%p] XDP initialized, %u procs",
        Xdp,
        Xdp->PartitionCount);

    Status = CxPlatXdpDiscoverInterfaces(Xdp, ClientRecvContextLength, CxPlatDpRawXdpCreateInterface);
    if (QUIC_FAILED(Status)) {
        goto Error;
    }

    if (CxPlatListIsEmpty(&Xdp->Interfaces)) {
        QuicTraceEvent(
            LibraryError,
            "[ lib] ERROR, %s.",
            "no XDP capable interface");
        Status = QUIC_STATUS_NOT_FOUND;
        goto Error;
    }

    Xdp->Running = TRUE;
    CxPlatRefInitialize(&Xdp->RefCount);
    for (uint32_t i = 0; i < Xdp->PartitionCount; i++) {

        XDP_PARTITION* Partition = &Xdp->Partitions[i];
        if (Partition->Queues == NULL) {
            //
            // Because queues are assigned in a round-robin manner, subsequent
            // partitions will not have a queue assigned. Stop the loop and update
            // partition count.
            //
            Xdp->PartitionCount = i;
            break;
        }

        Partition->Xdp = Xdp;
        Partition->PartitionIndex = (uint16_t)i;
        Partition->Ec.Ready = TRUE;
        Partition->Ec.NextTimeUs = UINT64_MAX;
        Partition->Ec.Callback = CxPlatXdpExecute;
        Partition->Ec.Context = &Xdp->Partitions[i];
        Partition->ShutdownSqe.CqeType = CXPLAT_CQE_TYPE_SOCKET_SHUTDOWN;
        CxPlatRefIncrement(&Xdp->RefCount);
        Partition->EventQ = CxPlatWorkerGetEventQ((uint16_t)i);

        uint32_t QueueCount = 0;
        XDP_QUEUE* Queue = Partition->Queues;
        while (Queue) {
#ifndef _KERNEL_MODE
            if (!CxPlatEventQAssociateHandle(Partition->EventQ, Queue->RxXsk)) {
                QuicTraceEvent(
                    LibraryErrorStatus,
                    "[ lib] ERROR, %u, %s.",
                    GetLastError(),
                    "CreateIoCompletionPort(RX)");
            }
            if (!CxPlatEventQAssociateHandle(Partition->EventQ, Queue->TxXsk)) {
                QuicTraceEvent(
                    LibraryErrorStatus,
                    "[ lib] ERROR, %u, %s.",
                    GetLastError(),
                    "CreateIoCompletionPort(TX)");
            }
#endif
            QuicTraceLogVerbose(
                XdpQueueStart,
                "[ xdp][%p] XDP queue start on partition %p",
                Queue,
                Partition);
            ++QueueCount;
            Queue = Queue->Next;
        }

        QuicTraceLogVerbose(
            XdpWorkerStart,
            "[ xdp][%p] XDP partition start, %u queues",
            Partition,
            QueueCount);

        CxPlatAddExecutionContext(&Partition->Ec, Partition->PartitionIndex);
    }
    Status = QUIC_STATUS_SUCCESS;

Error:

    if (QUIC_FAILED(Status)) {
        while (!CxPlatListIsEmpty(&Xdp->Interfaces)) {
            XDP_INTERFACE* Interface =
                CONTAINING_RECORD(CxPlatListRemoveHead(&Xdp->Interfaces), XDP_INTERFACE, Link);
            CxPlatDpRawInterfaceUninitialize(Interface);
            CXPLAT_FREE(Interface, IF_TAG);
        }

        CxPlatXdpUninitialize(Xdp);
    }

    return Status;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
void
CxPlatDpRawRelease(
    _In_ XDP_DATAPATH* Xdp
    )
{
    QuicTraceLogVerbose(
        XdpRelease,
        "[ xdp][%p] XDP release",
        Xdp);
    if (CxPlatRefDecrement(&Xdp->RefCount)) {
        QuicTraceLogVerbose(
            XdpUninitializeComplete,
            "[ xdp][%p] XDP uninitialize complete",
            Xdp);
        while (!CxPlatListIsEmpty(&Xdp->Interfaces)) {
            XDP_INTERFACE* Interface =
                CONTAINING_RECORD(CxPlatListRemoveHead(&Xdp->Interfaces), XDP_INTERFACE, Link);
            CxPlatDpRawInterfaceUninitialize(Interface);
            CXPLAT_FREE(Interface, IF_TAG);
        }
        CxPlatXdpUninitialize(Xdp);
        CxPlatDataPathUninitializeComplete((CXPLAT_DATAPATH_RAW*)Xdp);
    }
}

_IRQL_requires_max_(PASSIVE_LEVEL)
void
CxPlatDpRawUninitialize(
    _In_ CXPLAT_DATAPATH_RAW* Datapath
    )
{
    XDP_DATAPATH* Xdp = (XDP_DATAPATH*)Datapath;
    QuicTraceLogVerbose(
        XdpUninitialize,
        "[ xdp][%p] XDP uninitialize",
        Xdp);
    Xdp->Running = FALSE;
    for (uint32_t i = 0; i < Xdp->PartitionCount; i++) {
        Xdp->Partitions[i].Ec.Ready = TRUE;
        CxPlatWakeExecutionContext(&Xdp->Partitions[i].Ec);
    }
    CxPlatDpRawRelease(Xdp);
}

_IRQL_requires_max_(PASSIVE_LEVEL)
void
CxPlatDpRawUpdateConfig(
    _In_ CXPLAT_DATAPATH_RAW* Datapath,
    _In_ QUIC_EXECUTION_CONFIG* Config
    )
{
    XDP_DATAPATH* Xdp = (XDP_DATAPATH*)Datapath;
    Xdp->PollingIdleTimeoutUs = Config->PollingIdleTimeoutUs;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
QUIC_STATUS
RawSocketUpdateQeo(
    _In_ CXPLAT_SOCKET_RAW* Socket,
    _In_reads_(OffloadCount)
        const CXPLAT_QEO_CONNECTION* Offloads,
    _In_ uint32_t OffloadCount
    )
{
    XDP_DATAPATH* Xdp = (XDP_DATAPATH*)Socket->RawDatapath;

    XDP_QUIC_CONNECTION Connections[2];
    CXPLAT_FRE_ASSERT(OffloadCount == 2); // TODO - Refactor so upper layer struct matches XDP struct
                                          // so we don't need to copy to a different struct.

    QUIC_STATUS Status = QUIC_STATUS_SUCCESS;
    for (uint32_t i = 0; i < OffloadCount; i++) {
        XdpInitializeQuicConnection(&Connections[i], sizeof(Connections[i]));
        Connections[i].Operation = Offloads[i].Operation;
        Connections[i].Direction = Offloads[i].Direction;
        Connections[i].DecryptFailureAction = Offloads[i].DecryptFailureAction;
        Connections[i].KeyPhase = Offloads[i].KeyPhase;
        Connections[i].RESERVED = Offloads[i].RESERVED;
        Connections[i].CipherType = Offloads[i].CipherType;
        Connections[i].NextPacketNumber = Offloads[i].NextPacketNumber;
        if (Offloads[i].Address.si_family == AF_INET) {
            Connections[i].AddressFamily = XDP_QUIC_ADDRESS_FAMILY_INET4;
            memcpy(Connections[i].Address, &Offloads[i].Address.Ipv4.sin_addr, sizeof(IN_ADDR));
        } else if (Offloads[i].Address.si_family == AF_INET6) {
            Connections[i].AddressFamily = XDP_QUIC_ADDRESS_FAMILY_INET6;
            memcpy(Connections[i].Address, &Offloads[i].Address.Ipv6.sin6_addr, sizeof(IN6_ADDR));
        } else {
            CXPLAT_FRE_ASSERT(FALSE); // Should NEVER happen!
        }
        Connections[i].UdpPort = Offloads[i].Address.Ipv4.sin_port;
        Connections[i].ConnectionIdLength = Offloads[i].ConnectionIdLength;
        memcpy(Connections[i].ConnectionId, Offloads[i].ConnectionId, Offloads[i].ConnectionIdLength);
        memcpy(Connections[i].PayloadKey, Offloads[i].PayloadKey, sizeof(Connections[i].PayloadKey));
        memcpy(Connections[i].HeaderKey, Offloads[i].HeaderKey, sizeof(Connections[i].HeaderKey));
        memcpy(Connections[i].PayloadIv, Offloads[i].PayloadIv, sizeof(Connections[i].PayloadIv));
        Connections[i].Status = 0;
    }

    //
    // The following logic just tries all interfaces and if it's able to offload
    // to any of them, it considers it a success. Long term though, this should
    // only offload to the interface that the socket is bound to.
    //

    BOOLEAN AtLeastOneSucceeded = FALSE;
    for (CXPLAT_LIST_ENTRY* Entry = Xdp->Interfaces.Flink; Entry != &Xdp->Interfaces; Entry = Entry->Flink) {
        if (Xdp->XdpQeoSet != NULL) {
            Status =
                Xdp->XdpQeoSet(
                    CONTAINING_RECORD(Entry, XDP_INTERFACE, Link)->XdpHandle,
                    Connections,
                    sizeof(Connections));
        } else {
            Status = QUIC_STATUS_NOT_SUPPORTED;
        }
        if (QUIC_FAILED(Status)) {
            QuicTraceEvent(
                LibraryErrorStatus,
                "[ lib] ERROR, %u, %s.",
                Status,
                "XdpQeoSet");
        } else {
            AtLeastOneSucceeded = TRUE; // TODO - Check individual connection status too.
        }
    }

    return AtLeastOneSucceeded ? QUIC_STATUS_SUCCESS : QUIC_STATUS_NOT_SUPPORTED;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
VOID
CxPlatDpRawSetPortBit(
    _Inout_ uint8_t *BitMap,
    _In_ uint16_t Port
    )
{
    BitMap[Port >> 3] |= (1 << (Port & 0x7));
}

_IRQL_requires_max_(PASSIVE_LEVEL)
VOID
CxPlatDpRawClearPortBit(
    _Inout_ uint8_t *BitMap,
    _In_ uint16_t Port
    )
{
    BitMap[Port >> 3] &= (uint8_t)~(1 << (Port & 0x7));
}

_IRQL_requires_max_(PASSIVE_LEVEL)
void
CxPlatDpRawPlumbRulesOnSocket(
    _In_ CXPLAT_SOCKET_RAW* Socket,
    _In_ BOOLEAN IsCreated
    )
{
    XDP_DATAPATH* Xdp = (XDP_DATAPATH*)Socket->RawDatapath;
    if (Socket->Wildcard) {
        XDP_RULE Rules[3] = {0};
        uint8_t RulesSize = 0;
        if (Socket->CibirIdLength) {
            Rules[0].Match = Socket->UseTcp ? XDP_MATCH_TCP_QUIC_FLOW_SRC_CID : XDP_MATCH_QUIC_FLOW_SRC_CID;
            Rules[0].Pattern.QuicFlow.UdpPort = Socket->LocalAddress.Ipv4.sin_port;
            Rules[0].Pattern.QuicFlow.CidLength = Socket->CibirIdLength;
            Rules[0].Pattern.QuicFlow.CidOffset = Socket->CibirIdOffsetSrc;
            Rules[0].Action = XDP_PROGRAM_ACTION_REDIRECT;
            Rules[0].Redirect.TargetType = XDP_REDIRECT_TARGET_TYPE_XSK;
            Rules[0].Redirect.Target = NULL;

            Rules[1].Match = Socket->UseTcp ? XDP_MATCH_TCP_QUIC_FLOW_DST_CID : XDP_MATCH_QUIC_FLOW_DST_CID;
            Rules[1].Pattern.QuicFlow.UdpPort = Socket->LocalAddress.Ipv4.sin_port;
            Rules[1].Pattern.QuicFlow.CidLength = Socket->CibirIdLength;
            Rules[1].Pattern.QuicFlow.CidOffset = Socket->CibirIdOffsetDst;
            Rules[1].Action = XDP_PROGRAM_ACTION_REDIRECT;
            Rules[1].Redirect.TargetType = XDP_REDIRECT_TARGET_TYPE_XSK;
            Rules[1].Redirect.Target = NULL;

            memcpy(Rules[0].Pattern.QuicFlow.CidData, Socket->CibirId, Socket->CibirIdLength);
            memcpy(Rules[1].Pattern.QuicFlow.CidData, Socket->CibirId, Socket->CibirIdLength);

            RulesSize = 2;
            if (Socket->UseTcp) {
                Rules[2].Match = XDP_MATCH_TCP_CONTROL_DST;
                Rules[2].Pattern.Port = Socket->LocalAddress.Ipv4.sin_port;
                Rules[2].Action = XDP_PROGRAM_ACTION_REDIRECT;
                Rules[2].Redirect.TargetType = XDP_REDIRECT_TARGET_TYPE_XSK;
                Rules[2].Redirect.Target = NULL;
                ++RulesSize;
            }
            CXPLAT_DBG_ASSERT(RulesSize <= RTL_NUMBER_OF(Rules));
        } else {
            Rules[0].Match = Socket->UseTcp ? XDP_MATCH_TCP_DST : XDP_MATCH_UDP_DST;
            Rules[0].Pattern.Port = Socket->LocalAddress.Ipv4.sin_port;
            Rules[0].Action = XDP_PROGRAM_ACTION_REDIRECT;
            Rules[0].Redirect.TargetType = XDP_REDIRECT_TARGET_TYPE_XSK;
            Rules[0].Redirect.Target = NULL;

            RulesSize = 1;
        }

        CXPLAT_LIST_ENTRY* Entry;
        for (Entry = Xdp->Interfaces.Flink; Entry != &Xdp->Interfaces; Entry = Entry->Flink) {
            XDP_INTERFACE* Interface = CONTAINING_RECORD(Entry, XDP_INTERFACE, Link);
            if (IsCreated) {
                CxPlatDpRawInterfaceAddRules(Interface, Rules, RulesSize);
            } else {
                CxPlatDpRawInterfaceRemoveRules(Interface, Rules, RulesSize);
            }
        }
    } else {

        //
        // TODO - Optimization: apply only to the correct interface.
        //
        CXPLAT_LIST_ENTRY* Entry;
        XDP_MATCH_TYPE MatchType;
        uint8_t* IpAddress;
        size_t IpAddressSize;
        if (Socket->LocalAddress.si_family == QUIC_ADDRESS_FAMILY_INET) {
            MatchType = Socket->UseTcp ? XDP_MATCH_IPV4_TCP_PORT_SET : XDP_MATCH_IPV4_UDP_PORT_SET;
            IpAddress = (uint8_t*)&Socket->LocalAddress.Ipv4.sin_addr;
            IpAddressSize = sizeof(IN_ADDR);
        } else {
            MatchType = Socket->UseTcp ? XDP_MATCH_IPV6_TCP_PORT_SET : XDP_MATCH_IPV6_UDP_PORT_SET;
            IpAddress = (uint8_t*)&Socket->LocalAddress.Ipv6.sin6_addr;
            IpAddressSize = sizeof(IN6_ADDR);
        }
        for (Entry = Xdp->Interfaces.Flink; Entry != &Xdp->Interfaces; Entry = Entry->Flink) {
            XDP_INTERFACE* Interface = CONTAINING_RECORD(Entry, XDP_INTERFACE, Link);
            XDP_RULE* Rule = NULL;
            CxPlatLockAcquire(&Interface->RuleLock);
            for (uint8_t i = 0; i < Interface->RuleCount; ++i) {
                if (Interface->Rules[i].Match == MatchType &&
                    memcmp(
                        &Interface->Rules[i].Pattern.IpPortSet.Address,
                        IpAddress,
                        IpAddressSize) == 0) {
                    Rule = &Interface->Rules[i];
                    break;
                }
            }
            if (IsCreated) {
                if (Rule) {
                    CxPlatDpRawSetPortBit(
                        (uint8_t*)Rule->Pattern.IpPortSet.PortSet.PortSet,
                        Socket->LocalAddress.Ipv4.sin_port);
                    CxPlatLockRelease(&Interface->RuleLock);
                } else {
                    CxPlatLockRelease(&Interface->RuleLock);
                    XDP_RULE NewRule = {
                        .Match = MatchType,
                        .Pattern.IpPortSet.PortSet.PortSet = CXPLAT_ALLOC_NONPAGED(XDP_PORT_SET_BUFFER_SIZE, PORT_SET_TAG),
                        .Action = XDP_PROGRAM_ACTION_REDIRECT,
                        .Redirect.TargetType = XDP_REDIRECT_TARGET_TYPE_XSK,
                        .Redirect.Target = NULL,
                    };
                    if (NewRule.Pattern.IpPortSet.PortSet.PortSet) {
                        CxPlatZeroMemory(
                            (uint8_t*)NewRule.Pattern.IpPortSet.PortSet.PortSet,
                            XDP_PORT_SET_BUFFER_SIZE);
                    } else {
                        QuicTraceEvent(
                            AllocFailure,
                            "Allocation of '%s' failed. (%llu bytes)",
                            "PortSet",
                            XDP_PORT_SET_BUFFER_SIZE);
                        return;
                    }
                    CxPlatDpRawSetPortBit(
                        (uint8_t*)NewRule.Pattern.IpPortSet.PortSet.PortSet,
                        Socket->LocalAddress.Ipv4.sin_port);
                    memcpy(
                        &NewRule.Pattern.IpPortSet.Address, IpAddress, IpAddressSize);
                    CxPlatDpRawInterfaceAddRules(Interface, &NewRule, 1);
                }
            } else {
                //
                // Due to memory allocation failures, we might not have this rule programmed on the interface.
                //
                if (Rule) {
                    CxPlatDpRawClearPortBit(
                        (uint8_t*)Rule->Pattern.IpPortSet.PortSet.PortSet,
                        Socket->LocalAddress.Ipv4.sin_port);
                }
                CxPlatLockRelease(&Interface->RuleLock);
            }
        }
    }
}

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

_IRQL_requires_max_(DISPATCH_LEVEL)
const CXPLAT_INTERFACE*
CxPlatDpRawGetInterfaceFromQueue(
    _In_ const void* Queue
    )
{
    return (const CXPLAT_INTERFACE*)((XDP_QUEUE*)Queue)->Interface;
}

static
BOOLEAN // Did work?
CxPlatXdpRx(
    _In_ const XDP_DATAPATH* Xdp,
    _In_ XDP_QUEUE* Queue,
    _In_ uint16_t PartitionIndex
    )
{
    CXPLAT_RECV_DATA* Buffers[RX_BATCH_SIZE];
    uint32_t RxIndex;
    uint32_t FillIndex;
    uint32_t ProdCount = 0;
    uint32_t PacketCount = 0;
    const uint32_t BuffersCount = XskRingConsumerReserve(&Queue->RxRing, RX_BATCH_SIZE, &RxIndex);

    for (uint32_t i = 0; i < BuffersCount; i++) {
        XSK_BUFFER_DESCRIPTOR* Buffer = XskRingGetElement(&Queue->RxRing, RxIndex++);
        XDP_RX_PACKET* Packet =
            (XDP_RX_PACKET*)(Queue->RxBuffers + Buffer->Address.BaseAddress);
        uint8_t* FrameBuffer = (uint8_t*)Packet + Buffer->Address.Offset;

        CxPlatZeroMemory(Packet, sizeof(XDP_RX_PACKET));
        Packet->Queue = Queue;
        Packet->RouteStorage.Queue = Queue;
        Packet->RecvData.Route = &Packet->RouteStorage;
        Packet->RecvData.Route->DatapathType = Packet->RecvData.DatapathType = CXPLAT_DATAPATH_TYPE_RAW;
        Packet->RecvData.PartitionIndex = PartitionIndex;

        CxPlatDpRawParseEthernet(
            (CXPLAT_DATAPATH*)Xdp,
            &Packet->RecvData,
            FrameBuffer,
            (uint16_t)Buffer->Length);

        //
        // The route has been filled in with the packet's src/dst IP and ETH addresses, so
        // mark it resolved. This allows stateless sends to be issued without performing
        // a route lookup.
        //
        Packet->RecvData.Route->State = RouteResolved;

        if (Packet->RecvData.Buffer) {
            Packet->RecvData.Allocated = TRUE;
            Buffers[PacketCount++] = &Packet->RecvData;
        } else {
            CxPlatListPushEntry(&Queue->PartitionRxPool, (CXPLAT_SLIST_ENTRY*)Packet);
        }
    }

    if (BuffersCount > 0) {
        XskRingConsumerRelease(&Queue->RxRing, BuffersCount);
    }

    uint32_t FillAvailable = XskRingProducerReserve(&Queue->RxFillRing, MAXUINT32, &FillIndex);
    while (FillAvailable-- > 0) {
        if (Queue->PartitionRxPool.Next == NULL) {
            Queue->PartitionRxPool.Next = (CXPLAT_SLIST_ENTRY*)InterlockedFlushSList(&Queue->RxPool);
        }

        XDP_RX_PACKET* Packet = (XDP_RX_PACKET*)CxPlatListPopEntry(&Queue->PartitionRxPool);
        if (Packet == NULL) {
            break;
        }

        uint64_t* FillDesc = XskRingGetElement(&Queue->RxFillRing, FillIndex++);
        *FillDesc = (uint8_t*)Packet - Queue->RxBuffers;
        ProdCount++;
    }

    if (ProdCount > 0) {
        XskRingProducerSubmit(&Queue->RxFillRing, ProdCount);
    }

    if (PacketCount > 0) {
        CxPlatDpRawRxEthernet((CXPLAT_DATAPATH_RAW*)Xdp, Buffers, (uint16_t)PacketCount);
    }

    if (XskRingError(&Queue->RxRing) && !Queue->Error) {
        XSK_ERROR ErrorStatus;
        QUIC_STATUS XskStatus;
        uint32_t ErrorSize = sizeof(ErrorStatus);
        XskStatus = CxPlatXdpXskGetSockopt(Xdp, Queue->RxXsk, XSK_SOCKOPT_RX_ERROR, &ErrorStatus, &ErrorSize);
        QuicTraceEvent(
            LibraryErrorStatus,
            "[ lib] ERROR, %u, %s.",
            XskStatus == 0 ? ErrorStatus : XskStatus,
            "XSK_SOCKOPT_RX_ERROR");
        Queue->Error = TRUE;
    }

    return ProdCount > 0 || PacketCount > 0;
}

_IRQL_requires_max_(DISPATCH_LEVEL)
void
CxPlatDpRawRxFree(
    _In_opt_ const CXPLAT_RECV_DATA* PacketChain
    )
{
    uint32_t Count = 0;
    SLIST_ENTRY* Head = NULL;
    SLIST_ENTRY** Tail = &Head;
    SLIST_HEADER* Pool = NULL;

    while (PacketChain) {
        const XDP_RX_PACKET* Packet =
            CXPLAT_CONTAINING_RECORD(PacketChain, XDP_RX_PACKET, RecvData);
        PacketChain = PacketChain->Next;
        // Packet->Allocated = FALSE; (other data paths don't clear this flag?)

        if (Pool != &Packet->Queue->RxPool) {
            if (Count > 0) {
                InterlockedPushListSList(
                    Pool, Head, CONTAINING_RECORD(Tail, SLIST_ENTRY, Next), Count);
                Head = NULL;
                Tail = &Head;
                Count = 0;
            }

            Pool = &Packet->Queue->RxPool;
        }

        *Tail = (SLIST_ENTRY*)Packet;
        Tail = &((SLIST_ENTRY*)Packet)->Next;
        Count++;
    }

    if (Count > 0) {
        InterlockedPushListSList(Pool, Head, CONTAINING_RECORD(Tail, SLIST_ENTRY, Next), Count);
    }
}

_IRQL_requires_max_(DISPATCH_LEVEL)
CXPLAT_SEND_DATA*
CxPlatDpRawTxAlloc(
    _In_ CXPLAT_SOCKET_RAW* Socket,
    _Inout_ CXPLAT_SEND_CONFIG* Config
    )
{
    QUIC_ADDRESS_FAMILY Family = QuicAddrGetFamily(&Config->Route->RemoteAddress);
    XDP_QUEUE* Queue = Config->Route->Queue;
    CXPLAT_DBG_ASSERT(Queue != NULL);
    CXPLAT_DBG_ASSERT(&Queue->TxPool != NULL);
    XDP_TX_PACKET* Packet = (XDP_TX_PACKET*)InterlockedPopEntrySList(&Queue->TxPool);

    if (Packet) {
        HEADER_BACKFILL HeaderBackfill = CxPlatDpRawCalculateHeaderBackFill(Family, Socket->UseTcp); // TODO - Cache in Route?
        CXPLAT_DBG_ASSERT(Config->MaxPacketSize <= sizeof(Packet->FrameBuffer) - HeaderBackfill.AllLayer);
        Packet->Queue = Queue;
        Packet->Buffer.Length = Config->MaxPacketSize;
        Packet->Buffer.Buffer = &Packet->FrameBuffer[HeaderBackfill.AllLayer];
        Packet->ECN = Config->ECN;
        Packet->DatapathType = Config->Route->DatapathType = CXPLAT_DATAPATH_TYPE_RAW;
    }

    return (CXPLAT_SEND_DATA*)Packet;
}

_IRQL_requires_max_(DISPATCH_LEVEL)
void
CxPlatDpRawTxFree(
    _In_ CXPLAT_SEND_DATA* SendData
    )
{
    XDP_TX_PACKET* Packet = (XDP_TX_PACKET*)SendData;
    InterlockedPushEntrySList(&Packet->Queue->TxPool, (PSLIST_ENTRY)Packet);
}

_IRQL_requires_max_(DISPATCH_LEVEL)
void
CxPlatDpRawTxEnqueue(
    _In_ CXPLAT_SEND_DATA* SendData
    )
{
    XDP_TX_PACKET* Packet = (XDP_TX_PACKET*)SendData;
    XDP_PARTITION* Partition = Packet->Queue->Partition;

    CxPlatLockAcquire(&Packet->Queue->TxLock);
    CxPlatListInsertTail(&Packet->Queue->TxQueue, &Packet->Link);
    CxPlatLockRelease(&Packet->Queue->TxLock);

    Partition->Ec.Ready = TRUE;
    CxPlatWakeExecutionContext(&Partition->Ec);
}

static
BOOLEAN // Did work?
CxPlatXdpTx(
    _In_ const XDP_DATAPATH* Xdp,
    _In_ XDP_QUEUE* Queue
    )
{
    uint32_t ProdCount = 0;
    uint32_t CompCount = 0;
    SLIST_ENTRY* TxCompleteHead = NULL;
    SLIST_ENTRY** TxCompleteTail = &TxCompleteHead;

    if (CxPlatListIsEmpty(&Queue->PartitionTxQueue) &&
        ReadPointerNoFence(&Queue->TxQueue.Flink) != &Queue->TxQueue) {
        CxPlatLockAcquire(&Queue->TxLock);
        CxPlatListMoveItems(&Queue->TxQueue, &Queue->PartitionTxQueue);
        CxPlatLockRelease(&Queue->TxLock);
    }

    uint32_t CompIndex;
    uint32_t CompAvailable =
        XskRingConsumerReserve(&Queue->TxCompletionRing, MAXUINT32, &CompIndex);
    while (CompAvailable-- > 0) {
        uint64_t* CompDesc = XskRingGetElement(&Queue->TxCompletionRing, CompIndex++);
        XDP_TX_PACKET* Packet = (XDP_TX_PACKET*)(Queue->TxBuffers + *CompDesc);
        *TxCompleteTail = (PSLIST_ENTRY)Packet;
        TxCompleteTail = &((PSLIST_ENTRY)Packet)->Next;
        CompCount++;
    }

    if (CompCount > 0) {
        XskRingConsumerRelease(&Queue->TxCompletionRing, CompCount);
        InterlockedPushListSList(
            &Queue->TxPool, TxCompleteHead, CONTAINING_RECORD(TxCompleteTail, SLIST_ENTRY, Next),
            CompCount);
    }

    uint32_t TxIndex;
    uint32_t TxAvailable = XskRingProducerReserve(&Queue->TxRing, MAXUINT32, &TxIndex);
    while (TxAvailable-- > 0 && !CxPlatListIsEmpty(&Queue->PartitionTxQueue)) {
        XSK_BUFFER_DESCRIPTOR* Buffer = XskRingGetElement(&Queue->TxRing, TxIndex++);
        CXPLAT_LIST_ENTRY* Entry = CxPlatListRemoveHead(&Queue->PartitionTxQueue);
        XDP_TX_PACKET* Packet = CONTAINING_RECORD(Entry, XDP_TX_PACKET, Link);

        Buffer->Address.BaseAddress = (uint8_t*)Packet - Queue->TxBuffers;
        Buffer->Address.Offset = FIELD_OFFSET(XDP_TX_PACKET, FrameBuffer);
        Buffer->Length = Packet->Buffer.Length;
        ProdCount++;
    }

    if (ProdCount > 0 ||
        (CompCount > 0 && XskRingProducerReserve(&Queue->TxRing, MAXUINT32, &TxIndex) != Queue->TxRing.Size)) {
        XskRingProducerSubmit(&Queue->TxRing, ProdCount);
        if (Xdp->TxAlwaysPoke || XskRingProducerNeedPoke(&Queue->TxRing)) {
            QUIC_STATUS Status = CxPlatXdpXskPokeTx(Xdp, Queue->TxXsk);
            CXPLAT_DBG_ASSERT(QUIC_SUCCEEDED(Status));
            UNREFERENCED_PARAMETER(Status);
        }
    }

    if (XskRingError(&Queue->TxRing) && !Queue->Error) {
        XSK_ERROR ErrorStatus;
        QUIC_STATUS XskStatus;
        uint32_t ErrorSize = sizeof(ErrorStatus);
        XskStatus = CxPlatXdpXskGetSockopt(Xdp, Queue->TxXsk, XSK_SOCKOPT_TX_ERROR, &ErrorStatus, &ErrorSize);
        QuicTraceEvent(
            LibraryErrorStatus,
            "[ lib] ERROR, %u, %s.",
            XskStatus == 0 ? ErrorStatus : XskStatus,
            "XSK_SOCKOPT_TX_ERROR");
        Queue->Error = TRUE;
    }

    return ProdCount > 0 || CompCount > 0;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
BOOLEAN
CxPlatXdpExecute(
    _Inout_ void* Context,
    _Inout_ CXPLAT_EXECUTION_STATE* State
    )
{
    XDP_PARTITION* Partition = (XDP_PARTITION*)Context;
    const XDP_DATAPATH* Xdp = Partition->Xdp;

    if (!Xdp->Running) {
        QuicTraceLogVerbose(
            XdpPartitionShutdown,
            "[ xdp][%p] XDP partition shutdown",
            Partition);
        XDP_QUEUE* Queue = Partition->Queues;
        while (Queue) {
#ifdef _KERNEL_MODE
            // TODO: Do we need a rundown for XSK usage?
#elif _WIN32
            CancelIoEx(Queue->RxXsk, NULL);
#endif
            CxPlatXdpCloseXsk(Xdp, Queue->RxXsk);
            Queue->RxXsk = NULL;
#ifdef _KERNEL_MODE
            // TODO: Do we need a rundown for XSK usage?
#elif _WIN32
            CancelIoEx(Queue->TxXsk, NULL);
#endif
            CxPlatXdpCloseXsk(Xdp, Queue->TxXsk);
            Queue->TxXsk = NULL;
            Queue = Queue->Next;
        }
        QuicTraceLogInfo(
            LogInfo,
            "[ xdp] INFO, Queueing shutdown.");
        CxPlatEventQEnqueue(Partition->EventQ, &Partition->ShutdownSqe.Sqe, &Partition->ShutdownSqe);
        return FALSE;
    }

    const BOOLEAN PollingExpired =
        CxPlatTimeDiff64(State->LastWorkTime, State->TimeNow) >= Xdp->PollingIdleTimeoutUs;

    BOOLEAN DidWork = FALSE;
    XDP_QUEUE* Queue = Partition->Queues;
    while (Queue) {
        DidWork |= CxPlatXdpRx(Xdp, Queue, Partition->PartitionIndex);
        DidWork |= CxPlatXdpTx(Xdp, Queue);
        Queue = Queue->Next;
    }

    if (DidWork) {
        Partition->Ec.Ready = TRUE;
        State->NoWorkCount = 0;
    } else if (!PollingExpired) {
        Partition->Ec.Ready = TRUE;
    } else {
        Queue = Partition->Queues;
        while (Queue) {
            if (!Queue->RxQueued) {
                QuicTraceLogVerbose(
                    XdpQueueAsyncIoRx,
                    "[ xdp][%p] XDP async IO start (RX)",
                    Queue);
                CxPlatZeroMemory(
                    &Queue->RxIoSqe.DatapathSqe.Sqe.Overlapped,
                    sizeof(Queue->RxIoSqe.DatapathSqe.Sqe.Overlapped));
                XSK_NOTIFY_RESULT_FLAGS ResultFlags;
                XDP_STATUS Status =
                    CxPlatXdpXskNotifyAsync(
                        Xdp, Queue->RxXsk, XSK_NOTIFY_FLAG_WAIT_RX,
                        &Queue->RxIoSqe.DatapathSqe.Sqe.Overlapped, &ResultFlags);
#ifdef _KERNEL_MODE
                if (Status == STATUS_SUCCESS) {
                    if (ResultFlags & XSK_NOTIFY_RESULT_FLAG_RX_AVAILABLE) {
                        Partition->Ec.Ready = TRUE;
                    } else {
                        Queue->RxQueued = TRUE;
                    }
#elif _WIN32
                if ((HRESULT)Status == HRESULT_FROM_WIN32(ERROR_IO_PENDING)) {
                    Queue->RxQueued = TRUE;
                } else if (Status == S_OK) {
                    Partition->Ec.Ready = TRUE;
#endif
                } else {
                    QuicTraceEvent(
                        LibraryErrorStatus,
                        "[ lib] ERROR, %u, %s.",
                        Status,
                        "XskNotifyAsync(RX)");
                }
            }
            if (!Queue->TxQueued) {
                QuicTraceLogVerbose(
                    XdpQueueAsyncIoTx,
                    "[ xdp][%p] XDP async IO start (TX)",
                    Queue);
                CxPlatZeroMemory(
                    &Queue->TxIoSqe.DatapathSqe.Sqe.Overlapped,
                    sizeof(Queue->TxIoSqe.DatapathSqe.Sqe.Overlapped));
                XSK_NOTIFY_RESULT_FLAGS ResultFlags;
                XDP_STATUS Status =
                    CxPlatXdpXskNotifyAsync(
                        Xdp, Queue->TxXsk, XSK_NOTIFY_FLAG_WAIT_TX,
                        &Queue->TxIoSqe.DatapathSqe.Sqe.Overlapped, &ResultFlags);
#ifdef _KERNEL_MODE
                if (Status == STATUS_SUCCESS) {
                    if (ResultFlags & XSK_NOTIFY_RESULT_FLAG_TX_COMP_AVAILABLE) {
                        Partition->Ec.Ready = TRUE;
                    } else {
                        Queue->TxQueued = TRUE;
                    }
#elif _WIN32
                if ((HRESULT)Status == HRESULT_FROM_WIN32(ERROR_IO_PENDING)) {
                    Queue->TxQueued = TRUE;
                } else if (Status == S_OK) {
                    Partition->Ec.Ready = TRUE;
#endif
                } else {
                    QuicTraceEvent(
                        LibraryErrorStatus,
                        "[ lib] ERROR, %u, %s.",
                        Status,
                        "XskNotifyAsync(TX)");
                }
            }
            Queue = Queue->Next;
        }
    }

    return TRUE;
}

void
RawDataPathProcessCqe(
    _In_ CXPLAT_CQE* Cqe
    )
{
    if (CxPlatCqeType(Cqe) == CXPLAT_CQE_TYPE_SOCKET_IO) {
        DATAPATH_XDP_IO_SQE* Sqe =
            CONTAINING_RECORD(CxPlatCqeUserData(Cqe), DATAPATH_XDP_IO_SQE, DatapathSqe);
        XDP_QUEUE* Queue;

        if (Sqe->IoType == DATAPATH_XDP_IO_RECV) {
            Queue = CONTAINING_RECORD(Sqe, XDP_QUEUE, RxIoSqe);
            QuicTraceLogVerbose(
                XdpQueueAsyncIoRxComplete,
                "[ xdp][%p] XDP async IO complete (RX)",
                Queue);
            Queue->RxQueued = FALSE;
        } else {
            CXPLAT_DBG_ASSERT(Sqe->IoType == DATAPATH_XDP_IO_SEND);
            Queue = CONTAINING_RECORD(Sqe, XDP_QUEUE, TxIoSqe);
            QuicTraceLogVerbose(
                XdpQueueAsyncIoTxComplete,
                "[ xdp][%p] XDP async IO complete (TX)",
                Queue);
            Queue->TxQueued = FALSE;
        }
        Queue->Partition->Ec.Ready = TRUE;
    } else if (CxPlatCqeType(Cqe) == CXPLAT_CQE_TYPE_SOCKET_SHUTDOWN) {
        XDP_PARTITION* Partition =
            CONTAINING_RECORD(CxPlatCqeUserData(Cqe), XDP_PARTITION, ShutdownSqe);
        QuicTraceLogVerbose(
            XdpPartitionShutdownComplete,
            "[ xdp][%p] XDP partition shutdown complete",
            Partition);
        CxPlatDpRawRelease((XDP_DATAPATH*)Partition->Xdp);
    }
}
