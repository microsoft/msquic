/*++
    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.
--*/
#ifdef QUIC_CLOG
#include "pathid.h.clog.h"
#endif

//
// Different flags of a pathid.
// Note - Keep quictypes.h's copy up to date.
//
typedef union QUIC_PATHID_FLAGS {
    uint64_t AllFlags;
    struct {
        BOOLEAN InPathIDTable           : 1;    // The path id is currently in the connection's table.
        BOOLEAN InUse                   : 1;    // The path id is currently in use.
        BOOLEAN Abandoned               : 1;
        BOOLEAN WaitClose               : 1;    
        BOOLEAN Closed                  : 1;    
        BOOLEAN Started                 : 1;    // The path id has started.
        BOOLEAN Freed                   : 1;    // The path id has been freed.
        BOOLEAN LocalBlocked            : 1;    // The path id is blocked by local restriction.
        BOOLEAN PeerBlocked             : 1;    // The path id is blocked by peer restriction.
    };
} QUIC_PATHID_FLAGS;

//
// Different references on a PathID.
//
typedef enum QUIC_PATHID_REF {

    QUIC_PATHID_REF_PATHID_SET,
    QUIC_PATHID_REF_PATH,
    QUIC_PATHID_REF_SEND,
    QUIC_PATHID_REF_SEND_PACKET,
    QUIC_PATHID_REF_LOOKUP,
    QUIC_PATHID_REF_OPERATION,

    QUIC_PATHID_REF_COUNT

} QUIC_PATHID_REF;

//
// Per PathID statistics.
//
typedef struct QUIC_PATHID_STATS {
    struct {
        uint64_t TotalPackets;          // QUIC packets; could be coalesced into fewer UDP datagrams.
        uint64_t RetransmittablePackets;
        uint64_t SuspectedLostPackets;
        uint64_t SpuriousLostPackets;   // Actual lost is (SuspectedLostPackets - SpuriousLostPackets)

        uint64_t TotalBytes;            // Sum of UDP payloads
        uint64_t TotalStreamBytes;      // Sum of stream payloads

        uint32_t CongestionCount;
        uint32_t EcnCongestionCount;
        uint32_t PersistentCongestionCount;
    } Send;

    struct {
        uint64_t TotalPackets;          // QUIC packets; could be coalesced into fewer UDP datagrams.
        uint64_t ReorderedPackets;      // Packets where packet number is less than highest seen.
        uint64_t DuplicatePackets;
        uint64_t DecryptionFailures;    // Count of packets that failed to decrypt.
        uint64_t ValidPackets;          // Count of packets that successfully decrypted or had no encryption.
        uint64_t ValidAckFrames;        // Count of receive ACK frames.

        uint64_t TotalBytes;            // Sum of UDP payloads
        uint64_t TotalStreamBytes;      // Sum of stream payloads
    } Recv;
} QUIC_PATHID_STATS;

//
// This structure represents all the per path id specific data.
//
typedef struct QUIC_PATHID {

    QUIC_CONNECTION* Connection;

    QUIC_PATH* Path;

    //
    // Unique identifier;
    //
    uint32_t ID;

    //
    // The current flags for this path id.
    //
    QUIC_PATHID_FLAGS Flags;

    //
    // The entry in the connection's hashtable of path ids.
    //
    CXPLAT_HASHTABLE_ENTRY TableEntry;

    //
    // The list of connection IDs used for receiving.
    //
    CXPLAT_SLIST_ENTRY SourceCids;

    //
    // The list of connection IDs used for sending. Given to us by the peer.
    //
    CXPLAT_LIST_ENTRY DestCids;

    //
    // Number of non-retired desintation CIDs we currently have cached.
    //
    uint8_t DestCidCount;

    //
    // Number of retired desintation CIDs we currently have cached.
    //
    uint8_t RetiredDestCidCount;

    //
    // The maximum number of source CIDs to give the peer. This is a minimum of
    // what we're willing to support and what the peer is willing to accept.
    //
    uint8_t SourceCidLimit;

    //
    // The sequence number to use for the next source CID.
    //
    QUIC_VAR_INT NextSourceCidSequenceNumber;

    //
    // The most recent Retire Prior To field received in a NEW_CONNECTION_ID
    // frame.
    //
    QUIC_VAR_INT RetirePriorTo;

    uint64_t CloseTime;

    //
    // Per-encryption level packet space information.
    //
    QUIC_PACKET_SPACE* Packets[QUIC_ENCRYPT_LEVEL_COUNT];

    //
    // Manages all the information for outstanding sent packets.
    //
    QUIC_LOSS_DETECTION LossDetection;

    //
    // Congestion control state.
    //
    QUIC_CONGESTION_CONTROL CongestionControl;

    //
    // The next packet number to use.
    //
    uint64_t NextPacketNumber;

    //
    // Statistics
    //
    QUIC_PATHID_STATS Stats;

    //
    // Number of references to the handle.
    //
    CXPLAT_REF_COUNT RefCount;

#if DEBUG
    short RefTypeCount[QUIC_PATHID_REF_COUNT];
#endif

    uint64_t StatusSendSeq;

    uint64_t StatusRecvSeq;

    //
    // Set of current reasons sending more packets is currently blocked.
    //
    uint8_t OutFlowBlockedReasons; // Set of QUIC_FLOW_BLOCKED_* flags

    //
    // PathID blocked timings.
    //
    struct {
        QUIC_FLOW_BLOCKED_TIMING_TRACKER Pacing;
        QUIC_FLOW_BLOCKED_TIMING_TRACKER AmplificationProt;
        QUIC_FLOW_BLOCKED_TIMING_TRACKER CongestionControl;
    } BlockedTimings;

} QUIC_PATHID;

//
// Allocates and partially initializes a new path id object.
//
_IRQL_requires_max_(DISPATCH_LEVEL)
QUIC_STATUS
QuicPathIDInitialize(
    _In_ QUIC_CONNECTION* Connection,
    _Outptr_ _At_(*NewPathID, __drv_allocatesMem(Mem))
        QUIC_PATHID** NewPathID
    );

//
// Free the path id object.
//
_IRQL_requires_max_(DISPATCH_LEVEL)
void
QuicPathIDFree(
    _In_ __drv_freesMem(Mem) QUIC_PATHID* PathID
    );

_IRQL_requires_max_(PASSIVE_LEVEL)
void
QuicPathIDAddDestCID(
    _Inout_ QUIC_PATHID* PathID,
    _In_ QUIC_CID_LIST_ENTRY *DestCid
    );

_IRQL_requires_max_(PASSIVE_LEVEL)
void
QuicPathIDAddSourceCID(
    _Inout_ QUIC_PATHID* PathID,
    _In_ QUIC_CID_SLIST_ENTRY *SourceCid,
    _In_ BOOLEAN IsInitial
    );

_IRQL_requires_max_(PASSIVE_LEVEL)
void
QuicPathIDFreeSourceCids(
    _Inout_ QUIC_PATHID* PathID
    );

_IRQL_requires_max_(PASSIVE_LEVEL)
void
QuicPathIDProcessPathCloseTimerOperation(
    _Inout_ QUIC_PATHID* PathID
    );

//
// Tracing rundown for the pathid.
//
_IRQL_requires_max_(PASSIVE_LEVEL)
void
QuicPathIDTraceRundown(
    _In_ QUIC_PATHID* PathID
    );

//
// Generates a new source connection ID.
//
_IRQL_requires_max_(PASSIVE_LEVEL)
QUIC_CID_SLIST_ENTRY*
QuicPathIDGenerateNewSourceCid(
    _In_ QUIC_PATHID* PathID,
    _In_ BOOLEAN IsInitial
    );

//
// Generates any necessary source CIDs.
//
_IRQL_requires_max_(PASSIVE_LEVEL)
void
QuicPathIDGenerateNewSourceCids(
    _In_ QUIC_PATHID* PathID,
    _In_ BOOLEAN ReplaceExistingCids
    );

//
// Look up a source CID by sequence number.
//
_IRQL_requires_max_(DISPATCH_LEVEL)
_Success_(return != NULL)
QUIC_INLINE
QUIC_CID_SLIST_ENTRY*
QuicPathIDGetSourceCidFromSeq(
    _In_ QUIC_PATHID* PathID,
    _In_ QUIC_VAR_INT SequenceNumber,
    _In_ BOOLEAN RemoveFromList,
    _Out_ BOOLEAN* IsLastCid
    )
{
    for (CXPLAT_SLIST_ENTRY** Entry = &PathID->SourceCids.Next;
            *Entry != NULL;
            Entry = &(*Entry)->Next) {
        QUIC_CID_SLIST_ENTRY* SourceCid =
            CXPLAT_CONTAINING_RECORD(
                *Entry,
                QUIC_CID_SLIST_ENTRY,
                Link);
        if (SourceCid->CID.SequenceNumber == SequenceNumber) {
            if (RemoveFromList) {
                while (SourceCid->HashEntries.Next != NULL) {
                    QUIC_CID_HASH_ENTRY* CID =
                        CXPLAT_CONTAINING_RECORD(
                            CxPlatListPopEntry(&SourceCid->HashEntries),
                            QUIC_CID_HASH_ENTRY,
                            Link);
                    QuicBindingRemoveSourceConnectionID(
                        CID->Binding,
                        CID);
                }
                QuicTraceEvent(
                    ConnSourceCidRemoved,
                    "[conn][%p][pathid][%u] (SeqNum=%llu) Removed Source CID: %!CID!",
                    PathID->Connection,
                    PathID->ID,
                    SourceCid->CID.SequenceNumber,
                    CASTED_CLOG_BYTEARRAY(SourceCid->CID.Length, SourceCid->CID.Data));
                *Entry = (*Entry)->Next;
            }
            *IsLastCid = PathID->SourceCids.Next == NULL;
            return SourceCid;
        }
    }
    return NULL;
}

//
// Look up a source CID by data buffer.
//
_IRQL_requires_max_(DISPATCH_LEVEL)
QUIC_INLINE
QUIC_CID_SLIST_ENTRY*
QuicPathIDGetSourceCidFromBuf(
    _In_ QUIC_PATHID* PathID,
    _In_ uint8_t CidLength,
    _In_reads_(CidLength)
        const uint8_t* CidBuffer
    )
{
    for (CXPLAT_SLIST_ENTRY* Entry = PathID->SourceCids.Next;
            Entry != NULL;
            Entry = Entry->Next) {
        QUIC_CID_SLIST_ENTRY* SourceCid =
            CXPLAT_CONTAINING_RECORD(
                Entry,
                QUIC_CID_SLIST_ENTRY,
                Link);
        if (CidLength == SourceCid->CID.Length &&
            memcmp(CidBuffer, SourceCid->CID.Data, CidLength) == 0) {
            return SourceCid;
        }
    }
    return NULL;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
QUIC_CID_LIST_ENTRY*
QuicPathIDGetUnusedDestCid(
    _In_ const QUIC_PATHID* PathID
    );

_IRQL_requires_max_(PASSIVE_LEVEL)
void
QuicPathIDRetireCid(
    _In_ QUIC_PATHID* PathID,
    _In_ QUIC_CID_LIST_ENTRY* DestCid
    );

//
// Retires the currently used destination connection ID.
//
_IRQL_requires_max_(PASSIVE_LEVEL)
BOOLEAN
QuicPathIDRetireCurrentDestCid(
    _In_ QUIC_PATHID* PathID,
    _In_ QUIC_PATH* Path
    );

_IRQL_requires_max_(PASSIVE_LEVEL)
BOOLEAN
QuicPathIDOnRetirePriorToUpdated(
    _In_ QUIC_PATHID* PathID
    );

_IRQL_requires_max_(PASSIVE_LEVEL)
BOOLEAN
QuicPathIDReplaceRetiredCids(
    _In_ QUIC_PATHID* PathID
    );

//
// Updates the current destination CID to the received packet's source CID, if
// not already equal. Only used during the handshake, on the client side.
//
_IRQL_requires_max_(PASSIVE_LEVEL)
BOOLEAN
QuicPathIDUpdateDestCid(
    _In_ QUIC_PATHID* PathID,
    _In_ const QUIC_RX_PACKET* const Packet
    );

//
// Look up a source CID by sequence number.
//
_IRQL_requires_max_(DISPATCH_LEVEL)
QUIC_INLINE
QUIC_CID_LIST_ENTRY*
QuicPathIDGetDestCidFromSeq(
    _In_ QUIC_PATHID* PathID,
    _In_ QUIC_VAR_INT SequenceNumber,
    _In_ BOOLEAN RemoveFromList
    )
{
    for (CXPLAT_LIST_ENTRY* Entry = PathID->DestCids.Flink;
            Entry != &PathID->DestCids;
            Entry = Entry->Flink) {
        QUIC_CID_LIST_ENTRY* DestCid =
            CXPLAT_CONTAINING_RECORD(
                Entry,
                QUIC_CID_LIST_ENTRY,
                Link);
        if (DestCid->CID.SequenceNumber == SequenceNumber) {
            if (RemoveFromList) {
                CxPlatListEntryRemove(Entry);
            }
            return DestCid;
        }
    }
    return NULL;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
BOOLEAN
QuicPathIDAssignCids(
    _In_ QUIC_PATHID* PathID
    );

_IRQL_requires_max_(DISPATCH_LEVEL)
BOOLEAN
QuicPathIDWriteAckFrame(
    _In_ QUIC_PATHID* PathID,
    _Inout_ QUIC_PACKET_BUILDER* Builder
    );

_IRQL_requires_max_(DISPATCH_LEVEL)
BOOLEAN
QuicPathIDWriteNewConnectionIDFrame(
    _In_ QUIC_PATHID* PathID,
    _Inout_ QUIC_PACKET_BUILDER* Builder,
    _In_ uint16_t AvailableBufferLength,
    _Inout_ BOOLEAN* HasMoreCidsToSend,
    _Inout_ BOOLEAN* MaxFrameLimitHit
    );

_IRQL_requires_max_(DISPATCH_LEVEL)
BOOLEAN
QuicPathIDWriteRetireConnectionIDFrame(
    _In_ QUIC_PATHID* PathID,
    _Inout_ QUIC_PACKET_BUILDER* Builder,
    _In_ uint16_t AvailableBufferLength,
    _Inout_ BOOLEAN* HasMoreCidsToSend,
    _Inout_ BOOLEAN* MaxFrameLimitHit
    );

//
// Adds a ref to a PathID.
//
_IRQL_requires_max_(DISPATCH_LEVEL)
QUIC_INLINE
void
QuicPathIDAddRef(
    _In_ QUIC_PATHID* PathID,
    _In_ QUIC_PATHID_REF Ref
    )
{
    CXPLAT_DBG_ASSERT(PathID->Connection);
    CXPLAT_DBG_ASSERT(PathID->RefCount > 0);

#if DEBUG
    InterlockedIncrement16((volatile short*)&PathID->RefTypeCount[Ref]);
#else
    UNREFERENCED_PARAMETER(Ref);
#endif

    CxPlatRefIncrement(&PathID->RefCount);
}

//
// Releases a ref on a PathID.
//
#pragma warning(push)
#pragma warning(disable:6014) // SAL doesn't understand ref counts
_IRQL_requires_max_(DISPATCH_LEVEL)
QUIC_INLINE
BOOLEAN
QuicPathIDRelease(
    _In_ __drv_freesMem(Mem) QUIC_PATHID* PathID,
    _In_ QUIC_PATHID_REF Ref
    )
{
    CXPLAT_DBG_ASSERT(PathID->Connection);
    CXPLAT_TEL_ASSERT(PathID->RefCount > 0);

#if DEBUG
    CXPLAT_TEL_ASSERT(PathID->RefTypeCount[Ref] > 0);
    uint16_t result = (uint16_t)InterlockedDecrement16((volatile short*)&PathID->RefTypeCount[Ref]);
    CXPLAT_TEL_ASSERT(result != 0xFFFF);
#else
    UNREFERENCED_PARAMETER(Ref);
#endif

    if (CxPlatRefDecrement(&PathID->RefCount)) {
#if DEBUG
        for (uint32_t i = 0; i < QUIC_PATHID_REF_COUNT; i++) {
            CXPLAT_TEL_ASSERT(PathID->RefTypeCount[i] == 0);
        }
#endif
        QuicPathIDFree(PathID);
        return TRUE;
    }
    return FALSE;
}
#pragma warning(pop)

//
// Helper to get the QUIC_PATHID for a loss detection.
//
QUIC_INLINE
_Ret_notnull_
QUIC_PATHID*
QuicLossDetectionGetPathID(
    _In_ QUIC_LOSS_DETECTION* LossDetection
    )
{
    return CXPLAT_CONTAINING_RECORD(LossDetection, QUIC_PATHID, LossDetection);
}

//
// Helper to get the owning QUIC_PATHID for the congestion control module.
//
QUIC_INLINE
_Ret_notnull_
QUIC_PATHID*
QuicCongestionControlGetPathID(
    _In_ const QUIC_CONGESTION_CONTROL* Cc
    )
{
    return CXPLAT_CONTAINING_RECORD(Cc, QUIC_PATHID, CongestionControl);
}

QUIC_INLINE
void
QuicPathIDLogOutFlowStats(
    _In_ const QUIC_PATHID* const PathID
    )
{
    if (!QuicTraceEventEnabled(ConnOutFlowStats)) {
        return;
    }

    QuicCongestionControlLogOutFlowStatus(&PathID->CongestionControl);
}

QUIC_INLINE
void
QuicPathIDLogInFlowStats(
    _In_ const QUIC_PATHID* const PathID
    )
{
    UNREFERENCED_PARAMETER(PathID);
    QuicTraceEvent(
        PathInFlowStats,
        "[conn][%p][pathid][%u] IN: BytesRecv=%llu",
        PathID->Connection,
        PathID->ID,
        PathID->Stats.Recv.TotalBytes);
}

QUIC_INLINE
void
QuicPathIDLogStatistics(
    _In_ const QUIC_PATHID* const PathID
    )
{
    UNREFERENCED_PARAMETER(PathID);

    QuicTraceEvent(
        PathStatsV3,
        "[conn][%p][pathid][%u] STATS: SRtt=%llu CongestionCount=%u PersistentCongestionCount=%u SendTotalBytes=%llu RecvTotalBytes=%llu CongestionWindow=%u Cc=%s EcnCongestionCount=%u",
        PathID->Connection,
        PathID->ID,
        PathID->Path->SmoothedRtt,
        PathID->Stats.Send.CongestionCount,
        PathID->Stats.Send.PersistentCongestionCount,
        PathID->Stats.Send.TotalBytes,
        PathID->Stats.Recv.TotalBytes,
        QuicCongestionControlGetCongestionWindow(&PathID->CongestionControl),
        PathID->CongestionControl.Name,
        PathID->Stats.Send.EcnCongestionCount);

    QuicTraceEvent(
        PathPacketStats,
        "[conn][%p][pathid][%u] STATS: SendTotalPackets=%llu SendSuspectedLostPackets=%llu SendSpuriousLostPackets=%llu RecvTotalPackets=%llu RecvReorderedPackets=%llu RecvDuplicatePackets=%llu RecvDecryptionFailures=%llu",
        PathID->Connection,
        PathID->ID,
        PathID->Stats.Send.TotalPackets,
        PathID->Stats.Send.SuspectedLostPackets,
        PathID->Stats.Send.SpuriousLostPackets,
        PathID->Stats.Recv.TotalPackets,
        PathID->Stats.Recv.ReorderedPackets,
        PathID->Stats.Recv.DuplicatePackets,
        PathID->Stats.Recv.DecryptionFailures);
}

QUIC_INLINE
BOOLEAN
QuicPathIDAddOutFlowBlockedReason(
    _In_ QUIC_PATHID* PathID,
    _In_ QUIC_FLOW_BLOCK_REASON Reason
    )
{
    CXPLAT_DBG_ASSERTMSG(
        (Reason & (Reason - 1)) == 0,
        "More than one reason is not allowed");
    if (!(PathID->OutFlowBlockedReasons & Reason)) {
        uint64_t Now = CxPlatTimeUs64();
        if (Reason & QUIC_FLOW_BLOCKED_PACING) {
            PathID->BlockedTimings.Pacing.LastStartTimeUs = Now;
        }
        if (Reason & QUIC_FLOW_BLOCKED_AMPLIFICATION_PROT) {
            PathID->BlockedTimings.AmplificationProt.LastStartTimeUs = Now;
        }
        if (Reason & QUIC_FLOW_BLOCKED_CONGESTION_CONTROL) {
            PathID->BlockedTimings.CongestionControl.LastStartTimeUs = Now;
        }

        PathID->OutFlowBlockedReasons |= Reason;
        QuicTraceEvent(
            PathOutFlowBlocked,
            "[conn][%p][pathid][%hhu] Send Blocked Flags: %hhu",
            PathID->Connection,
            PathID->ID,
            PathID->OutFlowBlockedReasons);
        return TRUE;
    }
    return FALSE;
}

QUIC_INLINE
BOOLEAN
QuicPathIDRemoveOutFlowBlockedReason(
    _In_ QUIC_PATHID* PathID,
    _In_ QUIC_FLOW_BLOCK_REASON Reason
    )
{
    if ((PathID->OutFlowBlockedReasons & Reason)) {
        uint64_t Now = CxPlatTimeUs64();
        if ((PathID->OutFlowBlockedReasons & QUIC_FLOW_BLOCKED_PACING) &&
            (Reason & QUIC_FLOW_BLOCKED_PACING)) {
            PathID->BlockedTimings.Pacing.CumulativeTimeUs +=
                CxPlatTimeDiff64(PathID->BlockedTimings.Pacing.LastStartTimeUs, Now);
            PathID->BlockedTimings.Pacing.LastStartTimeUs = 0;
        }
        if ((PathID->OutFlowBlockedReasons & QUIC_FLOW_BLOCKED_AMPLIFICATION_PROT) &&
            (Reason & QUIC_FLOW_BLOCKED_AMPLIFICATION_PROT)) {
            PathID->BlockedTimings.AmplificationProt.CumulativeTimeUs +=
                CxPlatTimeDiff64(PathID->BlockedTimings.AmplificationProt.LastStartTimeUs, Now);
            PathID->BlockedTimings.AmplificationProt.LastStartTimeUs = 0;
        }
        if ((PathID->OutFlowBlockedReasons & QUIC_FLOW_BLOCKED_CONGESTION_CONTROL) &&
            (Reason & QUIC_FLOW_BLOCKED_CONGESTION_CONTROL)) {
            PathID->BlockedTimings.CongestionControl.CumulativeTimeUs +=
                CxPlatTimeDiff64(PathID->BlockedTimings.CongestionControl.LastStartTimeUs, Now);
            PathID->BlockedTimings.CongestionControl.LastStartTimeUs = 0;
        }

        PathID->OutFlowBlockedReasons &= ~Reason;
        QuicTraceEvent(
            PathOutFlowBlocked,
            "[conn][%p][pathid][%hhu] Send Blocked Flags: %hhu",
            PathID->Connection,
            PathID->ID,
            PathID->OutFlowBlockedReasons);
        return TRUE;
    }
    return FALSE;
}

