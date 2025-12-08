/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.

--*/
#ifdef QUIC_CLOG
#include "path.h.clog.h"
#endif

//
// ECN validation state transition:
//
// ECN_VALIDATION_TESTING: when a new path is created AND ECN is enabled.
//
// ECN_VALIDATION_TESTING -> ECN_VALIDATION_UNKNOWN: after sending packets with ECT bit set for 3 PTOs.
//
// {ECN_VALIDATION_TESTING | ECN_VALIDATION_UNKNOWN} -> ECN_VALIDATION_CAPABLE:
// when ECN validation passes.
//
// {ANY} -> ECN_VALIDATION_FAILED: when ECN validation fails.
//
// In ECN_VALIDATION_TESTING or ECN_VALIDATION_CAPABLE state, packets sent are marked with ECT bit.
//
// This algorithm is a slightly simplified and relaxed version of the sample ECN validation in
// RFC9000 A.4. The main differences are:
//
// 1. Our algorithm can transition into capable state right from testing state if ECN validation passes.
//
// 2. The sample algorithm fails ECN validation when all packets sent in testing are considered lost.
// Our algorithm does not do that. However, in that case, our algorithm stays in unknown state, where
// we send packets without ECT mark, which is effectively the same as failing the validation.
//

//
// Different state of ECN validation for the network path.
//
typedef enum ECN_VALIDATION_STATE {
    ECN_VALIDATION_TESTING,
    ECN_VALIDATION_UNKNOWN,
    ECN_VALIDATION_CAPABLE,
    ECN_VALIDATION_FAILED, // or not enabled by the app.
} ECN_VALIDATION_STATE;

//
// Per path statistics.
//
typedef struct QUIC_PATH_STATS {
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
} QUIC_PATH_STATS;

//
// Represents all the per-path information of a connection.
//
typedef struct QUIC_PATH {

    //
    // Unique identifier;
    //
    uint8_t ID;

    //
    // Indicates the path object is actively in use.
    //
    BOOLEAN InUse : 1;

    //
    // Indicates this is the primary path being used by the connection.
    //
    BOOLEAN IsActive : 1;

    //
    // Indicates whether this connection initiated a CID change, and therefore
    // shouldn't respond to the peer's next CID change with one of its own.
    //
    BOOLEAN InitiatedCidUpdate : 1;

    //
    // Indicates that the first RTT sample has been taken. Until this is set,
    // the RTT estimate is set to a default value.
    //
    BOOLEAN GotFirstRttSample : 1;

    //
    // Indicates a valid (not dropped) packet has been received on this path.
    //
    BOOLEAN GotValidPacket : 1;

    //
    // Indicates the peer's source IP address has been validated.
    //
    BOOLEAN IsPeerValidated : 1;

    //
    // Indicates the minimum MTU has been validated.
    //
    BOOLEAN IsMinMtuValidated : 1;

    //
    // Current value to encode in the short header spin bit field.
    //
    BOOLEAN SpinBit : 1;

    //
    // The current path challenge needs to be sent out.
    //
    BOOLEAN SendChallenge : 1;

    //
    // The current path response needs to be sent out.
    //
    BOOLEAN SendResponse : 1;

    BOOLEAN SendStatus : 1;

    BOOLEAN LocalClose : 1;
    BOOLEAN LocalCloseAcked : 1;

    BOOLEAN SendAbandon : 1;

    BOOLEAN RemoteClose : 1;

    //
    // Indicates the partition has updated for this path.
    //
    uint8_t PartitionUpdated : 1;

    //
    // ECN validation state.
    //
    uint8_t EcnValidationState : 2;

    //
    // Indicates whether this connection offloads encryption workload to HW
    //
    BOOLEAN EncryptionOffloading : 1;

    //
    // The ending time of ECN validation testing state in microseconds.
    //
    uint64_t EcnTestingEndingTime;

    //
    // The currently calculated path MTU.
    //
    uint16_t Mtu;

    //
    // The local socket MTU.
    //
    uint16_t LocalMtu;

    //
    // MTU Discovery logic.
    //
    QUIC_MTU_DISCOVERY MtuDiscovery;

    QUIC_PATHID *PathID;
    
    //
    // The binding used for sending/receiving UDP packets.
    //
    QUIC_BINDING* Binding;

    //
    // The network route.
    //
    CXPLAT_ROUTE Route;

    //
    // The destination CID used for sending on this path.
    //
    QUIC_CID_LIST_ENTRY* DestCid;

    //
    // Congestion control state.
    //
    QUIC_CONGESTION_CONTROL CongestionControl;

    //
    // Statistics
    //
    QUIC_PATH_STATS Stats;

    //
    // RTT moving average, computed as in RFC6298. Units of microseconds.
    //
    uint64_t SmoothedRtt;
    uint64_t LatestRttSample;
    uint64_t MinRtt;
    uint64_t MaxRtt;
    uint64_t RttVariance;
    uint64_t OneWayDelay;
    uint64_t OneWayDelayLatest;

    //
    // Used on the server side until the client's IP address has been validated
    // to prevent the server from being used for amplification attacks. A value
    // of UINT32_MAX indicates this variable does not apply.
    //
    uint32_t Allowance;

    //
    // The last path challenge we received and needs to be sent back as in a
    // PATH_RESPONSE frame.
    //
    uint8_t Response[8];

    //
    // The current path challenge to send and wait for the peer to echo back.
    //
    uint8_t Challenge[8];

    //
    // Time when path validation was begun. Used for timing out path validation.
    //
    uint64_t PathValidationStartTime;

    //
    // Set of current reasons sending more packets is currently blocked.
    //
    uint8_t OutFlowBlockedReasons; // Set of QUIC_FLOW_BLOCKED_* flags

    //
    // Path blocked timings.
    //
    struct {
        QUIC_FLOW_BLOCKED_TIMING_TRACKER Pacing;
        QUIC_FLOW_BLOCKED_TIMING_TRACKER AmplificationProt;
        QUIC_FLOW_BLOCKED_TIMING_TRACKER CongestionControl;
    } BlockedTimings;

} QUIC_PATH;

#if DEBUG
#define QuicPathValidate(Path) \
    CXPLAT_DBG_ASSERT( \
        (Path)->DestCid == NULL || \
        (Path)->DestCid->CID.Length == 0 || \
        ((Path)->DestCid->AssignedPath == (Path) && \
         (Path)->DestCid->CID.UsedLocally))
#else
#define QuicPathValidate(Path) UNREFERENCED_PARAMETER(Path)
#endif

CXPLAT_STATIC_ASSERT(
    sizeof(QUIC_PATH) < 1024,
    "Ensure path struct stays small since we prealloc them");

_IRQL_requires_max_(PASSIVE_LEVEL)
void
QuicPathInitialize(
    _In_ QUIC_CONNECTION* Connection,
    _In_ QUIC_PATH* Path
    );

_IRQL_requires_max_(PASSIVE_LEVEL)
void
QuicPathRemove(
    _In_ QUIC_CONNECTION* Connection,
    _In_ uint8_t Index
    );

_IRQL_requires_max_(PASSIVE_LEVEL)
void
QuicPathSetAllowance(
    _In_ QUIC_CONNECTION* Connection,
    _In_ QUIC_PATH* Path,
    _In_ uint32_t NewAllowance
    );

_IRQL_requires_max_(PASSIVE_LEVEL)
QUIC_INLINE
void
QuicPathIncrementAllowance(
    _In_ QUIC_CONNECTION* Connection,
    _In_ QUIC_PATH* Path,
    _In_ uint32_t Amount
    )
{
    QuicPathSetAllowance(Connection, Path, Path->Allowance + Amount);
}

_IRQL_requires_max_(PASSIVE_LEVEL)
QUIC_INLINE
void
QuicPathDecrementAllowance(
    _In_ QUIC_CONNECTION* Connection,
    _In_ QUIC_PATH* Path,
    _In_ uint32_t Amount
    )
{
    QuicPathSetAllowance(
        Connection,
        Path,
        Path->Allowance <= Amount ? 0 : (Path->Allowance - Amount));
}

//
// Calculates the maximum size datagram payload from the path's MTU.
//
QUIC_INLINE
uint16_t
QuicPathGetDatagramPayloadSize(
    _In_ const QUIC_PATH* Path
    )
{
    return
        MaxUdpPayloadSizeForFamily(
            QuicAddrGetFamily(&Path->Route.RemoteAddress), Path->Mtu);
}

typedef enum QUIC_PATH_VALID_REASON {
    QUIC_PATH_VALID_INITIAL_TOKEN,
    QUIC_PATH_VALID_HANDSHAKE_PACKET,
    QUIC_PATH_VALID_PATH_RESPONSE
} QUIC_PATH_VALID_REASON;

_IRQL_requires_max_(PASSIVE_LEVEL)
void
QuicPathSetValid(
    _In_ QUIC_CONNECTION* Connection,
    _In_ QUIC_PATH* Path,
    _In_ QUIC_PATH_VALID_REASON Reason
    );

_IRQL_requires_max_(PASSIVE_LEVEL)
void
QuicPathSetActive(
    _In_ QUIC_CONNECTION* Connection,
    _In_ QUIC_PATH* Path
    );

_IRQL_requires_max_(PASSIVE_LEVEL)
_Ret_maybenull_
_Success_(return != NULL)
QUIC_PATH*
QuicConnGetPathByID(
    _In_ QUIC_CONNECTION* Connection,
    _In_ uint8_t ID,
    _Out_ uint8_t* Index
    );

_IRQL_requires_max_(PASSIVE_LEVEL)
_Ret_maybenull_
QUIC_PATH*
QuicConnGetPathByAddress(
    _In_ QUIC_CONNECTION* Connection,
    _In_ const QUIC_ADDR* LocalAddress,
    _In_ const QUIC_ADDR* RemoteAddress
    );

_IRQL_requires_max_(PASSIVE_LEVEL)
_Ret_maybenull_
QUIC_PATH*
QuicConnGetPathForPacket(
    _In_ QUIC_CONNECTION* Connection,
    _In_ const QUIC_RX_PACKET* Packet
    );

_IRQL_requires_max_(PASSIVE_LEVEL)
_Ret_notnull_
QUIC_PATH*
QuicConnChoosePath(
    _In_ QUIC_CONNECTION* Connection
    );

_IRQL_requires_max_(PASSIVE_LEVEL)
void
QuicCopyRouteInfo(
    _Inout_ CXPLAT_ROUTE* DstRoute,
    _In_ CXPLAT_ROUTE* SrcRoute
    );

//
// Plumbs new or removes existing QUIC encryption offload information.
//
_IRQL_requires_max_(PASSIVE_LEVEL)
void
QuicPathUpdateQeo(
    _In_ QUIC_CONNECTION* Connection,
    _In_ QUIC_PATH* Path,
    _In_ CXPLAT_QEO_OPERATION Operation
    );

//
// Helper to get the owning QUIC_CONNECTION for the congestion control module.
//
QUIC_INLINE
_Ret_notnull_
QUIC_PATH*
QuicCongestionControlGetPath(
    _In_ const QUIC_CONGESTION_CONTROL* Cc
    )
{
    return CXPLAT_CONTAINING_RECORD(Cc, QUIC_PATH, CongestionControl);
}

QUIC_INLINE
void
QuicPathLogOutFlowStats(
    _In_ const QUIC_PATH* const Path
    )
{
    if (!QuicTraceEventEnabled(ConnOutFlowStats)) {
        return;
    }

    QuicCongestionControlLogOutFlowStatus(&Path->CongestionControl);
}

QUIC_INLINE
void
QuicPathLogInFlowStats(
    _In_ const QUIC_PATH* const Path
    )
{
    UNREFERENCED_PARAMETER(Path);
    QuicTraceEvent(
        PathInFlowStats,
        "[conn][%p][pathid][%u] IN: BytesRecv=%llu",
        Path->PathID->Connection,
        Path->PathID->ID,
        Path->Stats.Recv.TotalBytes);
}

QUIC_INLINE
void
QuicPathLogStatistics(
    _In_ const QUIC_PATH* const Path
    )
{
    UNREFERENCED_PARAMETER(Path);

    QuicTraceEvent(
        PathStatsV3,
        "[conn][%p][pathid][%u] STATS: SRtt=%llu CongestionCount=%u PersistentCongestionCount=%u SendTotalBytes=%llu RecvTotalBytes=%llu CongestionWindow=%u Cc=%s EcnCongestionCount=%u",
        Path->PathID->Connection,
        Path->PathID->ID,
        Path->SmoothedRtt,
        Path->Stats.Send.CongestionCount,
        Path->Stats.Send.PersistentCongestionCount,
        Path->Stats.Send.TotalBytes,
        Path->Stats.Recv.TotalBytes,
        QuicCongestionControlGetCongestionWindow(&Path->CongestionControl),
        Path->CongestionControl.Name,
        Path->Stats.Send.EcnCongestionCount);

    QuicTraceEvent(
        PathPacketStats,
        "[conn][%p][pathid][%u] STATS: SendTotalPackets=%llu SendSuspectedLostPackets=%llu SendSpuriousLostPackets=%llu RecvTotalPackets=%llu RecvReorderedPackets=%llu RecvDuplicatePackets=%llu RecvDecryptionFailures=%llu",
        Path->PathID->Connection,
        Path->PathID->ID,
        Path->Stats.Send.TotalPackets,
        Path->Stats.Send.SuspectedLostPackets,
        Path->Stats.Send.SpuriousLostPackets,
        Path->Stats.Recv.TotalPackets,
        Path->Stats.Recv.ReorderedPackets,
        Path->Stats.Recv.DuplicatePackets,
        Path->Stats.Recv.DecryptionFailures);
}

QUIC_INLINE
BOOLEAN
QuicPathAddOutFlowBlockedReason(
    _In_ QUIC_PATH* Path,
    _In_ QUIC_FLOW_BLOCK_REASON Reason
    )
{
    CXPLAT_DBG_ASSERTMSG(
        (Reason & (Reason - 1)) == 0,
        "More than one reason is not allowed");
    if (!(Path->OutFlowBlockedReasons & Reason)) {
        uint64_t Now = CxPlatTimeUs64();
        if (Reason & QUIC_FLOW_BLOCKED_PACING) {
            Path->BlockedTimings.Pacing.LastStartTimeUs = Now;
        }
        if (Reason & QUIC_FLOW_BLOCKED_AMPLIFICATION_PROT) {
            Path->BlockedTimings.AmplificationProt.LastStartTimeUs = Now;
        }
        if (Reason & QUIC_FLOW_BLOCKED_CONGESTION_CONTROL) {
            Path->BlockedTimings.CongestionControl.LastStartTimeUs = Now;
        }

        Path->OutFlowBlockedReasons |= Reason;
        QuicTraceEvent(
            PathOutFlowBlocked,
            "[conn][%p][pathid][%hhu] Send Blocked Flags: %hhu",
            Path->PathID->Connection,
            Path->PathID->ID,
            Path->OutFlowBlockedReasons);
        return TRUE;
    }
    return FALSE;
}

QUIC_INLINE
BOOLEAN
QuicPathRemoveOutFlowBlockedReason(
    _In_ QUIC_PATH* Path,
    _In_ QUIC_FLOW_BLOCK_REASON Reason
    )
{
    if ((Path->OutFlowBlockedReasons & Reason)) {
        uint64_t Now = CxPlatTimeUs64();
        if ((Path->OutFlowBlockedReasons & QUIC_FLOW_BLOCKED_PACING) &&
            (Reason & QUIC_FLOW_BLOCKED_PACING)) {
            Path->BlockedTimings.Pacing.CumulativeTimeUs +=
                CxPlatTimeDiff64(Path->BlockedTimings.Pacing.LastStartTimeUs, Now);
            Path->BlockedTimings.Pacing.LastStartTimeUs = 0;
        }
        if ((Path->OutFlowBlockedReasons & QUIC_FLOW_BLOCKED_AMPLIFICATION_PROT) &&
            (Reason & QUIC_FLOW_BLOCKED_AMPLIFICATION_PROT)) {
            Path->BlockedTimings.AmplificationProt.CumulativeTimeUs +=
                CxPlatTimeDiff64(Path->BlockedTimings.AmplificationProt.LastStartTimeUs, Now);
            Path->BlockedTimings.AmplificationProt.LastStartTimeUs = 0;
        }
        if ((Path->OutFlowBlockedReasons & QUIC_FLOW_BLOCKED_CONGESTION_CONTROL) &&
            (Reason & QUIC_FLOW_BLOCKED_CONGESTION_CONTROL)) {
            Path->BlockedTimings.CongestionControl.CumulativeTimeUs +=
                CxPlatTimeDiff64(Path->BlockedTimings.CongestionControl.LastStartTimeUs, Now);
            Path->BlockedTimings.CongestionControl.LastStartTimeUs = 0;
        }

        Path->OutFlowBlockedReasons &= ~Reason;
        QuicTraceEvent(
            PathOutFlowBlocked,
            "[conn][%p][pathid][%hhu] Send Blocked Flags: %hhu",
            Path->PathID->Connection,
            Path->PathID->ID,
            Path->OutFlowBlockedReasons);
        return TRUE;
    }
    return FALSE;
}
