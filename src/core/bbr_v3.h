/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.

--*/

#pragma once

#include "bbr_common.h"

#if defined(__cplusplus)
extern "C" {
#endif

typedef enum BBR_V3_PHASE {
    BBR_V3_PHASE_DOWN,
    BBR_V3_PHASE_CRUISE,
    BBR_V3_PHASE_REFILL,
    BBR_V3_PHASE_UP
} BBR_V3_PHASE;

typedef struct BBR_V3_MODEL {
    uint64_t BandwidthLow;
    uint64_t BandwidthLatest;
    uint64_t TotalBytesLost;
    uint64_t CycleCount;
    uint64_t ProbeRound;
    uint64_t ProbeWait;
    uint64_t ProbeEndPacketNumber;
    uint64_t ProbeStartPacketNumber;
    uint64_t ProbeUpAcked;
    uint64_t ProbeRttMin;
    uint64_t ProbeRttMinTimestamp;
    uint64_t LastLostPacketNumber;
    uint64_t MinValidPacketNumber;
    uint32_t InflightHigh;
    uint32_t InflightLow;
    uint32_t InflightLatest;
    uint32_t ProbeUpCount;
    uint32_t StartupLossEvents;
    uint32_t PriorCongestionWindow;
    uint32_t UndoInflightHigh;
    uint32_t UndoInflightLow;
    uint64_t UndoBandwidthLow;
    uint32_t UndoState;
    BBR_V3_PHASE UndoPhase;
    BBR_V3_PHASE Phase;
    BOOLEAN LossInRound;
    BOOLEAN ExcessiveLossInRound;
    BOOLEAN AwaitingProbeFeedback;
    BOOLEAN ProbeSamples;
    BOOLEAN UndoValid;
    BOOLEAN UndoBtlbwFound;
} BBR_V3_MODEL;

typedef struct QUIC_CONGESTION_CONTROL_BBR_V3 {

    BBR_COMMON Common;

    BBR_V3_MODEL Model;

} QUIC_CONGESTION_CONTROL_BBR_V3;

_IRQL_requires_max_(DISPATCH_LEVEL)
void
BbrV3CongestionControlInitialize(
    _In_ QUIC_CONGESTION_CONTROL* Cc,
    _In_ const QUIC_SETTINGS_INTERNAL* Settings
    );

_IRQL_requires_max_(DISPATCH_LEVEL)
void
BbrV3CongestionControlOnPacketSent(
    _In_ const QUIC_CONGESTION_CONTROL* Cc,
    _Inout_ QUIC_SENT_PACKET_METADATA* Packet
    );

#if defined(__cplusplus)
}
#endif
