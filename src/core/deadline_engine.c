/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.

Abstract:
    Implements `DrainBeforeDeadlineEngine` which is used to check if the stream
    can be drained before the deadline. This check requires working with congestion
    control and has different behavior based on the congestion control algorithm used.

--*/

#include "precomp.h"

// Should match the enum in bbr.c
typedef enum BBR_STATE {

    BBR_STATE_STARTUP,

    BBR_STATE_DRAIN,

    BBR_STATE_PROBE_BW,

    BBR_STATE_PROBE_RTT

} BBR_STATE;

typedef enum TRILEAN {

    TRILEAN_TRUE,

    TRILEAN_FALSE,

    //
    // Indicates bad state, all operations on it result it TRILEAN_UNKNOWN
    // Fall back to default behavior.
    //
    TRILEAN_UNKNOWN

} TRILEAN;


TRILEAN DrainBeforeDeadlineEngineBBR(
    _In_ const QUIC_STREAM* Stream
    )
{
    QUIC_CONNECTION* Connection = Stream->Connection;
    QUIC_CONGESTION_CONTROL* Cc = &Connection->CongestionControl;
    QUIC_CONGESTION_CONTROL_BBR* Bbr = (QUIC_CONGESTION_CONTROL_BBR*)(&Cc->Bbr);

    if(Bbr->BbrState == BBR_STATE_STARTUP)
    {
        // In the startup state, we do not have a good estimate of the bandwidth,
        // so we assume that we can drain the stream.
        return TRILEAN_UNKNOWN;
    }

    return TRUE;
}

TRILEAN DrainBeforeDeadlineCcSpecificEngine(
    _In_ const QUIC_STREAM* Stream,
    _In_ QUIC_CONGESTION_CONTROL* Cc
    )
{
    if(strcmp(Cc->Name, "BBR") == 0) {
        // BBR congestion control algorithm.
        return DrainBeforeDeadlineEngineBBR(Stream);
    } else {
        // Unknown or unsupported congestion control algorithm.
        return TRUE;
    }
}

BOOLEAN DrainBeforeDeadlineEngine(
    _In_ const QUIC_STREAM* Stream
    )
{
    QUIC_TIME_POINT Now = CxPlatTimeUs64();
    if(Stream->Deadline < Now) {
        return FALSE;
    }

    QUIC_CONNECTION* Connection = Stream->Connection;
    QUIC_CONGESTION_CONTROL* Cc = &Connection->CongestionControl;

    // We do Congestion Control algorithm specific checks first
    TRILEAN CcSpecficResult = DrainBeforeDeadlineCcSpecificEngine(Stream, Cc);

    // TRILEAN_UNKNOWN && _ == TRILEAN_UNKNOWN (we use default value which is TRUE)
    if(CcSpecficResult == TRILEAN_UNKNOWN)
        // default behavior is true
        return TRUE;
    // TRILEAN_FALSE && _ == TRILEAN_FALSE
    else if (CcSpecficResult == TRILEAN_FALSE)
        return FALSE;

    QUIC_NETWORK_STATISTICS NetworkStatistics;
    CxPlatZeroMemory(&NetworkStatistics, sizeof(NetworkStatistics));
    Cc->QuicCongestionControlGetNetworkStatistics(Connection, Cc, &NetworkStatistics);

    if(NetworkStatistics.Bandwidth == 0)
    {
        // If we have no/invalid bandwidth estimate, we cannot determine if we can drain.
        // Assume it can drain for now.
        return TRUE;
    }

    uint32_t BytesInFlight = NetworkStatistics.BytesInFlight;
    uint64_t SmoothedRTT = NetworkStatistics.SmoothedRTT;
    uint64_t Bandwidth = NetworkStatistics.Bandwidth;

    QUIC_TIME_DIFF TransmissionDelayOfBytesInFlight = (BytesInFlight / Bandwidth) * 1000000; // Convert to microseconds
    uint64_t BytesToDrain = Stream->QueuedSendOffset - Stream->NextSendOffset;
    QUIC_TIME_DIFF TransmissionDelayOfBytesToDrain = (BytesToDrain / Bandwidth) * 1000000; // Convert to microseconds

    QUIC_TIME_DIFF TotalTransmissionDelay = TransmissionDelayOfBytesInFlight + TransmissionDelayOfBytesToDrain + (SmoothedRTT / 2);

    return TotalTransmissionDelay < Stream->Deadline - Now;
}
