/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.

Abstract:

    Algorithm for using (but not exceeding) available network bandwidth.

    The send rate is limited to the available bandwidth by
    limiting the number of bytes in flight to CongestionWindow.

--*/

#include "precomp.h"
#ifdef QUIC_CLOG
#include "congestion_control.c.clog.h"
#endif

_IRQL_requires_max_(DISPATCH_LEVEL)
void
QuicCongestionControlInitialize(
    _In_ QUIC_CONGESTION_CONTROL* Cc,
    _In_ const QUIC_SETTINGS* Settings
    )
{
    CXPLAT_DBG_ASSERT(Settings->CongestionControlAlgorithm < QUIC_CONGESTION_CONTROL_ALGORITHM_MAX);

    switch (Settings->CongestionControlAlgorithm) {
        case QUIC_CONGESTION_CONTROL_ALGORITHM_CUBIC: {
            CubicCongestionControlInitialize(Cc, Settings);
            break;
        }
        default: {
            QUIC_CONNECTION* Connection = QuicCongestionControlGetConnection(Cc);
            QuicTraceLogConnWarning(
                InvalidCongestionControlAlgorithm,
                Connection,
                "Unknown congestion control algorithm: %d, fallback to Cubic",
                Settings->CongestionControlAlgorithm);
            CubicCongestionControlInitialize(Cc, Settings);
            break;
        }
    }
}

_IRQL_requires_max_(DISPATCH_LEVEL)
void
QuicCongestionControlReset(
    _In_ QUIC_CONGESTION_CONTROL* Cc
    )
{
    Cc->QuicCongestionControlReset(Cc);
}

_IRQL_requires_max_(DISPATCH_LEVEL)
uint32_t
QuicCongestionControlGetSendAllowance(
    _In_ QUIC_CONGESTION_CONTROL* Cc,
    _In_ uint64_t TimeSinceLastSend, // microsec
    _In_ BOOLEAN TimeSinceLastSendValid
    )
{
    return Cc->QuicCongestionControlGetSendAllowance(Cc, TimeSinceLastSend, TimeSinceLastSendValid);
}

_IRQL_requires_max_(PASSIVE_LEVEL)
void
QuicCongestionControlOnDataSent(
    _In_ QUIC_CONGESTION_CONTROL* Cc,
    _In_ uint32_t NumRetransmittableBytes
    )
{
    Cc->QuicCongestionControlOnDataSent(Cc, NumRetransmittableBytes);
}

_IRQL_requires_max_(DISPATCH_LEVEL)
BOOLEAN
QuicCongestionControlOnDataInvalidated(
    _In_ QUIC_CONGESTION_CONTROL* Cc,
    _In_ uint32_t NumRetransmittableBytes
    )
{
    return Cc->QuicCongestionControlOnDataInvalidated(Cc, NumRetransmittableBytes);
}

_IRQL_requires_max_(DISPATCH_LEVEL)
BOOLEAN
QuicCongestionControlOnDataAcknowledged(
    _In_ QUIC_CONGESTION_CONTROL* Cc,
    _In_ uint64_t TimeNow, // microsecond
    _In_ uint64_t LargestPacketNumberAcked,
    _In_ uint32_t NumRetransmittableBytes,
    _In_ uint32_t SmoothedRtt
    )
{
    return Cc->QuicCongestionControlOnDataAcknowledged(
        Cc, TimeNow, LargestPacketNumberAcked, NumRetransmittableBytes, SmoothedRtt);
}

_IRQL_requires_max_(DISPATCH_LEVEL)
void
QuicCongestionControlOnDataLost(
    _In_ QUIC_CONGESTION_CONTROL* Cc,
    _In_ uint64_t LargestPacketNumberLost,
    _In_ uint64_t LargestPacketNumberSent,
    _In_ uint32_t NumRetransmittableBytes,
    _In_ BOOLEAN PersistentCongestion
    )
{
    Cc->QuicCongestionControlOnDataLost(
        Cc, LargestPacketNumberLost, LargestPacketNumberSent, NumRetransmittableBytes, PersistentCongestion);
}

_IRQL_requires_max_(DISPATCH_LEVEL)
void
QuicCongestionControlOnSpuriousCongestionEvent(
    _In_ QUIC_CONGESTION_CONTROL* Cc
    )
{
    Cc->QuicCongestionControlOnSpuriousCongestionEvent(Cc);
}

_IRQL_requires_max_(DISPATCH_LEVEL)
uint8_t
QuicCongestionControlGetExemptions(
    _In_ const QUIC_CONGESTION_CONTROL* Cc
    )
{
    return Cc->QuicCongestionControlGetExemptions(Cc);
}
