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
    _In_ const QUIC_SETTINGS_INTERNAL* Settings
    )
{
    CXPLAT_DBG_ASSERT(Settings->CongestionControlAlgorithm < QUIC_CONGESTION_CONTROL_ALGORITHM_MAX);

    switch (Settings->CongestionControlAlgorithm) {
    default:
        QuicTraceLogConnWarning(
            InvalidCongestionControlAlgorithm,
            QuicCongestionControlGetConnection(Cc),
            "Unknown congestion control algorithm: %hu, fallback to Cubic",
            Settings->CongestionControlAlgorithm);
        __fallthrough;
    case QUIC_CONGESTION_CONTROL_ALGORITHM_CUBIC:
        CubicCongestionControlInitialize(Cc, Settings);
        break;
    }
}
