/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.

--*/

#pragma once

#include "bbr_common.h"

#if defined(__cplusplus)
extern "C" {
#endif

typedef struct QUIC_CONGESTION_CONTROL_BBR {

    BBR_COMMON Common;

    // If TRUE, Common.ProbeRttRound is valid.
    BOOLEAN ProbeRttRoundValid : 1;

    // Current cycle index in kPacingGain.
    uint32_t PacingCycleIndex;

} QUIC_CONGESTION_CONTROL_BBR;

_IRQL_requires_max_(DISPATCH_LEVEL)
void
BbrCongestionControlInitialize(
    _In_ QUIC_CONGESTION_CONTROL* Cc,
    _In_ const QUIC_SETTINGS_INTERNAL* Settings
    );

#if defined(__cplusplus)
}
#endif
