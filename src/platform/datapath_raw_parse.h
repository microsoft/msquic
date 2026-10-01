/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.

Abstract:

    QUIC raw datapath packet parsing

--*/

#pragma once

#include "quic_datapath.h"

#if defined(__cplusplus)
extern "C" {
#endif

//
// Parses an Ethernet frame received by the raw datapath.
//
_IRQL_requires_max_(DISPATCH_LEVEL)
void
CxPlatDpRawParseEthernet(
    _In_ const CXPLAT_DATAPATH* Datapath,
    _Inout_ CXPLAT_RECV_DATA* Packet,
    _In_reads_bytes_(Length)
        const uint8_t* Payload,
    _In_ uint16_t Length
    );

#if defined(__cplusplus)
}
#endif
