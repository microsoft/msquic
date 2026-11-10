/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.

Abstract:

    Fuzzing raw datapath packet parsing

--*/

#define CX_PLATFORM_LINUX 1

#include <stddef.h>
#include <stdint.h>

#include "datapath_raw_parse.h"

int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    if (size > UINT16_MAX) {
        return 0;
    }

    CXPLAT_ROUTE Route = {0};
    CXPLAT_RECV_DATA Packet = {0};
    Packet.Route = &Route;

    const CXPLAT_DATAPATH* Datapath =
        (const CXPLAT_DATAPATH*)(uintptr_t)0xDEADBEEF;

    CxPlatDpRawParseEthernet(
        Datapath,
        &Packet,
        data,
        (uint16_t)size);

    return 0;
}
