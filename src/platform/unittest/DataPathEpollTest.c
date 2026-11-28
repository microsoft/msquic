/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.

--*/

#include "../platform_internal.h"
#include "../datapath_linux.h"

uint32_t
CxPlatTestDataPathDisableSegmentation(
    CXPLAT_DATAPATH* Datapath
    )
{
    // Called before any sockets can use the send pools.
    if (Datapath->Features & CXPLAT_DATAPATH_FEATURE_SEND_SEGMENTATION) {
        Datapath->Features &= ~CXPLAT_DATAPATH_FEATURE_SEND_SEGMENTATION;
        Datapath->SendDataSize += (CXPLAT_MAX_IO_BATCH_SIZE - 1) * sizeof(struct iovec);
        Datapath->SendIoVecCount = CXPLAT_MAX_IO_BATCH_SIZE;
        for (uint32_t i = 0; i < Datapath->PartitionCount; ++i) {
            CXPLAT_POOL* Pool = &Datapath->Partitions[i].SendBlockPool;
            CxPlatPoolUninitialize(Pool);
            CxPlatPoolInitialize(TRUE, Datapath->SendDataSize, QUIC_POOL_DATA, Pool);
        }
    }
    return CXPLAT_LARGE_IO_BUFFER_SIZE;
}
