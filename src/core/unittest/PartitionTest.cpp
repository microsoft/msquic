/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.

Abstract:

    Unit test for the partition ID and index logic.

--*/

#include "main.h"
#ifdef QUIC_CLOG
#include "PartitionTest.cpp.clog.h"
#endif

extern "C"
void
MsQuicCalculatePartitionMask(
    void
    );

TEST(PartitionTest, SplitPartitioning)
{
    //
    // For every supported partition count, this test validates that the logic
    // for incrementing and decrementing a partition index results in an
    // unchanged value.
    //

    const uint16_t Inc = QUIC_MAX_THROUGHPUT_PARTITION_OFFSET;

    for (uint32_t i = 1; i <= QUIC_MAX_PARTITION_COUNT; ++i) {
        MsQuicLib.PartitionCount = (uint16_t)i;
        MsQuicCalculatePartitionMask();

        //printf("Partition Count: %hhu [Mask: %hhx]\n", MsQuicLib.PartitionCount, MsQuicLib.PartitionMask);

        if (Inc >= MsQuicLib.PartitionCount) {
            continue;
        }

        for (uint32_t j = 0; j < i; ++j) {
            uint16_t PartitionIndex = (uint16_t)j;
            ASSERT_EQ(
                PartitionIndex,
                QuicPartitionIndexDecrement(
                    QuicPartitionIndexIncrement(
                        PartitionIndex,
                        Inc),
                    Inc));
        }
    }
}

TEST(PartitionTest, RandomPartitionId)
{
    //
    // For every supported partition count, this test validates that the logic
    // for generating a random partition ID from a partition index and then
    // converting it back to a partition index.
    //

    for (uint32_t i = 1; i <= QUIC_MAX_PARTITION_COUNT; ++i) {
        MsQuicLib.PartitionCount = (uint16_t)i;
        MsQuicCalculatePartitionMask();

        //printf("Partition Count: %hhu [Mask: %hhx]\n", MsQuicLib.PartitionCount, MsQuicLib.PartitionMask);

        for (uint32_t j = 0; j < i; ++j) {
            uint16_t PartitionIndex = (uint16_t)j;

            for (uint32_t k = 0; k < 50; ++k) {
                uint16_t PartitionId = QuicPartitionIdCreate(PartitionIndex);
                ASSERT_EQ(PartitionIndex, QuicPartitionIdGetIndex(PartitionId));
            }
        }
    }
}
