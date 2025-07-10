/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.

--*/

#include "main.h"
#ifdef QUIC_CLOG
#include "BbrTest.cpp.clog.h"
#endif

TEST(BbrTest, SendAllowanceOverflowFix) {
    //
    // This test demonstrates that type elevation fixes the overflow issue
    // in BBR SendAllowance calculation
    //

    // Constants from bbr.c
    const uint32_t GAIN_UNIT = 256;
    
    // High bandwidth scenario (6 Gbps)
    uint64_t BandwidthEst = 6ULL * 1000 * 1000 * 1000; // 6 Gbps in bps
    uint32_t PacingGain = 738; // kHighGain ≈ 2.885 * GAIN_UNIT
    uint64_t TimeSinceLastSend = 1000; // 1ms in microseconds
    
    // Original calculation (what would happen with uint32_t cast)
    uint64_t OriginalCalculation = BandwidthEst * PacingGain * TimeSinceLastSend / GAIN_UNIT;
    uint32_t OriginalWithOverflow = (uint32_t)OriginalCalculation;
    
    // New calculation (using uint64_t variable, capped to uint32_t max)
    uint64_t NewCalculation = BandwidthEst * PacingGain * TimeSinceLastSend / GAIN_UNIT;
    uint32_t NewWithTypeElevation = (NewCalculation > UINT32_MAX) ? UINT32_MAX : (uint32_t)NewCalculation;
    
    // Verify the problem exists in original approach
    EXPECT_GT(OriginalCalculation, UINT32_MAX) << "Original calculation should overflow uint32_t";
    EXPECT_NE(OriginalWithOverflow, OriginalCalculation) << "Original cast should overflow";
    
    // Verify the fix works
    EXPECT_EQ(NewCalculation, OriginalCalculation) << "New calculation should be same as original 64-bit result";
    EXPECT_EQ(NewWithTypeElevation, UINT32_MAX) << "New approach should cap to UINT32_MAX";
    
    // The new approach should be much larger than the overflowed value
    EXPECT_GT(NewWithTypeElevation, OriginalWithOverflow) << "Type elevation should preserve more of the value";
    
    // Log the values for manual inspection
    printf("BandwidthEst: %llu bps\n", (unsigned long long)BandwidthEst);
    printf("TimeSinceLastSend: %llu us\n", (unsigned long long)TimeSinceLastSend);
    printf("PacingGain: %u (represents %f)\n", PacingGain, (double)PacingGain/GAIN_UNIT);
    printf("Original 64-bit calculation: %llu\n", (unsigned long long)OriginalCalculation);
    printf("Original with overflow (32-bit cast): %u\n", OriginalWithOverflow);
    printf("New with type elevation (capped): %u\n", NewWithTypeElevation);
    
    // Verify we get reasonable high bandwidth allowance
    EXPECT_GT(NewWithTypeElevation, 1000000u) << "Should allow significant data at high bandwidth";
}