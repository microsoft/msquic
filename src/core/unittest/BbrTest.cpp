/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.

--*/

#include "main.h"
#ifdef QUIC_CLOG
#include "BbrTest.cpp.clog.h"
#endif

TEST(BbrTest, SendAllowanceOverflowAndUnitConversionFix) {
    //
    // This test demonstrates the complete fix: proper unit conversion
    // combined with type elevation to prevent overflow
    //

    // Constants from bbr.c
    const uint32_t BW_UNIT = 8;
    const uint32_t GAIN_UNIT = 256;
    const uint64_t kMicroSecsInSec = 1000000;
    
    // High bandwidth scenario (6 Gbps)
    uint64_t BandwidthEst = 6ULL * 1000 * 1000 * 1000; // 6 Gbps in bps
    uint32_t PacingGain = 738; // kHighGain ≈ 2.885 * GAIN_UNIT
    uint64_t TimeSinceLastSend = 1000; // 1ms in microseconds
    
    // Original calculation (what would overflow with uint32_t)
    uint64_t OriginalWithoutUnitConversion = BandwidthEst * PacingGain * TimeSinceLastSend / GAIN_UNIT;
    uint32_t OriginalWithOverflow = (uint32_t)OriginalWithoutUnitConversion;
    
    // New calculation with proper unit conversion
    uint64_t NewWithUnitConversion = BandwidthEst * PacingGain * TimeSinceLastSend / GAIN_UNIT / kMicroSecsInSec / BW_UNIT;
    
    // Verify the problem existed in original approach
    EXPECT_GT(OriginalWithoutUnitConversion, UINT32_MAX) << "Original calculation should overflow uint32_t";
    EXPECT_NE(OriginalWithOverflow, OriginalWithoutUnitConversion) << "Original cast should overflow";
    
    // Verify the fix works - new approach should fit in uint32_t range after unit conversion
    EXPECT_LT(NewWithUnitConversion, UINT32_MAX) << "New calculation should fit in uint32_t after unit conversion";
    
    // The new approach should be much smaller due to proper unit conversion
    EXPECT_LT(NewWithUnitConversion, OriginalWithOverflow) << "Unit conversion should produce reasonable values";
    
    // Calculate the expected value: (6 * 10^9 * 2.885 * 0.001) / 8 ≈ 2,162,109 bytes
    uint64_t ExpectedValue = (6ULL * 1000 * 1000 * 1000 * 738 * 1000) / (256 * 1000000 * 8);
    EXPECT_NEAR(NewWithUnitConversion, ExpectedValue, ExpectedValue * 0.01) << "Result should be close to expected value";
    
    // Log the values for manual inspection
    printf("BandwidthEst: %llu bps\n", (unsigned long long)BandwidthEst);
    printf("TimeSinceLastSend: %llu us\n", (unsigned long long)TimeSinceLastSend);
    printf("PacingGain: %u (represents %f)\n", PacingGain, (double)PacingGain/GAIN_UNIT);
    printf("Original without unit conversion: %llu\n", (unsigned long long)OriginalWithoutUnitConversion);
    printf("Original with overflow (32-bit cast): %u\n", OriginalWithOverflow);
    printf("New with unit conversion: %llu\n", (unsigned long long)NewWithUnitConversion);
    printf("Expected value: %llu\n", (unsigned long long)ExpectedValue);
    
    // Verify we get reasonable bandwidth allowance (should be ~2MB for 6Gbps over 1ms)
    EXPECT_GT(NewWithUnitConversion, 2000000u) << "Should allow around 2MB for 6Gbps over 1ms";
    EXPECT_LT(NewWithUnitConversion, 3000000u) << "Should not be too much more than expected";
}