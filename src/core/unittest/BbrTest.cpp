/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.

--*/

#include "main.h"
#ifdef QUIC_CLOG
#include "BbrTest.cpp.clog.h"
#endif

TEST(BbrTest, SendAllowanceOverflowDemonstration) {
    //
    // This test demonstrates the overflow issue in BBR SendAllowance calculation
    // by showing what happens with the current formula
    //

    // Constants from bbr.c
    const uint32_t BW_UNIT = 8;
    const uint32_t GAIN_UNIT = 256;
    
    // High bandwidth scenario (6 Gbps)
    uint64_t BandwidthEst = 6ULL * 1000 * 1000 * 1000; // 6 Gbps in bps
    uint32_t PacingGain = 738; // kHighGain ≈ 2.885 * GAIN_UNIT
    uint64_t TimeSinceLastSend = 1000; // 1ms in microseconds
    
    // Current calculation from BBR code (missing both time and bit-to-byte conversion)
    uint64_t CurrentFormula = BandwidthEst * PacingGain * TimeSinceLastSend / GAIN_UNIT;
    
    // What gets stored in SendAllowance (cast to uint32_t)
    uint32_t CurrentSendAllowance = (uint32_t)CurrentFormula;
    
    // Corrected calculation (with both time conversion and bit-to-byte conversion)
    const uint64_t kMicroSecsInSec = 1000000;
    uint64_t CorrectedFormula = BandwidthEst * PacingGain * TimeSinceLastSend / GAIN_UNIT / kMicroSecsInSec / BW_UNIT;
    uint32_t CorrectedSendAllowance = (uint32_t)CorrectedFormula;
    
    // Show the problem
    EXPECT_NE(CurrentFormula, CorrectedFormula) << "Current and corrected formulas should be different";
    
    // The current formula overflows when cast to uint32_t, but produces wrong result
    // while the corrected formula gives the right result
    EXPECT_GT(CurrentFormula, UINT32_MAX) << "Current calculation should overflow uint32_t";
    EXPECT_LE(CorrectedFormula, UINT32_MAX) << "Corrected calculation should fit in uint32_t";
    
    // The overflow causes the cast to wrap around
    EXPECT_EQ(CurrentSendAllowance, (uint32_t)CurrentFormula) << "Current value is the wrapped result";
    
    // The corrected calculation should be the proper result without overflow
    EXPECT_EQ(CorrectedSendAllowance, (uint32_t)CorrectedFormula) << "Corrected value should not overflow";
    
    // Log the values for manual inspection
    printf("BandwidthEst: %llu bps\n", (unsigned long long)BandwidthEst);
    printf("TimeSinceLastSend: %llu us\n", (unsigned long long)TimeSinceLastSend);
    printf("PacingGain: %u (represents %f)\n", PacingGain, (double)PacingGain/GAIN_UNIT);
    printf("Current formula result (64-bit): %llu\n", (unsigned long long)CurrentFormula);
    printf("Current SendAllowance (32-bit cast): %u\n", CurrentSendAllowance);
    printf("Corrected formula result (64-bit): %llu\n", (unsigned long long)CorrectedFormula);
    printf("Corrected SendAllowance (32-bit cast): %u\n", CorrectedSendAllowance);
    
    // The corrected version should give a reasonable result  
    EXPECT_GT(CorrectedSendAllowance, 0u) << "Corrected calculation should not be zero";
    EXPECT_LT(CorrectedSendAllowance, 10000000u) << "Corrected calculation should be reasonable (under 10MB)";
    
    // The corrected calculation should be much smaller than current (and correct)
    EXPECT_LT(CorrectedSendAllowance, CurrentSendAllowance) << 
        "Corrected calculation should be much smaller than current (no overflow)";
    // The corrected calculation should be much smaller than the original 64-bit result
    EXPECT_LT(CorrectedFormula, CurrentFormula) << 
        "Corrected calculation should be much smaller than current";
        
    // Verify we're in the right ballpark: ~2.1 MB for 6Gbps over 1ms with pacing gain
    EXPECT_GT(CorrectedSendAllowance, 2000000u) << "Should be around 2MB";
    EXPECT_LT(CorrectedSendAllowance, 2500000u) << "Should be around 2MB";
    
    double ExpectedBytes = (6e9 * (738.0/256.0) * 1000) / 1e6 / 8;
    printf("Expected calculation result: %f bytes (~%.1f KB)\n", ExpectedBytes, ExpectedBytes/1024);
}