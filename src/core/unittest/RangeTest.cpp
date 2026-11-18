/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.

Abstract:

    Unit test for the QUIC_RANGE multirange tracker interface.

--*/

#include "main.h"
#include "range_tiered.h"
#ifdef QUIC_CLOG
#include "RangeTest.cpp.clog.h"
#endif

static constexpr QUIC_RANGE_MODE_MASK ArrayOnlyModes =
    QUIC_RANGE_MODE_ARRAY;
static constexpr QUIC_RANGE_MODE_MASK TieredModes =
    QUIC_RANGE_MODE_ARRAY | QUIC_RANGE_MODE_TIERED;

struct SmartRange {
    QUIC_RANGE range;
    SmartRange(
        uint32_t MaxAllocSize = QUIC_MAX_RANGE_ALLOC_SIZE,
        QUIC_RANGE_MODE_MASK AllowedModes = ArrayOnlyModes
        ) {
        // Tests pass the mode explicitly to exercise each storage policy.
        QuicRangeInitialize(MaxAllocSize, AllowedModes, &range);
    }
    ~SmartRange() {
        QuicRangeUninitialize(&range);
    }
    void Reset() {
        QuicRangeReset(&range);
    }
    bool TryAdd(uint64_t value) {
        return QuicRangeAddValue(&range, value) != FALSE;
    }
    bool TryAdd(uint64_t low, uint64_t count) {
        BOOLEAN rangeUpdated;
        return QuicRangeAddRange(&range, low, count, &rangeUpdated) != FALSE;
    }
    void Add(uint64_t value) {
        ASSERT_TRUE(TryAdd(value));
    #ifndef LOG_ONLY_FAILURES
        Dump();
    #endif
    }
    void Add(uint64_t low, uint64_t count) {
        ASSERT_TRUE(TryAdd(low, count));
    #ifndef LOG_ONLY_FAILURES
        Dump();
    #endif
    }
    int Find(uint64_t value) {
        QUIC_RANGE_SEARCH_KEY Key = { value, value };
        return QuicRangeSearch(&range, &Key);
    }
    int FindRange(uint64_t value, uint64_t count) {
        QUIC_RANGE_SEARCH_KEY Key = { value, value + count - 1 };
        return QuicRangeSearch(&range, &Key);
    }
    uint32_t FindContainingOrNext(uint64_t value) {
        return QuicRangeFindContainingOrNext(&range, value);
    }
    uint64_t Min() {
        uint64_t value;
        EXPECT_EQ(TRUE, QuicRangeGetMinSafe(&range, &value));
        return value;
    }
    uint64_t Max() {
        uint64_t value;
        EXPECT_EQ(TRUE, QuicRangeGetMaxSafe(&range, &value));
        return value;
    }
    uint32_t ValidCount() {
        return QuicRangeSize(&range);
    }
    void Dump() {
#if 0
        std::cerr << ("== Dump == ") << std::endl;
        for (uint32_t i = 0; i < QuicRangeSize(&range); i++) {
            auto cur = QuicRangeGet(&range, i);
            std::cerr << "[" << cur->Low << ":" << cur->Count << "]" << std::endl;
        }
#endif
    }
};

static void
ValidateModePolicy(
    const QUIC_RANGE& Range
    )
{
    ASSERT_TRUE(
        Range.Mode == QUIC_RANGE_MODE_ARRAY ||
        Range.Mode == QUIC_RANGE_MODE_TIERED);
    const QUIC_RANGE_MODE_MASK ActiveMode =
        static_cast<QUIC_RANGE_MODE_MASK>(Range.Mode);
    ASSERT_EQ(
        Range.AllowedModes & ActiveMode,
        ActiveMode);
}

TEST(RangeTest, AddSingle)
{
    SmartRange range;
    range.Add(100);
    ASSERT_EQ(range.ValidCount(), (uint32_t)1);
    ASSERT_EQ(range.Min(), (uint32_t)100);
    ASSERT_EQ(range.Max(), (uint32_t)100);
}

TEST(RangeTest, AddTwoAdjacentBefore)
{
    SmartRange range;
    range.Add(101);
    range.Add(100);
    ASSERT_EQ(range.ValidCount(), (uint32_t)1);
    ASSERT_EQ(range.Min(), (uint32_t)100);
    ASSERT_EQ(range.Max(), (uint32_t)101);
}

TEST(RangeTest, AddTwoAdjacentAfter)
{
    SmartRange range;
    range.Add(100);
    range.Add(101);
    ASSERT_EQ(range.ValidCount(), (uint32_t)1);
    ASSERT_EQ(range.Min(), (uint32_t)100);
    ASSERT_EQ(range.Max(), (uint32_t)101);
}

TEST(RangeTest, AddTwoSeparateBefore)
{
    SmartRange range;
    range.Add(102);
    range.Add(100);
    ASSERT_EQ(range.ValidCount(), (uint32_t)2);
    ASSERT_EQ(range.Min(), (uint32_t)100);
    ASSERT_EQ(range.Max(), (uint32_t)102);
}

TEST(RangeTest, AddTwoSeparateAfter)
{
    SmartRange range;
    range.Add(100);
    range.Add(102);
    ASSERT_EQ(range.ValidCount(), (uint32_t)2);
    ASSERT_EQ(range.Min(), (uint32_t)100);
    ASSERT_EQ(range.Max(), (uint32_t)102);
}

TEST(RangeTest, AddThreeMerge)
{
    SmartRange range;
    range.Add(100);
    range.Add(102);
    range.Add(101);
    ASSERT_EQ(range.ValidCount(), (uint32_t)1);
    ASSERT_EQ(range.Min(), (uint32_t)100);
    ASSERT_EQ(range.Max(), (uint32_t)102);
}

TEST(RangeTest, AddBetween)
{
    SmartRange range;
    range.Add(100);
    range.Add(104);
    range.Add(102);
    ASSERT_EQ(range.ValidCount(), (uint32_t)3);
    ASSERT_EQ(range.Min(), (uint32_t)100);
    ASSERT_EQ(range.Max(), (uint32_t)104);
}

TEST(RangeTest, AddRangeSingle)
{
    SmartRange range;
    range.Add(100, 100);
    ASSERT_EQ(range.ValidCount(), (uint32_t)1);
    ASSERT_EQ(range.Min(), (uint32_t)100);
    ASSERT_EQ(range.Max(), (uint32_t)199);
}

TEST(RangeTest, AddRangeBetween)
{
    SmartRange range;
    range.Add(100, 50);
    range.Add(300, 50);
    range.Add(200, 50);
    ASSERT_EQ(range.ValidCount(), (uint32_t)3);
    ASSERT_EQ(range.Min(), (uint32_t)100);
    ASSERT_EQ(range.Max(), (uint32_t)349);
}

TEST(RangeTest, AddRangeTwoAdjacentBefore)
{
    SmartRange range;
    range.Add(200, 100);
    range.Add(100, 100);
    ASSERT_EQ(range.ValidCount(), (uint32_t)1);
    ASSERT_EQ(range.Min(), (uint32_t)100);
    ASSERT_EQ(range.Max(), (uint32_t)299);
}

TEST(RangeTest, AddRangeTwoAdjacentAfter)
{
    SmartRange range;
    range.Add(100, 100);
    range.Add(200, 100);
    ASSERT_EQ(range.ValidCount(), (uint32_t)1);
    ASSERT_EQ(range.Min(), (uint32_t)100);
    ASSERT_EQ(range.Max(), (uint32_t)299);
}

TEST(RangeTest, AddRangeTwoSeparateBefore)
{
    SmartRange range;
    range.Add(300, 100);
    range.Add(100, 100);
    ASSERT_EQ(range.ValidCount(), (uint32_t)2);
    ASSERT_EQ(range.Min(), (uint32_t)100);
    ASSERT_EQ(range.Max(), (uint32_t)399);
}

TEST(RangeTest, AddRangeTwoSeparateAfter)
{
    SmartRange range;
    range.Add(100, 100);
    range.Add(300, 100);
    ASSERT_EQ(range.ValidCount(), (uint32_t)2);
    ASSERT_EQ(range.Min(), (uint32_t)100);
    ASSERT_EQ(range.Max(), (uint32_t)399);
}

TEST(RangeTest, AddRangeTwoOverlapBefore1)
{
    SmartRange range;
    range.Add(200, 100);
    range.Add(100, 150);
    ASSERT_EQ(range.ValidCount(), (uint32_t)1);
    ASSERT_EQ(range.Min(), (uint32_t)100);
    ASSERT_EQ(range.Max(), (uint32_t)299);
}

TEST(RangeTest, AddRangeTwoOverlapBefore2)
{
    SmartRange range;
    range.Add(200, 100);
    range.Add(100, 200);
    ASSERT_EQ(range.ValidCount(), (uint32_t)1);
    ASSERT_EQ(range.Min(), (uint32_t)100);
    ASSERT_EQ(range.Max(), (uint32_t)299);
}

TEST(RangeTest, AddRangeTwoOverlapBefore3)
{
    SmartRange range;
    range.Add(200, 50);
    range.Add(100, 200);
    ASSERT_EQ(range.ValidCount(), (uint32_t)1);
    ASSERT_EQ(range.Min(), (uint32_t)100);
    ASSERT_EQ(range.Max(), (uint32_t)299);
}

TEST(RangeTest, AddRangeTwoOverlapAfter1)
{
    SmartRange range;
    range.Add(100, 100);
    range.Add(150, 150);
    ASSERT_EQ(range.ValidCount(), (uint32_t)1);
    ASSERT_EQ(range.Min(), (uint32_t)100);
    ASSERT_EQ(range.Max(), (uint32_t)299);
}

TEST(RangeTest, AddRangeTwoOverlapAfter2)
{
    SmartRange range;
    range.Add(100, 100);
    range.Add(100, 200);
    ASSERT_EQ(range.ValidCount(), (uint32_t)1);
    ASSERT_EQ(range.Min(), (uint32_t)100);
    ASSERT_EQ(range.Max(), (uint32_t)299);
}

TEST(RangeTest, AddRangeThreeMerge)
{
    SmartRange range;
    range.Add(100, 100);
    range.Add(300, 100);
    range.Add(200, 100);
    ASSERT_EQ(range.ValidCount(), (uint32_t)1);
    ASSERT_EQ(range.Min(), (uint32_t)100);
    ASSERT_EQ(range.Max(), (uint32_t)399);
}

TEST(RangeTest, AddRangeThreeOverlapAndAdjacentAfter1)
{
    SmartRange range;
    range.Add(100, 1);
    range.Add(200, 100);
    range.Add(101, 150);
    ASSERT_EQ(range.ValidCount(), (uint32_t)1);
    ASSERT_EQ(range.Min(), (uint32_t)100);
    ASSERT_EQ(range.Max(), (uint32_t)299);
}

TEST(RangeTest, AddRangeThreeOverlapAndAdjacentAfter2)
{
    SmartRange range;
    range.Add(100, 1);
    range.Add(200, 100);
    range.Add(101, 299);
    ASSERT_EQ(range.ValidCount(), (uint32_t)1);
    ASSERT_EQ(range.Min(), (uint32_t)100);
    ASSERT_EQ(range.Max(), (uint32_t)399);
}

TEST(RangeTest, AddRangeThreeOverlapAndAdjacentAfter3)
{
    SmartRange range;
    range.Add(100, 100);
    range.Add(300, 100);
    range.Add(150, 150);
    ASSERT_EQ(range.ValidCount(), (uint32_t)1);
    ASSERT_EQ(range.Min(), (uint32_t)100);
    ASSERT_EQ(range.Max(), (uint32_t)399);
}

TEST(RangeTest, AddRangeThreeOverlapAndAdjacentAfter4)
{
    SmartRange range;
    range.Add(100, 100);
    range.Add(300, 100);
    range.Add(50, 250);
    ASSERT_EQ(range.ValidCount(), (uint32_t)1);
    ASSERT_EQ(range.Min(), (uint32_t)50);
    ASSERT_EQ(range.Max(), (uint32_t)399);
}

TEST(RangeTest, ExampleAckTest)
{
    //
    // Simulates the production ACK tracker pattern: add received packet
    // numbers, then trim via QuicRangeSetMin as ACKs are acknowledged.
    //
    SmartRange range;
    range.Add(10000);
    range.Add(10001);
    range.Add(10003);
    range.Add(10002);
    ASSERT_EQ(range.ValidCount(), (uint32_t)1);
    ASSERT_EQ(range.Min(), 10000ull);
    ASSERT_EQ(range.Max(), 10003ull);

    // Peer ACKs up to 10001, trim everything <= 10001.
    QuicRangeSetMin(&range.range, 10002);
    ASSERT_EQ(range.ValidCount(), (uint32_t)1);
    ASSERT_EQ(range.Min(), 10002ull);
    ASSERT_EQ(range.Max(), 10003ull);

    // Peer ACKs up to 10003, trim everything.
    QuicRangeSetMin(&range.range, 10004);
    ASSERT_EQ(range.ValidCount(), (uint32_t)0);

    // Receive more packets.
    range.Add(10005);
    range.Add(10006);
    range.Add(10004);
    range.Add(10007);
    ASSERT_EQ(range.ValidCount(), (uint32_t)1);
    ASSERT_EQ(range.Min(), 10004ull);
    ASSERT_EQ(range.Max(), 10007ull);

    // Peer ACKs up to 10007.
    QuicRangeSetMin(&range.range, 10008);
    ASSERT_EQ(range.ValidCount(), (uint32_t)0);
}

TEST(RangeTest, ExampleAckWithLossTest)
{
    //
    // Simulates receiving packets with gaps (loss), then trimming via
    // QuicRangeSetMin as ACKs are acknowledged.
    //
    SmartRange range;
    range.Add(10000);
    range.Add(10001);
    range.Add(10003); // 10002 lost
    ASSERT_EQ(range.ValidCount(), (uint32_t)2);

    // 10002 arrives (retransmitted).
    range.Add(10002);
    ASSERT_EQ(range.ValidCount(), (uint32_t)1);

    // Peer ACKs up to 10001, trim.
    QuicRangeSetMin(&range.range, 10002);
    ASSERT_EQ(range.ValidCount(), (uint32_t)1);
    ASSERT_EQ(range.Min(), 10002ull);
    ASSERT_EQ(range.Max(), 10003ull);

    // Peer ACKs up to 10003, trim all.
    QuicRangeSetMin(&range.range, 10004);
    ASSERT_EQ(range.ValidCount(), (uint32_t)0);

    // New batch of packets.
    range.Add(10004);
    range.Add(10005);
    range.Add(10006);
    ASSERT_EQ(range.ValidCount(), (uint32_t)1);

    // Peer ACKs all.
    QuicRangeSetMin(&range.range, 10007);
    ASSERT_EQ(range.ValidCount(), (uint32_t)0);

    // Another batch with a gap.
    range.Add(10008);
    range.Add(10009);
    range.Add(10011); // 10010 lost
    ASSERT_EQ(range.ValidCount(), (uint32_t)2);

    // Peer ACKs up to 10009, trim front range.
    QuicRangeSetMin(&range.range, 10010);
    ASSERT_EQ(range.ValidCount(), (uint32_t)1);
    ASSERT_EQ(range.Min(), 10011ull);
    ASSERT_EQ(range.Max(), 10011ull);
}

TEST(RangeTest, AddLots)
{
    SmartRange range;
    for (uint32_t i = 0; i < 400; i += 2) {
        range.Add(i);
    }
    ASSERT_EQ(range.ValidCount(), (uint32_t)200);
    //
    // Use SetMin to trim from the front, verifying the range still works
    // after many additions and removals.
    //
    QuicRangeSetMin(&range.range, 397);
    ASSERT_EQ(range.ValidCount(), (uint32_t)1);
    ASSERT_EQ(range.Min(), 398ull);
    ASSERT_EQ(range.Max(), 398ull);
}

TEST(RangeTest, HitMax)
{
    const uint32_t MaxCount = 16;
    SmartRange range(MaxCount * sizeof(QUIC_SUBRANGE));
    for (uint32_t i = 0; i < MaxCount; i++) {
        range.Add(i*2);
    }
    ASSERT_EQ(range.ValidCount(), MaxCount);
    ASSERT_EQ(range.Min(), 0ull);
    ASSERT_EQ(range.Max(), (MaxCount - 1)*2);
    range.Add(MaxCount*2);
    ASSERT_EQ(range.ValidCount(), MaxCount);
    ASSERT_EQ(range.Min(), 2ull);
    ASSERT_EQ(range.Max(), MaxCount*2);
    //
    // Use SetMin to trim the front, then verify we can add back.
    //
    QuicRangeSetMin(&range.range, 4);
    ASSERT_EQ(range.ValidCount(), MaxCount - 1);
    ASSERT_EQ(range.Min(), 4ull);
    ASSERT_EQ(range.Max(), MaxCount*2);
    range.Add(0);
    ASSERT_EQ(range.ValidCount(), MaxCount);
    ASSERT_EQ(range.Min(), 0ull);
    ASSERT_EQ(range.Max(), MaxCount*2);
}

//
// Compares the ordered subranges returned by QuicRangeGet(), independent of
// whether the range uses array or tiered storage.
//
static void
ValidateRangesEqual(
    const QUIC_RANGE& Left,
    const QUIC_RANGE& Right
    )
{
    ASSERT_EQ(QuicRangeSize(&Left), QuicRangeSize(&Right));
    for (uint32_t i = 0; i < QuicRangeSize(&Left); ++i) {
        const QUIC_SUBRANGE* LeftSub = QuicRangeGet(&Left, i);
        const QUIC_SUBRANGE* RightSub = QuicRangeGet(&Right, i);
        ASSERT_EQ(LeftSub->Low, RightSub->Low);
        ASSERT_EQ(LeftSub->Count, RightSub->Count);
    }
}

//
// Verifies a sequence of equally spaced singleton subranges.
//
static void
ValidateSequentialSingletonRanges(
    const QUIC_RANGE& Range,
    uint32_t ExpectedCount,
    uint64_t FirstLow = 2,
    uint64_t Step = 2
    )
{
    ASSERT_EQ(QuicRangeSize(&Range), ExpectedCount);
    for (uint32_t i = 0; i < ExpectedCount; ++i) {
        const QUIC_SUBRANGE* Sub = QuicRangeGet(&Range, i);
        ASSERT_EQ(Sub->Low, FirstLow + Step * i);
        ASSERT_EQ(Sub->Count, 1u);
    }
}

TEST(RangeTest, InitializationPolicies)
{
    SmartRange ArrayOnly(
        QUIC_MAX_RANGE_ALLOC_SIZE,
        ArrayOnlyModes);
    ASSERT_EQ(ArrayOnly.range.Mode, QUIC_RANGE_MODE_ARRAY);
    ASSERT_EQ(ArrayOnly.range.AllowedModes, ArrayOnlyModes);
    ValidateModePolicy(ArrayOnly.range);

    SmartRange Tiered(
        QUIC_MAX_RANGE_ALLOC_SIZE,
        TieredModes);
    ASSERT_EQ(Tiered.range.Mode, QUIC_RANGE_MODE_ARRAY);
    ASSERT_EQ(Tiered.range.AllowedModes, TieredModes);
    ValidateModePolicy(Tiered.range);
}

TEST(RangeTest, ArrayOnlyLargeRangeRemainsArray)
{
    SmartRange Range(
        QUIC_MAX_RANGE_ALLOC_SIZE,
        ArrayOnlyModes);
    for (uint32_t i = 0;
         i <= QUIC_RANGE_TIERED_PROMOTE_LENGTH;
         ++i) {
        Range.Add(2ULL * i);
    }

    ASSERT_EQ(Range.range.Mode, QUIC_RANGE_MODE_ARRAY);
    ASSERT_EQ(Range.range.AllowedModes, ArrayOnlyModes);
    ASSERT_EQ(
        Range.range.Array.AllocLength,
        2 * QUIC_RANGE_TIERED_PROMOTE_LENGTH);
    ASSERT_EQ(
        Range.ValidCount(),
        QUIC_RANGE_TIERED_PROMOTE_LENGTH + 1);
    ValidateModePolicy(Range.range);

    Range.Reset();
    ASSERT_EQ(Range.range.Mode, QUIC_RANGE_MODE_ARRAY);
    ASSERT_EQ(Range.range.AllowedModes, ArrayOnlyModes);
    ASSERT_EQ(
        Range.range.Array.AllocLength,
        2 * QUIC_RANGE_TIERED_PROMOTE_LENGTH);
    Range.Add(1);
    ValidateModePolicy(Range.range);
}

TEST(RangeTest, TieredOptInInsufficientBudgetUsesArray)
{
    const uint32_t MaxAllocSize =
        2 * QUIC_RANGE_TIERED_BLOCK_BYTES;
    ASSERT_FALSE(QuicRangeTieredCanPromote(MaxAllocSize));
    SmartRange Range(
        MaxAllocSize,
        TieredModes);
    for (uint32_t i = 0;
         i <= QUIC_RANGE_TIERED_PROMOTE_LENGTH;
         ++i) {
        Range.Add(2ULL * i);
    }

    ASSERT_EQ(Range.range.Mode, QUIC_RANGE_MODE_ARRAY);
    ASSERT_EQ(Range.range.AllowedModes, TieredModes);
    ASSERT_EQ(
        Range.range.Array.AllocLength,
        2 * QUIC_RANGE_TIERED_PROMOTE_LENGTH);
    ASSERT_EQ(
        Range.ValidCount(),
        QUIC_RANGE_TIERED_PROMOTE_LENGTH + 1);
    ValidateModePolicy(Range.range);
}

//
// Verifies that a non-maximum-budget tiered range evicts its lowest subrange
// when full, while insertion at the front still fails without modification.
//
TEST(RangeTest, TieredNonMaximumBudgetAgesOldest)
{
    const uint32_t MaxAllocSize =
        3 * QUIC_RANGE_TIERED_BLOCK_BYTES;
    const uint32_t ExpectedCapacity =
        2 * QUIC_RANGE_TIERED_BLOCK_CAPACITY;
    ASSERT_TRUE(QuicRangeTieredCanPromote(MaxAllocSize));
    ASSERT_LT(MaxAllocSize, QUIC_MAX_RANGE_ALLOC_SIZE);

    SmartRange Range(
        MaxAllocSize,
        TieredModes);
    for (uint32_t i = 0; i < ExpectedCapacity; ++i) {
        Range.Add(4ULL * i);
    }

    ASSERT_EQ(Range.range.Mode, QUIC_RANGE_MODE_TIERED);
    ASSERT_EQ(Range.range.AllowedModes, TieredModes);
    ValidateModePolicy(Range.range);
    ASSERT_EQ(
        QuicRangeTieredGetCapacity(Range.range.Tiered),
        ExpectedCapacity);
    const uint32_t AllocatedBytes =
        QuicRangeTieredGetAllocatedBytes(Range.range.Tiered);

    ASSERT_TRUE(Range.TryAdd(4ULL * ExpectedCapacity));
    ASSERT_EQ(Range.ValidCount(), ExpectedCapacity);
    ASSERT_EQ(
        QuicRangeTieredGetAllocatedBytes(Range.range.Tiered),
        AllocatedBytes);
    ValidateSequentialSingletonRanges(
        Range.range,
        ExpectedCapacity,
        4,
        4);

    ASSERT_FALSE(Range.TryAdd(0));
    ASSERT_EQ(Range.ValidCount(), ExpectedCapacity);
    ASSERT_EQ(
        QuicRangeTieredGetAllocatedBytes(Range.range.Tiered),
        AllocatedBytes);
    ValidateSequentialSingletonRanges(
        Range.range,
        ExpectedCapacity,
        4,
        4);

    // Insert at the first block's final slot. Aging removes the minimum, and
    // insertion carries the displaced record across the block boundary.
    const uint32_t MiddleIndex =
        QUIC_RANGE_TIERED_BLOCK_CAPACITY - 1;
    const uint64_t MiddleLow =
        4ULL * QUIC_RANGE_TIERED_BLOCK_CAPACITY + 2;
    ASSERT_TRUE(Range.TryAdd(MiddleLow));
    ASSERT_EQ(Range.range.Mode, QUIC_RANGE_MODE_TIERED);
    ASSERT_EQ(Range.ValidCount(), ExpectedCapacity);
    ASSERT_EQ(
        QuicRangeTieredGetAllocatedBytes(Range.range.Tiered),
        AllocatedBytes);
    for (uint32_t i = 0; i < ExpectedCapacity; ++i) {
        const QUIC_SUBRANGE* Sub =
            QuicRangeGet(&Range.range, i);
        uint64_t ExpectedLow;
        if (i < MiddleIndex) {
            ExpectedLow = 4ULL * (i + 2);
        } else if (i == MiddleIndex) {
            ExpectedLow = MiddleLow;
        } else {
            ExpectedLow = 4ULL * (i + 1);
        }
        ASSERT_EQ(Sub->Low, ExpectedLow);
        ASSERT_EQ(Sub->Count, 1u);
    }
}

//
// Verifies that only a new 257th subrange promotes and transfers the full array.
//
TEST(RangeTest, TieredPromotionPolicy)
{
    SmartRange Range(
        QUIC_MAX_RANGE_ALLOC_SIZE,
        TieredModes);
    for (uint32_t i = 0;
         i < QUIC_RANGE_TIERED_PROMOTE_LENGTH;
         ++i) {
        Range.Add(4ULL * i);
    }

    ASSERT_EQ(Range.range.Mode, QUIC_RANGE_MODE_ARRAY);
    ASSERT_EQ(Range.range.AllowedModes, TieredModes);
    ValidateModePolicy(Range.range);
    ASSERT_EQ(
        Range.range.Array.AllocLength,
        QUIC_RANGE_TIERED_PROMOTE_LENGTH);
    QUIC_SUBRANGE* const OriginalSubRanges =
        Range.range.Array.SubRanges;

    Range.Add(0, 2);
    ASSERT_EQ(Range.range.Mode, QUIC_RANGE_MODE_ARRAY);
    ASSERT_EQ(
        Range.ValidCount(),
        QUIC_RANGE_TIERED_PROMOTE_LENGTH);
    ASSERT_EQ(QuicRangeGet(&Range.range, 0)->Count, 2u);

    Range.Add(4ULL * QUIC_RANGE_TIERED_PROMOTE_LENGTH);
    ASSERT_EQ(Range.range.Mode, QUIC_RANGE_MODE_TIERED);
    ASSERT_EQ(Range.range.AllowedModes, TieredModes);
    ValidateModePolicy(Range.range);
    ASSERT_EQ(
        Range.ValidCount(),
        QUIC_RANGE_TIERED_PROMOTE_LENGTH + 1);
    ASSERT_EQ(
        QuicRangeGet(&Range.range, 0),
        OriginalSubRanges);
    for (uint32_t i = 0; i < Range.ValidCount(); ++i) {
        ASSERT_EQ(QuicRangeGet(&Range.range, i)->Low, 4ULL * i);
    }
}

//
// Verifies that small fixed-budget ranges remain array-backed and evict the
// lowest subrange when full.
//
TEST(RangeTest, TieredLeavesSmallBudgetsAsArrays)
{
    // Duplicate-packet and decoded-ACK tracking use the same 4 KiB budget.
    const uint32_t Budgets[] = {
        QUIC_MAX_RANGE_ACK_PACKETS,
        QUIC_MAX_RANGE_DUPLICATE_PACKETS
    };

    for (uint32_t Budget : Budgets) {
        SmartRange Range(
            Budget,
            TieredModes);
        const uint32_t Capacity =
            Budget / sizeof(QUIC_SUBRANGE);
        for (uint32_t i = 0; i < Capacity; ++i) {
            Range.Add(2ULL * i);
        }

        ASSERT_EQ(Range.range.Mode, QUIC_RANGE_MODE_ARRAY);
        ASSERT_EQ(Range.range.AllowedModes, TieredModes);
        ValidateModePolicy(Range.range);
        ASSERT_EQ(Range.range.Array.AllocLength, Capacity);
        ASSERT_EQ(Range.ValidCount(), Capacity);

        Range.Add(2ULL * Capacity);
        ASSERT_EQ(Range.range.Mode, QUIC_RANGE_MODE_ARRAY);
        ASSERT_EQ(Range.ValidCount(), Capacity);
        ASSERT_EQ(Range.Min(), 2u);
        ASSERT_EQ(Range.Max(), 2ULL * Capacity);
    }
}

#ifdef DEBUG
//
// Verifies that conversion and tiered-growth allocation failures preserve contents.
//
TEST(RangeTest, TieredAllocationFailuresAreAtomic)
{
    const int32_t FailurePoints[] = {-1, -2};
    for (int32_t FailurePoint : FailurePoints) {
        SmartRange Range(
            QUIC_MAX_RANGE_ALLOC_SIZE,
            TieredModes);
        for (uint32_t i = 0;
             i < QUIC_RANGE_TIERED_PROMOTE_LENGTH;
             ++i) {
            Range.Add(2ULL * i);
        }

        QUIC_SUBRANGE* const OriginalSubRanges =
            Range.range.Array.SubRanges;
        CxPlatSetAllocFailDenominator(FailurePoint);
        const bool Inserted =
            Range.TryAdd(
                2ULL * QUIC_RANGE_TIERED_PROMOTE_LENGTH);
        CxPlatSetAllocFailDenominator(0);

        ASSERT_FALSE(Inserted);
        ASSERT_EQ(Range.range.Mode, QUIC_RANGE_MODE_ARRAY);
        ASSERT_EQ(Range.range.AllowedModes, TieredModes);
        ValidateModePolicy(Range.range);
        ASSERT_EQ(Range.range.Array.SubRanges, OriginalSubRanges);
        ASSERT_EQ(
            Range.ValidCount(),
            QUIC_RANGE_TIERED_PROMOTE_LENGTH);
        for (uint32_t i = 0;
             i < QUIC_RANGE_TIERED_PROMOTE_LENGTH;
             ++i) {
            ASSERT_EQ(
                QuicRangeGet(&Range.range, i)->Low,
                2ULL * i);
        }
    }

    SmartRange Range(
        QUIC_MAX_RANGE_ALLOC_SIZE,
        TieredModes);
    const uint32_t InitialCount =
        2 * QUIC_RANGE_TIERED_BLOCK_CAPACITY;
    for (uint32_t i = 0; i < InitialCount; ++i) {
        Range.Add(4ULL * i);
    }
    ASSERT_EQ(Range.range.Mode, QUIC_RANGE_MODE_TIERED);

    std::vector<QUIC_SUBRANGE> OriginalRanges(InitialCount);
    for (uint32_t i = 0; i < InitialCount; ++i) {
        OriginalRanges[i] = *QuicRangeGet(&Range.range, i);
    }
    const uint32_t OriginalAllocatedBytes =
        QuicRangeTieredGetAllocatedBytes(Range.range.Tiered);
    const uint64_t InsertLow =
        4ULL * QUIC_RANGE_TIERED_BLOCK_CAPACITY - 2;

    BOOLEAN RangeUpdated = TRUE;
    CxPlatSetAllocFailDenominator(-1);
    QUIC_SUBRANGE* Result =
        QuicRangeAddRange(
            &Range.range,
            InsertLow,
            1,
            &RangeUpdated);
    CxPlatSetAllocFailDenominator(0);

    ASSERT_EQ(Result, nullptr);
    ASSERT_FALSE(RangeUpdated);
    ASSERT_EQ(Range.range.Mode, QUIC_RANGE_MODE_TIERED);
    ASSERT_EQ(Range.range.AllowedModes, TieredModes);
    ValidateModePolicy(Range.range);
    ASSERT_EQ(Range.ValidCount(), InitialCount);
    ASSERT_EQ(
        QuicRangeTieredGetAllocatedBytes(Range.range.Tiered),
        OriginalAllocatedBytes);
    for (uint32_t i = 0; i < InitialCount; ++i) {
        const QUIC_SUBRANGE* Sub = QuicRangeGet(&Range.range, i);
        ASSERT_EQ(Sub->Low, OriginalRanges[i].Low);
        ASSERT_EQ(Sub->Count, OriginalRanges[i].Count);
    }

    RangeUpdated = FALSE;
    Result =
        QuicRangeAddRange(
            &Range.range,
            InsertLow,
            1,
            &RangeUpdated);
    ASSERT_NE(Result, nullptr);
    ASSERT_TRUE(RangeUpdated);
    ASSERT_EQ(Range.ValidCount(), InitialCount + 1);
    ASSERT_EQ(
        Result,
        QuicRangeGet(
            &Range.range,
            QUIC_RANGE_TIERED_BLOCK_CAPACITY));
    ASSERT_EQ(Result->Low, InsertLow);
    ASSERT_EQ(Result->Count, 1u);
    ASSERT_EQ(
        QuicRangeTieredGetAllocatedBytes(Range.range.Tiered),
        OriginalAllocatedBytes + QUIC_RANGE_TIERED_BLOCK_BYTES);
}
#endif

//
// Applies the same insert, remove, merge, prefix-trim, and reinsert operations
// to tiered and array-backed ranges and verifies identical results.
//
TEST(RangeTest, TieredMatchesArrayAcrossMultipleBlocks)
{
    SmartRange Tiered(
        QUIC_MAX_RANGE_ALLOC_SIZE,
        TieredModes);
    SmartRange Array(
        QUIC_RANGE_NO_MAX_ALLOC_SIZE,
        ArrayOnlyModes);

    const uint32_t InitialCount =
        4 * QUIC_RANGE_TIERED_BLOCK_CAPACITY + 257;
    std::vector<uint64_t> Values(InitialCount);
    for (uint32_t i = 0; i < InitialCount; ++i) {
        Values[i] = 2ULL * i;
    }

    // Deterministic shuffling exercises insertion throughout multiple blocks.
    uint64_t State = 0x9E3779B97F4A7C15ull;
    for (uint32_t i = InitialCount; i > 1; --i) {
        State ^= State << 7;
        State ^= State >> 9;
        State ^= State << 8;
        const uint32_t SwapIndex =
            (uint32_t)(State % i);
        std::swap(Values[i - 1], Values[SwapIndex]);
    }

    uint32_t PeakCount = 0;
    for (uint64_t Low : Values) {
        BOOLEAN TieredUpdated;
        BOOLEAN ArrayUpdated;
        QUIC_SUBRANGE* TieredResult =
            QuicRangeAddRange(
                &Tiered.range,
                Low,
                1,
                &TieredUpdated);
        QUIC_SUBRANGE* ArrayResult =
            QuicRangeAddRange(
                &Array.range,
                Low,
                1,
                &ArrayUpdated);
        ASSERT_EQ(TieredResult == nullptr, ArrayResult == nullptr);
        ASSERT_EQ(TieredUpdated, ArrayUpdated);
        ValidateRangesEqual(Tiered.range, Array.range);
        PeakCount =
            CXPLAT_MAX(PeakCount, Tiered.ValidCount());
    }

    ASSERT_GE(
        PeakCount,
        4 * QUIC_RANGE_TIERED_BLOCK_CAPACITY);
    ASSERT_EQ(Tiered.range.Mode, QUIC_RANGE_MODE_TIERED);

    std::vector<uint64_t> RemovedValues;
    for (uint32_t Operation = 0; Operation < 18; ++Operation) {
        State ^= State << 7;
        State ^= State >> 9;
        State ^= State << 8;

        const uint32_t RemoveIndex =
            (uint32_t)(State % Tiered.ValidCount());
        uint32_t RemoveCount;
        // Rotate through single, short-span, and half-block removal paths.
        if ((Operation % 3) == 0) {
            RemoveCount = 1;
        } else if ((Operation % 3) == 1) {
            RemoveCount = CXPLAT_MIN(
                2u,
                Tiered.ValidCount() - RemoveIndex);
        } else {
            RemoveCount = CXPLAT_MIN(
                QUIC_RANGE_TIERED_BLOCK_CAPACITY / 2,
                Tiered.ValidCount() - RemoveIndex);
        }

        for (uint32_t i = 0; i < RemoveCount; ++i) {
            RemovedValues.push_back(
                QuicRangeGet(
                    &Tiered.range,
                    RemoveIndex + i)->Low);
        }
        (void)QuicRangeRemoveSubranges(
            &Tiered.range,
            RemoveIndex,
            RemoveCount);
        (void)QuicRangeRemoveSubranges(
            &Array.range,
            RemoveIndex,
            RemoveCount);
        ValidateRangesEqual(Tiered.range, Array.range);
    }

    for (uint64_t Low : RemovedValues) {
        Tiered.Add(Low);
        Array.Add(Low);
        ValidateRangesEqual(Tiered.range, Array.range);
    }

    ASSERT_EQ(Tiered.ValidCount(), InitialCount);
    ASSERT_EQ(Array.ValidCount(), InitialCount);

    // Merge across the first block boundary and verify the returned records.
    const uint32_t MergeFirstIndex =
        QUIC_RANGE_TIERED_BLOCK_CAPACITY - 2;
    const uint32_t MergeLastIndex =
        QUIC_RANGE_TIERED_BLOCK_CAPACITY + 2;
    const uint64_t MergeLow = 2ULL * MergeFirstIndex;
    const uint64_t MergeCount =
        2ULL * (MergeLastIndex - MergeFirstIndex) + 1;
    BOOLEAN TieredUpdated = FALSE;
    BOOLEAN ArrayUpdated = FALSE;
    QUIC_SUBRANGE* TieredResult =
        QuicRangeAddRange(
            &Tiered.range,
            MergeLow,
            MergeCount,
            &TieredUpdated);
    QUIC_SUBRANGE* ArrayResult =
        QuicRangeAddRange(
            &Array.range,
            MergeLow,
            MergeCount,
            &ArrayUpdated);
    ASSERT_NE(TieredResult, nullptr);
    ASSERT_NE(ArrayResult, nullptr);
    ASSERT_TRUE(TieredUpdated);
    ASSERT_EQ(TieredUpdated, ArrayUpdated);
    ASSERT_EQ(
        TieredResult,
        QuicRangeGet(&Tiered.range, MergeFirstIndex));
    ASSERT_EQ(
        ArrayResult,
        QuicRangeGet(&Array.range, MergeFirstIndex));
    ASSERT_EQ(TieredResult->Low, MergeLow);
    ASSERT_EQ(TieredResult->Count, MergeCount);
    ASSERT_EQ(ArrayResult->Low, MergeLow);
    ASSERT_EQ(ArrayResult->Count, MergeCount);
    ValidateRangesEqual(Tiered.range, Array.range);

    // Trim into the merged range so prefix removal also updates its first record.
    const uint64_t TrimLow = MergeLow + 3;
    QuicRangeSetMin(&Tiered.range, TrimLow);
    QuicRangeSetMin(&Array.range, TrimLow);
    ValidateRangesEqual(Tiered.range, Array.range);
    ASSERT_EQ(QuicRangeGet(&Tiered.range, 0)->Low, TrimLow);
    ASSERT_EQ(
        QuicRangeGet(&Tiered.range, 0)->Count,
        MergeCount - 3);

    // Leave ten records tiered, then merge three into one to trigger demotion.
    (void)QuicRangeRemoveSubranges(
        &Tiered.range,
        10,
        Tiered.ValidCount() - 10);
    (void)QuicRangeRemoveSubranges(
        &Array.range,
        10,
        Array.ValidCount() - 10);
    ASSERT_EQ(Tiered.range.Mode, QUIC_RANGE_MODE_TIERED);
    ValidateRangesEqual(Tiered.range, Array.range);

    const uint32_t DemotionMergeIndex = 1;
    const QUIC_SUBRANGE* DemotionMergeFirst =
        QuicRangeGet(&Tiered.range, DemotionMergeIndex);
    const QUIC_SUBRANGE* DemotionMergeLast =
        QuicRangeGet(&Tiered.range, DemotionMergeIndex + 2);
    const uint64_t DemotionMergeLow = DemotionMergeFirst->Low;
    const uint64_t DemotionMergeCount =
        QuicRangeGetHigh(DemotionMergeLast) -
            DemotionMergeLow + 1;

    TieredUpdated = FALSE;
    ArrayUpdated = FALSE;
    TieredResult =
        QuicRangeAddRange(
            &Tiered.range,
            DemotionMergeLow,
            DemotionMergeCount,
            &TieredUpdated);
    ArrayResult =
        QuicRangeAddRange(
            &Array.range,
            DemotionMergeLow,
            DemotionMergeCount,
            &ArrayUpdated);
    ASSERT_NE(TieredResult, nullptr);
    ASSERT_NE(ArrayResult, nullptr);
    ASSERT_TRUE(TieredUpdated);
    ASSERT_EQ(TieredUpdated, ArrayUpdated);
    ASSERT_EQ(Tiered.range.Mode, QUIC_RANGE_MODE_ARRAY);
    ASSERT_EQ(Tiered.ValidCount(), QUIC_RANGE_INITIAL_SUB_COUNT);
    ASSERT_EQ(
        TieredResult,
        QuicRangeGet(&Tiered.range, DemotionMergeIndex));
    ASSERT_EQ(
        ArrayResult,
        QuicRangeGet(&Array.range, DemotionMergeIndex));
    ASSERT_EQ(TieredResult->Low, DemotionMergeLow);
    ASSERT_EQ(TieredResult->Count, DemotionMergeCount);
    ASSERT_EQ(ArrayResult->Low, DemotionMergeLow);
    ASSERT_EQ(ArrayResult->Count, DemotionMergeCount);
    ValidateRangesEqual(Tiered.range, Array.range);
}

//
// Verifies that removals free unused blocks, shrink back to inline array
// storage, allow later promotion again, and reset to an empty inline range.
//
TEST(RangeTest, TieredReclaimsBlocksAndDemotes)
{
    SmartRange Range(
        QUIC_MAX_RANGE_ALLOC_SIZE,
        TieredModes);
    const uint32_t InitialCount =
        8 * QUIC_RANGE_TIERED_BLOCK_CAPACITY;
    for (uint32_t i = 0; i < InitialCount; ++i) {
        Range.Add(2ULL * i);
    }

    ASSERT_EQ(Range.range.Mode, QUIC_RANGE_MODE_TIERED);
    const uint32_t PeakAllocatedBytes =
        QuicRangeTieredGetAllocatedBytes(Range.range.Tiered);

    // Collapse to one active block and verify excess allocations are reclaimed.
    (void)QuicRangeRemoveSubranges(
        &Range.range,
        QUIC_RANGE_TIERED_BLOCK_CAPACITY,
        Range.ValidCount() -
            QUIC_RANGE_TIERED_BLOCK_CAPACITY);
    ASSERT_EQ(Range.range.Mode, QUIC_RANGE_MODE_TIERED);
    ASSERT_LT(
        QuicRangeTieredGetAllocatedBytes(Range.range.Tiered),
        PeakAllocatedBytes);

    // Remove one front record to advance the circular start before demotion.
    (void)QuicRangeRemoveSubranges(
        &Range.range,
        0,
        1);
    ASSERT_EQ(Range.range.Mode, QUIC_RANGE_MODE_TIERED);

    std::vector<QUIC_SUBRANGE> ExpectedInline(
        QUIC_RANGE_INITIAL_SUB_COUNT);
    for (uint32_t i = 0;
         i < QUIC_RANGE_INITIAL_SUB_COUNT;
         ++i) {
        ExpectedInline[i] = *QuicRangeGet(&Range.range, i);
    }

    // Collapse to inline capacity and verify every surviving record is copied.
    (void)QuicRangeRemoveSubranges(
        &Range.range,
        QUIC_RANGE_INITIAL_SUB_COUNT,
        Range.ValidCount() - QUIC_RANGE_INITIAL_SUB_COUNT);
    ASSERT_EQ(Range.range.Mode, QUIC_RANGE_MODE_ARRAY);
    ASSERT_EQ(Range.range.AllowedModes, TieredModes);
    ValidateModePolicy(Range.range);
    ASSERT_EQ(
        Range.range.Array.SubRanges,
        Range.range.Array.PreAllocSubRanges);
    ASSERT_EQ(
        Range.ValidCount(),
        QUIC_RANGE_INITIAL_SUB_COUNT);
    for (uint32_t i = 0;
         i < QUIC_RANGE_INITIAL_SUB_COUNT;
         ++i) {
        const QUIC_SUBRANGE* Sub = QuicRangeGet(&Range.range, i);
        ASSERT_EQ(Sub->Low, ExpectedInline[i].Low);
        ASSERT_EQ(Sub->Count, ExpectedInline[i].Count);
    }

    // Grow through the array threshold again and verify repromotion still works.
    uint64_t NextLow =
        ExpectedInline.back().Low + 2;
    const uint32_t RegrowCount =
        QUIC_RANGE_TIERED_PROMOTE_LENGTH -
            QUIC_RANGE_INITIAL_SUB_COUNT;
    for (uint32_t i = 0; i < RegrowCount; ++i) {
        ASSERT_TRUE(Range.TryAdd(NextLow));
        NextLow += 2;
    }
    ASSERT_EQ(Range.range.Mode, QUIC_RANGE_MODE_ARRAY);
    ASSERT_EQ(
        Range.ValidCount(),
        QUIC_RANGE_TIERED_PROMOTE_LENGTH);

    ASSERT_TRUE(Range.TryAdd(NextLow));
    ASSERT_EQ(Range.range.Mode, QUIC_RANGE_MODE_TIERED);
    ASSERT_EQ(Range.range.AllowedModes, TieredModes);
    ValidateModePolicy(Range.range);

    Range.Reset();
    ASSERT_EQ(Range.range.Mode, QUIC_RANGE_MODE_ARRAY);
    ASSERT_EQ(Range.range.AllowedModes, TieredModes);
    ASSERT_EQ(Range.ValidCount(), 0u);
    ASSERT_EQ(
        Range.range.Array.SubRanges,
        Range.range.Array.PreAllocSubRanges);
    ASSERT_EQ(
        Range.range.Array.AllocLength,
        QUIC_RANGE_INITIAL_SUB_COUNT);

    // Public reset returns inline; a fresh sequence can promote normally.
    for (uint32_t i = 0;
         i < QUIC_RANGE_TIERED_PROMOTE_LENGTH;
         ++i) {
        Range.Add(2ULL * i);
    }
    ASSERT_EQ(Range.range.Mode, QUIC_RANGE_MODE_ARRAY);
    ASSERT_TRUE(
        Range.TryAdd(
            2ULL * QUIC_RANGE_TIERED_PROMOTE_LENGTH));
    ASSERT_EQ(Range.range.Mode, QUIC_RANGE_MODE_TIERED);
    ASSERT_EQ(Range.range.AllowedModes, TieredModes);
    ValidateModePolicy(Range.range);
}

//
// Fills a maximum-budget tiered range to 65,280 subranges and verifies that
// another insertion fails without changing its contents or exceeding 1 MiB.
//
TEST(RangeTest, TieredExactCapacity)
{
    SmartRange Range(
        QUIC_MAX_RANGE_ALLOC_SIZE,
        TieredModes);
    const uint32_t ExpectedCapacity =
        (QUIC_RANGE_TIERED_DIRECTORY_CAPACITY - 1) *
            QUIC_RANGE_TIERED_BLOCK_CAPACITY;
    // Descending values force front insertion until the strict capacity is reached.
    for (uint32_t i = 0; i < ExpectedCapacity; ++i) {
        ASSERT_TRUE(
            Range.TryAdd(
                2ULL * (ExpectedCapacity - i)));
    }

    ASSERT_EQ(Range.ValidCount(), ExpectedCapacity);
    ASSERT_EQ(Range.range.Mode, QUIC_RANGE_MODE_TIERED);
    ASSERT_EQ(
        QuicRangeTieredGetCapacity(Range.range.Tiered),
        ExpectedCapacity);
    ASSERT_LE(
        QuicRangeTieredGetAllocatedBytes(Range.range.Tiered),
        QUIC_MAX_RANGE_ALLOC_SIZE);
    ValidateSequentialSingletonRanges(
        Range.range,
        ExpectedCapacity);

    ASSERT_FALSE(Range.TryAdd(0));
    ValidateSequentialSingletonRanges(
        Range.range,
        ExpectedCapacity);

    ASSERT_FALSE(
        Range.TryAdd(
            2ULL * (ExpectedCapacity + 1)));
    ValidateSequentialSingletonRanges(
        Range.range,
        ExpectedCapacity);
}

//
// Sends disjoint acknowledgements through QuicStreamOnAck() and verifies that
// the stream's sparse ACK range switches to tiered storage at 257 entries.
//
TEST(RangeTest, TieredStreamAckPromotesAfterArrayThreshold)
{
    QUIC_STREAM Stream = {};
    // Tiered: this test exercises promotion at 257 subranges.
    QuicRangeInitialize(
        QUIC_MAX_RANGE_ALLOC_SIZE,
        TieredModes,
        &Stream.SparseAckRanges);
    Stream.Flags.SendOpenAcked = TRUE;
    Stream.QueuedSendOffset =
        2ULL * (QUIC_RANGE_TIERED_PROMOTE_LENGTH + 2);
    Stream.MaxSentLength = Stream.QueuedSendOffset;

    QUIC_SEND_PACKET_FLAGS PacketFlags = {};
    PacketFlags.KeyType = QUIC_PACKET_KEY_1_RTT;
    QUIC_SENT_FRAME_METADATA FrameMetadata = {};
    FrameMetadata.StreamLength = 1;

    for (uint32_t i = 0;
         i < QUIC_RANGE_TIERED_PROMOTE_LENGTH;
         ++i) {
        FrameMetadata.StreamOffset = 2ULL * (i + 1);
        QuicStreamOnAck(
            &Stream,
            PacketFlags,
            &FrameMetadata);
    }
    ASSERT_EQ(
        Stream.SparseAckRanges.Mode,
        QUIC_RANGE_MODE_ARRAY);
    ASSERT_EQ(
        Stream.SparseAckRanges.AllowedModes,
        TieredModes);
    ValidateModePolicy(Stream.SparseAckRanges);

    FrameMetadata.StreamOffset =
        2ULL * (QUIC_RANGE_TIERED_PROMOTE_LENGTH + 1);
    QuicStreamOnAck(
        &Stream,
        PacketFlags,
        &FrameMetadata);
    ASSERT_EQ(
        Stream.SparseAckRanges.Mode,
        QUIC_RANGE_MODE_TIERED);
    ASSERT_EQ(
        Stream.SparseAckRanges.AllowedModes,
        TieredModes);
    ValidateModePolicy(Stream.SparseAckRanges);
    ASSERT_EQ(
        QuicRangeSize(&Stream.SparseAckRanges),
        QUIC_RANGE_TIERED_PROMOTE_LENGTH + 1);

    QuicRangeUninitialize(&Stream.SparseAckRanges);
}

TEST(RangeTest, SearchZero)
{
    SmartRange range;
    auto index = range.Find(25);
    ASSERT_TRUE(IS_INSERT_INDEX(index));
    ASSERT_EQ(INSERT_INDEX_TO_FIND_INDEX(index), 0ul);
}

TEST(RangeTest, SearchOne)
{
    SmartRange range;
    range.Add(25);

    auto index = range.Find(27);
    ASSERT_TRUE(IS_INSERT_INDEX(index));
    ASSERT_EQ(INSERT_INDEX_TO_FIND_INDEX(index), 1ul);
    index = range.Find(26);
    ASSERT_TRUE(IS_INSERT_INDEX(index));
    ASSERT_EQ(INSERT_INDEX_TO_FIND_INDEX(index), 1ul);
    index = range.Find(24);
    ASSERT_TRUE(IS_INSERT_INDEX(index));
    ASSERT_EQ(INSERT_INDEX_TO_FIND_INDEX(index), 0ul);
    index = range.Find(23);
    ASSERT_TRUE(IS_INSERT_INDEX(index));
    ASSERT_EQ(INSERT_INDEX_TO_FIND_INDEX(index), 0ul);

    index = range.Find(25);
    ASSERT_TRUE(IS_FIND_INDEX(index));
    ASSERT_EQ(index, 0);
}

TEST(RangeTest, SearchTwo)
{
    SmartRange range;
    range.Add(25);
    range.Add(27);

    auto index = range.Find(28);
    ASSERT_TRUE(IS_INSERT_INDEX(index));
    ASSERT_EQ(INSERT_INDEX_TO_FIND_INDEX(index), 2ul);
    index = range.Find(26);
    ASSERT_TRUE(IS_INSERT_INDEX(index));
    ASSERT_EQ(INSERT_INDEX_TO_FIND_INDEX(index), 1ul);
    index = range.Find(24);
    ASSERT_TRUE(IS_INSERT_INDEX(index));
    ASSERT_EQ(INSERT_INDEX_TO_FIND_INDEX(index), 0ul);

    index = range.Find(27);
    ASSERT_TRUE(IS_FIND_INDEX(index));
    ASSERT_EQ(index, 1);
    index = range.Find(25);
    ASSERT_TRUE(IS_FIND_INDEX(index));
    ASSERT_EQ(index, 0);
}

TEST(RangeTest, SearchThree)
{
    SmartRange range;
    range.Add(25);
    range.Add(27);
    range.Add(29);

    auto index = range.Find(30);
    ASSERT_TRUE(IS_INSERT_INDEX(index));
    ASSERT_EQ(INSERT_INDEX_TO_FIND_INDEX(index), 3ul);
    index = range.Find(28);
    ASSERT_TRUE(IS_INSERT_INDEX(index));
    ASSERT_EQ(INSERT_INDEX_TO_FIND_INDEX(index), 2ul);
    index = range.Find(26);
    ASSERT_TRUE(IS_INSERT_INDEX(index));
    ASSERT_EQ(INSERT_INDEX_TO_FIND_INDEX(index), 1ul);
    index = range.Find(24);
    ASSERT_TRUE(IS_INSERT_INDEX(index));
    ASSERT_EQ(INSERT_INDEX_TO_FIND_INDEX(index), 0ul);

    index = range.Find(29);
    ASSERT_TRUE(IS_FIND_INDEX(index));
    ASSERT_EQ(index, 2);
    index = range.Find(27);
    ASSERT_TRUE(IS_FIND_INDEX(index));
    ASSERT_EQ(index, 1);
    index = range.Find(25);
    ASSERT_TRUE(IS_FIND_INDEX(index));
    ASSERT_EQ(index, 0);
}

TEST(RangeTest, SearchFour)
{
    SmartRange range;
    range.Add(25);
    range.Add(27);
    range.Add(29);
    range.Add(31);

    auto index = range.Find(32);
    ASSERT_TRUE(IS_INSERT_INDEX(index));
    ASSERT_EQ(INSERT_INDEX_TO_FIND_INDEX(index), 4ul);
    index = range.Find(30);
    ASSERT_TRUE(IS_INSERT_INDEX(index));
    ASSERT_EQ(INSERT_INDEX_TO_FIND_INDEX(index), 3ul);
    index = range.Find(28);
    ASSERT_TRUE(IS_INSERT_INDEX(index));
    ASSERT_EQ(INSERT_INDEX_TO_FIND_INDEX(index), 2ul);
    index = range.Find(26);
    ASSERT_TRUE(IS_INSERT_INDEX(index));
    ASSERT_EQ(INSERT_INDEX_TO_FIND_INDEX(index), 1ul);
    index = range.Find(24);
    ASSERT_TRUE(IS_INSERT_INDEX(index));
    ASSERT_EQ(INSERT_INDEX_TO_FIND_INDEX(index), 0ul);

    index = range.Find(29);
    ASSERT_TRUE(IS_FIND_INDEX(index));
    ASSERT_EQ(index, 2);
    index = range.Find(27);
    ASSERT_TRUE(IS_FIND_INDEX(index));
    ASSERT_EQ(index, 1);
    index = range.Find(25);
    ASSERT_TRUE(IS_FIND_INDEX(index));
    ASSERT_EQ(index, 0);
}

TEST(RangeTest, SearchRangeZero)
{
    SmartRange range;
    auto index = range.FindRange(25, 17);
    ASSERT_TRUE(IS_INSERT_INDEX(index));
    ASSERT_EQ(INSERT_INDEX_TO_FIND_INDEX(index), 0ul);
}

TEST(RangeTest, SearchRangeOne)
{
    SmartRange range;
    range.Add(25);

    auto index = range.FindRange(27, 3);
    ASSERT_TRUE(IS_INSERT_INDEX(index));
    ASSERT_EQ(INSERT_INDEX_TO_FIND_INDEX(index), 1ul);
    index = range.FindRange(26, 3);
    ASSERT_TRUE(IS_INSERT_INDEX(index));
    ASSERT_EQ(INSERT_INDEX_TO_FIND_INDEX(index), 1ul);
    index = range.FindRange(22, 3);
    ASSERT_TRUE(IS_INSERT_INDEX(index));
    ASSERT_EQ(INSERT_INDEX_TO_FIND_INDEX(index), 0ul);
    index = range.FindRange(21, 3);
    ASSERT_TRUE(IS_INSERT_INDEX(index));
    ASSERT_EQ(INSERT_INDEX_TO_FIND_INDEX(index), 0ul);

    index = range.FindRange(23, 3);
    ASSERT_TRUE(IS_FIND_INDEX(index));
    ASSERT_EQ(index, 0);
    index = range.FindRange(24, 3);
    ASSERT_TRUE(IS_FIND_INDEX(index));
    ASSERT_EQ(index, 0);
    index = range.FindRange(25, 3);
    ASSERT_TRUE(IS_FIND_INDEX(index));
    ASSERT_EQ(index, 0);
}

TEST(RangeTest, SearchRangeTwo)
{
    SmartRange range;
    range.Add(25);
    range.Add(30);

    auto index = range.FindRange(32, 3);
    ASSERT_TRUE(IS_INSERT_INDEX(index));
    ASSERT_EQ(INSERT_INDEX_TO_FIND_INDEX(index), 2ul);
    index = range.FindRange(31, 3);
    ASSERT_TRUE(IS_INSERT_INDEX(index));
    ASSERT_EQ(INSERT_INDEX_TO_FIND_INDEX(index), 2ul);
    index = range.FindRange(26, 2);
    ASSERT_TRUE(IS_INSERT_INDEX(index));
    ASSERT_EQ(INSERT_INDEX_TO_FIND_INDEX(index), 1ul);
    index = range.FindRange(27, 2);
    ASSERT_TRUE(IS_INSERT_INDEX(index));
    ASSERT_EQ(INSERT_INDEX_TO_FIND_INDEX(index), 1ul);
    index = range.FindRange(28, 2);
    ASSERT_TRUE(IS_INSERT_INDEX(index));
    ASSERT_EQ(INSERT_INDEX_TO_FIND_INDEX(index), 1ul);
    index = range.FindRange(22, 2);
    ASSERT_TRUE(IS_INSERT_INDEX(index));
    ASSERT_EQ(INSERT_INDEX_TO_FIND_INDEX(index), 0ul);
    index = range.FindRange(23, 2);
    ASSERT_TRUE(IS_INSERT_INDEX(index));
    ASSERT_EQ(INSERT_INDEX_TO_FIND_INDEX(index), 0ul);

    index = range.FindRange(24, 2);
    ASSERT_TRUE(IS_FIND_INDEX(index));
    ASSERT_EQ(index, 0);
    index = range.FindRange(24, 3);
    ASSERT_TRUE(IS_FIND_INDEX(index));
    ASSERT_EQ(index, 0);
    index = range.FindRange(25, 2);
    ASSERT_TRUE(IS_FIND_INDEX(index));
    ASSERT_EQ(index, 0);
    index = range.FindRange(29, 2);
    ASSERT_TRUE(IS_FIND_INDEX(index));
    ASSERT_EQ(index, 1);
    index = range.FindRange(29, 3);
    ASSERT_TRUE(IS_FIND_INDEX(index));
    ASSERT_EQ(index, 1);
    index = range.FindRange(30, 2);
    ASSERT_TRUE(IS_FIND_INDEX(index));
    ASSERT_EQ(index, 1);

    index = range.FindRange(24, 7);
    ASSERT_TRUE(IS_FIND_INDEX(index));
#if QUIC_RANGE_USE_BINARY_SEARCH
    ASSERT_EQ(index, 0);
#else
    ASSERT_EQ(index, 1);
#endif
    index = range.FindRange(25, 6);
    ASSERT_TRUE(IS_FIND_INDEX(index));
#if QUIC_RANGE_USE_BINARY_SEARCH
    ASSERT_EQ(index, 0);
#else
    ASSERT_EQ(index, 1);
#endif
}

TEST(RangeTest, SearchRangeThree)
{
    SmartRange range;
    range.Add(25);
    range.Add(30);
    range.Add(35);

    auto index = range.FindRange(36, 3);
    ASSERT_TRUE(IS_INSERT_INDEX(index));
    ASSERT_EQ(INSERT_INDEX_TO_FIND_INDEX(index), 3ul);
    index = range.FindRange(32, 3);
    ASSERT_TRUE(IS_INSERT_INDEX(index));
    ASSERT_EQ(INSERT_INDEX_TO_FIND_INDEX(index), 2ul);
    index = range.FindRange(31, 3);
    ASSERT_TRUE(IS_INSERT_INDEX(index));
    ASSERT_EQ(INSERT_INDEX_TO_FIND_INDEX(index), 2ul);
    index = range.FindRange(26, 2);
    ASSERT_TRUE(IS_INSERT_INDEX(index));
    ASSERT_EQ(INSERT_INDEX_TO_FIND_INDEX(index), 1ul);
    index = range.FindRange(27, 2);
    ASSERT_TRUE(IS_INSERT_INDEX(index));
    ASSERT_EQ(INSERT_INDEX_TO_FIND_INDEX(index), 1ul);
    index = range.FindRange(28, 2);
    ASSERT_TRUE(IS_INSERT_INDEX(index));
    ASSERT_EQ(INSERT_INDEX_TO_FIND_INDEX(index), 1ul);
    index = range.FindRange(22, 2);
    ASSERT_TRUE(IS_INSERT_INDEX(index));
    ASSERT_EQ(INSERT_INDEX_TO_FIND_INDEX(index), 0ul);
    index = range.FindRange(23, 2);
    ASSERT_TRUE(IS_INSERT_INDEX(index));
    ASSERT_EQ(INSERT_INDEX_TO_FIND_INDEX(index), 0ul);

    index = range.FindRange(24, 2);
    ASSERT_TRUE(IS_FIND_INDEX(index));
    ASSERT_EQ(index, 0);
    index = range.FindRange(24, 3);
    ASSERT_TRUE(IS_FIND_INDEX(index));
    ASSERT_EQ(index, 0);
    index = range.FindRange(25, 2);
    ASSERT_TRUE(IS_FIND_INDEX(index));
    ASSERT_EQ(index, 0);
    index = range.FindRange(29, 2);
    ASSERT_TRUE(IS_FIND_INDEX(index));
    ASSERT_EQ(index, 1);
    index = range.FindRange(29, 3);
    ASSERT_TRUE(IS_FIND_INDEX(index));
    ASSERT_EQ(index, 1);
    index = range.FindRange(30, 2);
    ASSERT_TRUE(IS_FIND_INDEX(index));
    ASSERT_EQ(index, 1);

    index = range.FindRange(24, 7);
    ASSERT_TRUE(IS_FIND_INDEX(index));
    ASSERT_EQ(index, 1);
    index = range.FindRange(25, 6);
    ASSERT_TRUE(IS_FIND_INDEX(index));
    ASSERT_EQ(index, 1);

    index = range.FindRange(29, 7);
    ASSERT_TRUE(IS_FIND_INDEX(index));
#if QUIC_RANGE_USE_BINARY_SEARCH
    ASSERT_EQ(index, 1);
#else
    ASSERT_EQ(index, 2);
#endif
    index = range.FindRange(30, 6);
    ASSERT_TRUE(IS_FIND_INDEX(index));
#if QUIC_RANGE_USE_BINARY_SEARCH
    ASSERT_EQ(index, 1);
#else
    ASSERT_EQ(index, 2);
#endif

    index = range.FindRange(24, 12);
    ASSERT_TRUE(IS_FIND_INDEX(index));
#if QUIC_RANGE_USE_BINARY_SEARCH
    ASSERT_EQ(index, 1);
#else
    ASSERT_EQ(index, 2);
#endif
    index = range.FindRange(25, 11);
    ASSERT_TRUE(IS_FIND_INDEX(index));
#if QUIC_RANGE_USE_BINARY_SEARCH
    ASSERT_EQ(index, 1);
#else
    ASSERT_EQ(index, 2);
#endif
}

//
// Verifies containing-or-next lookup at overlaps, gaps, large indices, and the end.
//
TEST(RangeTest, FindContainingOrNext)
{
    SmartRange Range;
    for (uint32_t i = 0; i < 1024; ++i) {
        Range.Add(4ULL * i, 2);
    }

    ASSERT_EQ(Range.FindContainingOrNext(0), 0u);
    ASSERT_EQ(Range.FindContainingOrNext(1), 0u);
    ASSERT_EQ(Range.FindContainingOrNext(2), 1u);
    ASSERT_EQ(Range.FindContainingOrNext(1023), 256u);
    ASSERT_EQ(Range.FindContainingOrNext(2047), 512u);
    ASSERT_EQ(Range.FindContainingOrNext(4093), 1023u);
    ASSERT_EQ(Range.FindContainingOrNext(4094), 1024u);
}
