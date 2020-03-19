/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.

Abstract:

    Unit test for the QUIC_RANGE multirange tracker interface.

--*/

#include "main.h"
#include "RangeTest.cpp.clog"

struct SmartRange {
    QUIC_RANGE range;
    SmartRange(uint32_t MaxAllocSize = QUIC_MAX_RANGE_ALLOC_SIZE) {
        QuicRangeInitialize(MaxAllocSize, &range);
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
        TEST_TRUE(TryAdd(value));
    #ifndef LOG_ONLY_FAILURES
        Dump();
    #endif
    }
    void Add(uint64_t low, uint64_t count) {
        TEST_TRUE(TryAdd(low, count));
    #ifndef LOG_ONLY_FAILURES
        Dump();
    #endif
    }
    void Remove(uint64_t low, uint64_t count) {
        TEST_TRUE(QuicRangeRemoveRange(&range, low, count));
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

TEST(RangeTest, AddSingle)
{
    SmartRange range;
    range.Add(100);
    TEST_EQUAL(range.ValidCount(), (uint32_t)1);
    TEST_EQUAL(range.Min(), (uint32_t)100);
    TEST_EQUAL(range.Max(), (uint32_t)100);
}

TEST(RangeTest, AddTwoAdjacentBefore)
{
    SmartRange range;
    range.Add(101);
    range.Add(100);
    TEST_EQUAL(range.ValidCount(), (uint32_t)1);
    TEST_EQUAL(range.Min(), (uint32_t)100);
    TEST_EQUAL(range.Max(), (uint32_t)101);
}

TEST(RangeTest, AddTwoAdjacentAfter)
{
    SmartRange range;
    range.Add(100);
    range.Add(101);
    TEST_EQUAL(range.ValidCount(), (uint32_t)1);
    TEST_EQUAL(range.Min(), (uint32_t)100);
    TEST_EQUAL(range.Max(), (uint32_t)101);
}

TEST(RangeTest, AddTwoSeparateBefore)
{
    SmartRange range;
    range.Add(102);
    range.Add(100);
    TEST_EQUAL(range.ValidCount(), (uint32_t)2);
    TEST_EQUAL(range.Min(), (uint32_t)100);
    TEST_EQUAL(range.Max(), (uint32_t)102);
}

TEST(RangeTest, AddTwoSeparateAfter)
{
    SmartRange range;
    range.Add(100);
    range.Add(102);
    TEST_EQUAL(range.ValidCount(), (uint32_t)2);
    TEST_EQUAL(range.Min(), (uint32_t)100);
    TEST_EQUAL(range.Max(), (uint32_t)102);
}

TEST(RangeTest, AddThreeMerge)
{
    SmartRange range;
    range.Add(100);
    range.Add(102);
    range.Add(101);
    TEST_EQUAL(range.ValidCount(), (uint32_t)1);
    TEST_EQUAL(range.Min(), (uint32_t)100);
    TEST_EQUAL(range.Max(), (uint32_t)102);
}

TEST(RangeTest, AddBetween)
{
    SmartRange range;
    range.Add(100);
    range.Add(104);
    range.Add(102);
    TEST_EQUAL(range.ValidCount(), (uint32_t)3);
    TEST_EQUAL(range.Min(), (uint32_t)100);
    TEST_EQUAL(range.Max(), (uint32_t)104);
}

TEST(RangeTest, AddRangeSingle)
{
    SmartRange range;
    range.Add(100, 100);
    TEST_EQUAL(range.ValidCount(), (uint32_t)1);
    TEST_EQUAL(range.Min(), (uint32_t)100);
    TEST_EQUAL(range.Max(), (uint32_t)199);
}

TEST(RangeTest, AddRangeBetween)
{
    SmartRange range;
    range.Add(100, 50);
    range.Add(300, 50);
    range.Add(200, 50);
    TEST_EQUAL(range.ValidCount(), (uint32_t)3);
    TEST_EQUAL(range.Min(), (uint32_t)100);
    TEST_EQUAL(range.Max(), (uint32_t)349);
}

TEST(RangeTest, AddRangeTwoAdjacentBefore)
{
    SmartRange range;
    range.Add(200, 100);
    range.Add(100, 100);
    TEST_EQUAL(range.ValidCount(), (uint32_t)1);
    TEST_EQUAL(range.Min(), (uint32_t)100);
    TEST_EQUAL(range.Max(), (uint32_t)299);
}

TEST(RangeTest, AddRangeTwoAdjacentAfter)
{
    SmartRange range;
    range.Add(100, 100);
    range.Add(200, 100);
    TEST_EQUAL(range.ValidCount(), (uint32_t)1);
    TEST_EQUAL(range.Min(), (uint32_t)100);
    TEST_EQUAL(range.Max(), (uint32_t)299);
}

TEST(RangeTest, AddRangeTwoSeparateBefore)
{
    SmartRange range;
    range.Add(300, 100);
    range.Add(100, 100);
    TEST_EQUAL(range.ValidCount(), (uint32_t)2);
    TEST_EQUAL(range.Min(), (uint32_t)100);
    TEST_EQUAL(range.Max(), (uint32_t)399);
}

TEST(RangeTest, AddRangeTwoSeparateAfter)
{
    SmartRange range;
    range.Add(100, 100);
    range.Add(300, 100);
    TEST_EQUAL(range.ValidCount(), (uint32_t)2);
    TEST_EQUAL(range.Min(), (uint32_t)100);
    TEST_EQUAL(range.Max(), (uint32_t)399);
}

TEST(RangeTest, AddRangeTwoOverlapBefore1)
{
    SmartRange range;
    range.Add(200, 100);
    range.Add(100, 150);
    TEST_EQUAL(range.ValidCount(), (uint32_t)1);
    TEST_EQUAL(range.Min(), (uint32_t)100);
    TEST_EQUAL(range.Max(), (uint32_t)299);
}

TEST(RangeTest, AddRangeTwoOverlapBefore2)
{
    SmartRange range;
    range.Add(200, 100);
    range.Add(100, 200);
    TEST_EQUAL(range.ValidCount(), (uint32_t)1);
    TEST_EQUAL(range.Min(), (uint32_t)100);
    TEST_EQUAL(range.Max(), (uint32_t)299);
}

TEST(RangeTest, AddRangeTwoOverlapBefore3)
{
    SmartRange range;
    range.Add(200, 50);
    range.Add(100, 200);
    TEST_EQUAL(range.ValidCount(), (uint32_t)1);
    TEST_EQUAL(range.Min(), (uint32_t)100);
    TEST_EQUAL(range.Max(), (uint32_t)299);
}

TEST(RangeTest, AddRangeTwoOverlapAfter1)
{
    SmartRange range;
    range.Add(100, 100);
    range.Add(150, 150);
    TEST_EQUAL(range.ValidCount(), (uint32_t)1);
    TEST_EQUAL(range.Min(), (uint32_t)100);
    TEST_EQUAL(range.Max(), (uint32_t)299);
}

TEST(RangeTest, AddRangeTwoOverlapAfter2)
{
    SmartRange range;
    range.Add(100, 100);
    range.Add(100, 200);
    TEST_EQUAL(range.ValidCount(), (uint32_t)1);
    TEST_EQUAL(range.Min(), (uint32_t)100);
    TEST_EQUAL(range.Max(), (uint32_t)299);
}

TEST(RangeTest, AddRangeThreeMerge)
{
    SmartRange range;
    range.Add(100, 100);
    range.Add(300, 100);
    range.Add(200, 100);
    TEST_EQUAL(range.ValidCount(), (uint32_t)1);
    TEST_EQUAL(range.Min(), (uint32_t)100);
    TEST_EQUAL(range.Max(), (uint32_t)399);
}

TEST(RangeTest, AddRangeThreeOverlapAndAdjacentAfter1)
{
    SmartRange range;
    range.Add(100, 1);
    range.Add(200, 100);
    range.Add(101, 150);
    TEST_EQUAL(range.ValidCount(), (uint32_t)1);
    TEST_EQUAL(range.Min(), (uint32_t)100);
    TEST_EQUAL(range.Max(), (uint32_t)299);
}

TEST(RangeTest, AddRangeThreeOverlapAndAdjacentAfter2)
{
    SmartRange range;
    range.Add(100, 1);
    range.Add(200, 100);
    range.Add(101, 299);
    TEST_EQUAL(range.ValidCount(), (uint32_t)1);
    TEST_EQUAL(range.Min(), (uint32_t)100);
    TEST_EQUAL(range.Max(), (uint32_t)399);
}

TEST(RangeTest, AddRangeThreeOverlapAndAdjacentAfter3)
{
    SmartRange range;
    range.Add(100, 100);
    range.Add(300, 100);
    range.Add(150, 150);
    TEST_EQUAL(range.ValidCount(), (uint32_t)1);
    TEST_EQUAL(range.Min(), (uint32_t)100);
    TEST_EQUAL(range.Max(), (uint32_t)399);
}

TEST(RangeTest, AddRangeThreeOverlapAndAdjacentAfter4)
{
    SmartRange range;
    range.Add(100, 100);
    range.Add(300, 100);
    range.Add(50, 250);
    TEST_EQUAL(range.ValidCount(), (uint32_t)1);
    TEST_EQUAL(range.Min(), (uint32_t)50);
    TEST_EQUAL(range.Max(), (uint32_t)399);
}

TEST(RangeTest, RemoveRangeBefore)
{
    SmartRange range;
    range.Add(100, 100);
    TEST_EQUAL(range.ValidCount(), (uint32_t)1);
    TEST_EQUAL(range.Min(), (uint32_t)100);
    TEST_EQUAL(range.Max(), (uint32_t)199);
    range.Remove(0, 99);
    TEST_EQUAL(range.ValidCount(), (uint32_t)1);
    TEST_EQUAL(range.Min(), (uint32_t)100);
    TEST_EQUAL(range.Max(), (uint32_t)199);
    range.Remove(0, 100);
    TEST_EQUAL(range.ValidCount(), (uint32_t)1);
    TEST_EQUAL(range.Min(), (uint32_t)100);
    TEST_EQUAL(range.Max(), (uint32_t)199);
}

TEST(RangeTest, RemoveRangeAfter)
{
    SmartRange range;
    range.Add(100, 100);
    TEST_EQUAL(range.ValidCount(), (uint32_t)1);
    TEST_EQUAL(range.Min(), (uint32_t)100);
    TEST_EQUAL(range.Max(), (uint32_t)199);
    range.Remove(201, 99);
    TEST_EQUAL(range.ValidCount(), (uint32_t)1);
    TEST_EQUAL(range.Min(), (uint32_t)100);
    TEST_EQUAL(range.Max(), (uint32_t)199);
    range.Remove(200, 100);
    TEST_EQUAL(range.ValidCount(), (uint32_t)1);
    TEST_EQUAL(range.Min(), (uint32_t)100);
    TEST_EQUAL(range.Max(), (uint32_t)199);
}

TEST(RangeTest, RemoveRangeFront)
{
    SmartRange range;
    range.Add(100, 100);
    TEST_EQUAL(range.ValidCount(), (uint32_t)1);
    TEST_EQUAL(range.Min(), (uint32_t)100);
    TEST_EQUAL(range.Max(), (uint32_t)199);
    range.Remove(100, 20);
    TEST_EQUAL(range.ValidCount(), (uint32_t)1);
    TEST_EQUAL(range.Min(), (uint32_t)120);
    TEST_EQUAL(range.Max(), (uint32_t)199);
}

TEST(RangeTest, RemoveRangeBack)
{
    SmartRange range;
    range.Add(100, 100);
    TEST_EQUAL(range.ValidCount(), (uint32_t)1);
    TEST_EQUAL(range.Min(), (uint32_t)100);
    TEST_EQUAL(range.Max(), (uint32_t)199);
    range.Remove(180, 20);
    TEST_EQUAL(range.ValidCount(), (uint32_t)1);
    TEST_EQUAL(range.Min(), (uint32_t)100);
    TEST_EQUAL(range.Max(), (uint32_t)179);
}

TEST(RangeTest, RemoveRangeAll)
{
    SmartRange range;
    range.Add(100, 100);
    TEST_EQUAL(range.ValidCount(), (uint32_t)1);
    TEST_EQUAL(range.Min(), (uint32_t)100);
    TEST_EQUAL(range.Max(), (uint32_t)199);
    range.Remove(100, 100);
    TEST_EQUAL(range.ValidCount(), (uint32_t)0);
}

TEST(RangeTest, ExampleAckTest)
{
    SmartRange range;
    range.Add(10000);
    range.Add(10001);
    range.Add(10003);
    range.Add(10002);
    TEST_EQUAL(range.ValidCount(), (uint32_t)1);
    range.Remove(10000, 2);
    TEST_EQUAL(range.ValidCount(), (uint32_t)1);
    range.Remove(10000, 4);
    TEST_EQUAL(range.ValidCount(), (uint32_t)0);
    range.Add(10005);
    range.Add(10006);
    range.Add(10004);
    range.Add(10007);
    TEST_EQUAL(range.ValidCount(), (uint32_t)1);
    range.Remove(10005, 2);
    TEST_EQUAL(range.ValidCount(), (uint32_t)2);
    range.Remove(10004, 1);
    TEST_EQUAL(range.ValidCount(), (uint32_t)1);
    range.Remove(10007, 1);
    TEST_EQUAL(range.ValidCount(), (uint32_t)0);
}

TEST(RangeTest, ExampleAckWithLossTest)
{
    SmartRange range;
    range.Add(10000);
    range.Add(10001);
    range.Add(10003);
    TEST_EQUAL(range.ValidCount(), (uint32_t)2);
    range.Add(10002);
    TEST_EQUAL(range.ValidCount(), (uint32_t)1);
    range.Remove(10000, 2);
    range.Remove(10003, 1);
    TEST_EQUAL(range.ValidCount(), (uint32_t)1);
    range.Remove(10002, 1);
    TEST_EQUAL(range.ValidCount(), (uint32_t)0);
    range.Add(10004);
    range.Add(10005);
    range.Add(10006);
    TEST_EQUAL(range.ValidCount(), (uint32_t)1);
    range.Remove(10004, 3);
    TEST_EQUAL(range.ValidCount(), (uint32_t)0);
    range.Add(10008);
    range.Add(10009);
    TEST_EQUAL(range.ValidCount(), (uint32_t)1);
    range.Remove(10008, 2);
    TEST_EQUAL(range.ValidCount(), (uint32_t)0);
}

TEST(RangeTest, AddLots)
{
    SmartRange range;
    for (uint32_t i = 0; i < 400; i += 2) {
        range.Add(i);
    }
    TEST_EQUAL(range.ValidCount(), (uint32_t)200);
    for (uint32_t i = 0; i < 398; i += 2) {
        range.Remove(i, 1);
    }
    TEST_EQUAL(range.ValidCount(), (uint32_t)1);
}

TEST(RangeTest, HitMax)
{
    const uint32_t MaxCount = 16;
    SmartRange range(MaxCount * sizeof(QUIC_SUBRANGE));
    for (uint32_t i = 0; i < MaxCount; i++) {
        range.Add(i*2);
    }
    TEST_EQUAL(range.ValidCount(), MaxCount);
    TEST_EQUAL(range.Min(), 0ull);
    TEST_EQUAL(range.Max(), (MaxCount - 1)*2);
    range.Add(MaxCount*2);
    TEST_EQUAL(range.ValidCount(), MaxCount);
    TEST_EQUAL(range.Min(), 2ull);
    TEST_EQUAL(range.Max(), MaxCount*2);
    range.Remove(2, 1);
    TEST_EQUAL(range.ValidCount(), MaxCount - 1);
    TEST_EQUAL(range.Min(), 4ull);
    TEST_EQUAL(range.Max(), MaxCount*2);
    range.Add(0);
    TEST_EQUAL(range.ValidCount(), MaxCount);
    TEST_EQUAL(range.Min(), 0ull);
    TEST_EQUAL(range.Max(), MaxCount*2);
}

TEST(RangeTest, SearchZero)
{
    SmartRange range;
    auto index = range.Find(25);
    TEST_TRUE(IS_INSERT_INDEX(index));
    TEST_EQUAL(INSERT_INDEX_TO_FIND_INDEX(index), 0ul);
}

TEST(RangeTest, SearchOne)
{
    SmartRange range;
    range.Add(25);

    auto index = range.Find(27);
    TEST_TRUE(IS_INSERT_INDEX(index));
    TEST_EQUAL(INSERT_INDEX_TO_FIND_INDEX(index), 1ul);
    index = range.Find(26);
    TEST_TRUE(IS_INSERT_INDEX(index));
    TEST_EQUAL(INSERT_INDEX_TO_FIND_INDEX(index), 1ul);
    index = range.Find(24);
    TEST_TRUE(IS_INSERT_INDEX(index));
    TEST_EQUAL(INSERT_INDEX_TO_FIND_INDEX(index), 0ul);
    index = range.Find(23);
    TEST_TRUE(IS_INSERT_INDEX(index));
    TEST_EQUAL(INSERT_INDEX_TO_FIND_INDEX(index), 0ul);

    index = range.Find(25);
    TEST_TRUE(IS_FIND_INDEX(index));
    TEST_EQUAL(index, 0);
}

TEST(RangeTest, SearchTwo)
{
    SmartRange range;
    range.Add(25);
    range.Add(27);

    auto index = range.Find(28);
    TEST_TRUE(IS_INSERT_INDEX(index));
    TEST_EQUAL(INSERT_INDEX_TO_FIND_INDEX(index), 2ul);
    index = range.Find(26);
    TEST_TRUE(IS_INSERT_INDEX(index));
    TEST_EQUAL(INSERT_INDEX_TO_FIND_INDEX(index), 1ul);
    index = range.Find(24);
    TEST_TRUE(IS_INSERT_INDEX(index));
    TEST_EQUAL(INSERT_INDEX_TO_FIND_INDEX(index), 0ul);

    index = range.Find(27);
    TEST_TRUE(IS_FIND_INDEX(index));
    TEST_EQUAL(index, 1);
    index = range.Find(25);
    TEST_TRUE(IS_FIND_INDEX(index));
    TEST_EQUAL(index, 0);
}

TEST(RangeTest, SearchThree)
{
    SmartRange range;
    range.Add(25);
    range.Add(27);
    range.Add(29);

    auto index = range.Find(30);
    TEST_TRUE(IS_INSERT_INDEX(index));
    TEST_EQUAL(INSERT_INDEX_TO_FIND_INDEX(index), 3ul);
    index = range.Find(28);
    TEST_TRUE(IS_INSERT_INDEX(index));
    TEST_EQUAL(INSERT_INDEX_TO_FIND_INDEX(index), 2ul);
    index = range.Find(26);
    TEST_TRUE(IS_INSERT_INDEX(index));
    TEST_EQUAL(INSERT_INDEX_TO_FIND_INDEX(index), 1ul);
    index = range.Find(24);
    TEST_TRUE(IS_INSERT_INDEX(index));
    TEST_EQUAL(INSERT_INDEX_TO_FIND_INDEX(index), 0ul);

    index = range.Find(29);
    TEST_TRUE(IS_FIND_INDEX(index));
    TEST_EQUAL(index, 2);
    index = range.Find(27);
    TEST_TRUE(IS_FIND_INDEX(index));
    TEST_EQUAL(index, 1);
    index = range.Find(25);
    TEST_TRUE(IS_FIND_INDEX(index));
    TEST_EQUAL(index, 0);
}

TEST(RangeTest, SearchFour)
{
    SmartRange range;
    range.Add(25);
    range.Add(27);
    range.Add(29);
    range.Add(31);

    auto index = range.Find(32);
    TEST_TRUE(IS_INSERT_INDEX(index));
    TEST_EQUAL(INSERT_INDEX_TO_FIND_INDEX(index), 4ul);
    index = range.Find(30);
    TEST_TRUE(IS_INSERT_INDEX(index));
    TEST_EQUAL(INSERT_INDEX_TO_FIND_INDEX(index), 3ul);
    index = range.Find(28);
    TEST_TRUE(IS_INSERT_INDEX(index));
    TEST_EQUAL(INSERT_INDEX_TO_FIND_INDEX(index), 2ul);
    index = range.Find(26);
    TEST_TRUE(IS_INSERT_INDEX(index));
    TEST_EQUAL(INSERT_INDEX_TO_FIND_INDEX(index), 1ul);
    index = range.Find(24);
    TEST_TRUE(IS_INSERT_INDEX(index));
    TEST_EQUAL(INSERT_INDEX_TO_FIND_INDEX(index), 0ul);

    index = range.Find(29);
    TEST_TRUE(IS_FIND_INDEX(index));
    TEST_EQUAL(index, 2);
    index = range.Find(27);
    TEST_TRUE(IS_FIND_INDEX(index));
    TEST_EQUAL(index, 1);
    index = range.Find(25);
    TEST_TRUE(IS_FIND_INDEX(index));
    TEST_EQUAL(index, 0);
}

TEST(RangeTest, SearchRangeZero)
{
    SmartRange range;
    auto index = range.FindRange(25, 17);
    TEST_TRUE(IS_INSERT_INDEX(index));
    TEST_EQUAL(INSERT_INDEX_TO_FIND_INDEX(index), 0ul);
}

TEST(RangeTest, SearchRangeOne)
{
    SmartRange range;
    range.Add(25);

    auto index = range.FindRange(27, 3);
    TEST_TRUE(IS_INSERT_INDEX(index));
    TEST_EQUAL(INSERT_INDEX_TO_FIND_INDEX(index), 1ul);
    index = range.FindRange(26, 3);
    TEST_TRUE(IS_INSERT_INDEX(index));
    TEST_EQUAL(INSERT_INDEX_TO_FIND_INDEX(index), 1ul);
    index = range.FindRange(22, 3);
    TEST_TRUE(IS_INSERT_INDEX(index));
    TEST_EQUAL(INSERT_INDEX_TO_FIND_INDEX(index), 0ul);
    index = range.FindRange(21, 3);
    TEST_TRUE(IS_INSERT_INDEX(index));
    TEST_EQUAL(INSERT_INDEX_TO_FIND_INDEX(index), 0ul);

    index = range.FindRange(23, 3);
    TEST_TRUE(IS_FIND_INDEX(index));
    TEST_EQUAL(index, 0);
    index = range.FindRange(24, 3);
    TEST_TRUE(IS_FIND_INDEX(index));
    TEST_EQUAL(index, 0);
    index = range.FindRange(25, 3);
    TEST_TRUE(IS_FIND_INDEX(index));
    TEST_EQUAL(index, 0);
}

TEST(RangeTest, SearchRangeTwo)
{
    SmartRange range;
    range.Add(25);
    range.Add(30);

    auto index = range.FindRange(32, 3);
    TEST_TRUE(IS_INSERT_INDEX(index));
    TEST_EQUAL(INSERT_INDEX_TO_FIND_INDEX(index), 2ul);
    index = range.FindRange(31, 3);
    TEST_TRUE(IS_INSERT_INDEX(index));
    TEST_EQUAL(INSERT_INDEX_TO_FIND_INDEX(index), 2ul);
    index = range.FindRange(26, 2);
    TEST_TRUE(IS_INSERT_INDEX(index));
    TEST_EQUAL(INSERT_INDEX_TO_FIND_INDEX(index), 1ul);
    index = range.FindRange(27, 2);
    TEST_TRUE(IS_INSERT_INDEX(index));
    TEST_EQUAL(INSERT_INDEX_TO_FIND_INDEX(index), 1ul);
    index = range.FindRange(28, 2);
    TEST_TRUE(IS_INSERT_INDEX(index));
    TEST_EQUAL(INSERT_INDEX_TO_FIND_INDEX(index), 1ul);
    index = range.FindRange(22, 2);
    TEST_TRUE(IS_INSERT_INDEX(index));
    TEST_EQUAL(INSERT_INDEX_TO_FIND_INDEX(index), 0ul);
    index = range.FindRange(23, 2);
    TEST_TRUE(IS_INSERT_INDEX(index));
    TEST_EQUAL(INSERT_INDEX_TO_FIND_INDEX(index), 0ul);

    index = range.FindRange(24, 2);
    TEST_TRUE(IS_FIND_INDEX(index));
    TEST_EQUAL(index, 0);
    index = range.FindRange(24, 3);
    TEST_TRUE(IS_FIND_INDEX(index));
    TEST_EQUAL(index, 0);
    index = range.FindRange(25, 2);
    TEST_TRUE(IS_FIND_INDEX(index));
    TEST_EQUAL(index, 0);
    index = range.FindRange(29, 2);
    TEST_TRUE(IS_FIND_INDEX(index));
    TEST_EQUAL(index, 1);
    index = range.FindRange(29, 3);
    TEST_TRUE(IS_FIND_INDEX(index));
    TEST_EQUAL(index, 1);
    index = range.FindRange(30, 2);
    TEST_TRUE(IS_FIND_INDEX(index));
    TEST_EQUAL(index, 1);

    index = range.FindRange(24, 7);
    TEST_TRUE(IS_FIND_INDEX(index));
#if QUIC_RANGE_USE_BINARY_SEARCH
    TEST_EQUAL(index, 0);
#else
    TEST_EQUAL(index, 1);
#endif
    index = range.FindRange(25, 6);
    TEST_TRUE(IS_FIND_INDEX(index));
#if QUIC_RANGE_USE_BINARY_SEARCH
    TEST_EQUAL(index, 0);
#else
    TEST_EQUAL(index, 1);
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
    TEST_EQUAL(INSERT_INDEX_TO_FIND_INDEX(index), 3ul);
    index = range.FindRange(32, 3);
    TEST_TRUE(IS_INSERT_INDEX(index));
    TEST_EQUAL(INSERT_INDEX_TO_FIND_INDEX(index), 2ul);
    index = range.FindRange(31, 3);
    TEST_TRUE(IS_INSERT_INDEX(index));
    TEST_EQUAL(INSERT_INDEX_TO_FIND_INDEX(index), 2ul);
    index = range.FindRange(26, 2);
    TEST_TRUE(IS_INSERT_INDEX(index));
    TEST_EQUAL(INSERT_INDEX_TO_FIND_INDEX(index), 1ul);
    index = range.FindRange(27, 2);
    TEST_TRUE(IS_INSERT_INDEX(index));
    TEST_EQUAL(INSERT_INDEX_TO_FIND_INDEX(index), 1ul);
    index = range.FindRange(28, 2);
    TEST_TRUE(IS_INSERT_INDEX(index));
    TEST_EQUAL(INSERT_INDEX_TO_FIND_INDEX(index), 1ul);
    index = range.FindRange(22, 2);
    TEST_TRUE(IS_INSERT_INDEX(index));
    TEST_EQUAL(INSERT_INDEX_TO_FIND_INDEX(index), 0ul);
    index = range.FindRange(23, 2);
    TEST_TRUE(IS_INSERT_INDEX(index));
    TEST_EQUAL(INSERT_INDEX_TO_FIND_INDEX(index), 0ul);

    index = range.FindRange(24, 2);
    TEST_TRUE(IS_FIND_INDEX(index));
    TEST_EQUAL(index, 0);
    index = range.FindRange(24, 3);
    TEST_TRUE(IS_FIND_INDEX(index));
    TEST_EQUAL(index, 0);
    index = range.FindRange(25, 2);
    TEST_TRUE(IS_FIND_INDEX(index));
    TEST_EQUAL(index, 0);
    index = range.FindRange(29, 2);
    TEST_TRUE(IS_FIND_INDEX(index));
    TEST_EQUAL(index, 1);
    index = range.FindRange(29, 3);
    TEST_TRUE(IS_FIND_INDEX(index));
    TEST_EQUAL(index, 1);
    index = range.FindRange(30, 2);
    TEST_TRUE(IS_FIND_INDEX(index));
    TEST_EQUAL(index, 1);

    index = range.FindRange(24, 7);
    TEST_TRUE(IS_FIND_INDEX(index));
    TEST_EQUAL(index, 1);
    index = range.FindRange(25, 6);
    TEST_TRUE(IS_FIND_INDEX(index));
    TEST_EQUAL(index, 1);

    index = range.FindRange(29, 7);
    TEST_TRUE(IS_FIND_INDEX(index));
#if QUIC_RANGE_USE_BINARY_SEARCH
    TEST_EQUAL(index, 1);
#else
    TEST_EQUAL(index, 2);
#endif
    index = range.FindRange(30, 6);
    TEST_TRUE(IS_FIND_INDEX(index));
#if QUIC_RANGE_USE_BINARY_SEARCH
    TEST_EQUAL(index, 1);
#else
    TEST_EQUAL(index, 2);
#endif

    index = range.FindRange(24, 12);
    TEST_TRUE(IS_FIND_INDEX(index));
#if QUIC_RANGE_USE_BINARY_SEARCH
    TEST_EQUAL(index, 1);
#else
    TEST_EQUAL(index, 2);
#endif
    index = range.FindRange(25, 11);
    TEST_TRUE(IS_FIND_INDEX(index));
#if QUIC_RANGE_USE_BINARY_SEARCH
    TEST_EQUAL(index, 1);
#else
    TEST_EQUAL(index, 2);
#endif
}
