/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.

Abstract:

    Unit test for the QUIC_RANGE multirange tracker interface.

--*/

#include "precomp.h"
#define LOG_ONLY_FAILURES
#define INLINE_TEST_METHOD_MARKUP
#include <wextestclass.h>
#include <logcontroller.h>

#include "rangetest.tmh"

using namespace WEX::Logging;
using namespace WEX::Common;

#define VERIFY_QUIC_SUCCESS(result, ...) \
    VERIFY_ARE_EQUAL(QUIC_STATUS_SUCCESS, result, __VA_ARGS__)

struct RangeTest : public WEX::TestClass<RangeTest>
{
    BEGIN_TEST_CLASS(RangeTest)
    END_TEST_CLASS()

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
        bool TryAdd(UINT64 value) {
            return QuicRangeAddValue(&range, value) != FALSE;
        }
        bool TryAdd(UINT64 low, UINT64 count) {
            BOOLEAN rangeUpdated;
            return QuicRangeAddRange(&range, low, count, &rangeUpdated) != FALSE;
        }
        void Add(UINT64 value) {
            VERIFY_IS_TRUE(TryAdd(value));
        #ifndef LOG_ONLY_FAILURES
            Dump();
        #endif
        }
        void Add(UINT64 low, UINT64 count) {
            VERIFY_IS_TRUE(TryAdd(low, count));
        #ifndef LOG_ONLY_FAILURES
            Dump();
        #endif
        }
        void Remove(UINT64 low, UINT64 count) {
            VERIFY_IS_TRUE(QuicRangeRemoveRange(&range, low, count));
        #ifndef LOG_ONLY_FAILURES
            Dump();
        #endif
        }
        int Find(UINT64 value) {
            QUIC_RANGE_SEARCH_KEY Key = { value, value };
            return QuicRangeSearch(&range, &Key);
        }
        int FindRange(UINT64 value, UINT64 count) {
            QUIC_RANGE_SEARCH_KEY Key = { value, value + count - 1 };
            return QuicRangeSearch(&range, &Key);
        }
        UINT64 Min() {
            UINT64 value;
            VERIFY_ARE_EQUAL(TRUE, QuicRangeGetMinSafe(&range, &value));
            return value;
        }
        UINT64 Max() {
            UINT64 value;
            VERIFY_ARE_EQUAL(TRUE, QuicRangeGetMaxSafe(&range, &value));
            return value;
        }
        UINT32 ValidCount() {
            return QuicRangeSize(&range);
        }
        void Dump() {
            Log::Comment(L"== Dump == ");
            for (UINT32 i = 0; i < QuicRangeSize(&range); i++) {
                auto cur = QuicRangeGet(&range, i);
                Log::Comment(
                    String().Format(
                        L"[%llu:%llu]",
                        cur->Low, cur->Count));
            }
        }
    };

    TEST_METHOD(AddSingle)
    {
        SmartRange range;
        range.Add(100);
        VERIFY_ARE_EQUAL(range.ValidCount(), (UINT32)1);
        VERIFY_ARE_EQUAL(range.Min(), (UINT32)100);
        VERIFY_ARE_EQUAL(range.Max(), (UINT32)100);
    }

    TEST_METHOD(AddTwoAdjacentBefore)
    {
        SmartRange range;
        range.Add(101);
        range.Add(100);
        VERIFY_ARE_EQUAL(range.ValidCount(), (UINT32)1);
        VERIFY_ARE_EQUAL(range.Min(), (UINT32)100);
        VERIFY_ARE_EQUAL(range.Max(), (UINT32)101);
    }

    TEST_METHOD(AddTwoAdjacentAfter)
    {
        SmartRange range;
        range.Add(100);
        range.Add(101);
        VERIFY_ARE_EQUAL(range.ValidCount(), (UINT32)1);
        VERIFY_ARE_EQUAL(range.Min(), (UINT32)100);
        VERIFY_ARE_EQUAL(range.Max(), (UINT32)101);
    }

    TEST_METHOD(AddTwoSeparateBefore)
    {
        SmartRange range;
        range.Add(102);
        range.Add(100);
        VERIFY_ARE_EQUAL(range.ValidCount(), (UINT32)2);
        VERIFY_ARE_EQUAL(range.Min(), (UINT32)100);
        VERIFY_ARE_EQUAL(range.Max(), (UINT32)102);
    }

    TEST_METHOD(AddTwoSeparateAfter)
    {
        SmartRange range;
        range.Add(100);
        range.Add(102);
        VERIFY_ARE_EQUAL(range.ValidCount(), (UINT32)2);
        VERIFY_ARE_EQUAL(range.Min(), (UINT32)100);
        VERIFY_ARE_EQUAL(range.Max(), (UINT32)102);
    }

    TEST_METHOD(AddThreeMerge)
    {
        SmartRange range;
        range.Add(100);
        range.Add(102);
        range.Add(101);
        VERIFY_ARE_EQUAL(range.ValidCount(), (UINT32)1);
        VERIFY_ARE_EQUAL(range.Min(), (UINT32)100);
        VERIFY_ARE_EQUAL(range.Max(), (UINT32)102);
    }

    TEST_METHOD(AddBetween)
    {
        SmartRange range;
        range.Add(100);
        range.Add(104);
        range.Add(102);
        VERIFY_ARE_EQUAL(range.ValidCount(), (UINT32)3);
        VERIFY_ARE_EQUAL(range.Min(), (UINT32)100);
        VERIFY_ARE_EQUAL(range.Max(), (UINT32)104);
    }

    TEST_METHOD(AddRangeSingle)
    {
        SmartRange range;
        range.Add(100, 100);
        VERIFY_ARE_EQUAL(range.ValidCount(), (UINT32)1);
        VERIFY_ARE_EQUAL(range.Min(), (UINT32)100);
        VERIFY_ARE_EQUAL(range.Max(), (UINT32)199);
    }

    TEST_METHOD(AddRangeBetween)
    {
        SmartRange range;
        range.Add(100, 50);
        range.Add(300, 50);
        range.Add(200, 50);
        VERIFY_ARE_EQUAL(range.ValidCount(), (UINT32)3);
        VERIFY_ARE_EQUAL(range.Min(), (UINT32)100);
        VERIFY_ARE_EQUAL(range.Max(), (UINT32)349);
    }

    TEST_METHOD(AddRangeTwoAdjacentBefore)
    {
        SmartRange range;
        range.Add(200, 100);
        range.Add(100, 100);
        VERIFY_ARE_EQUAL(range.ValidCount(), (UINT32)1);
        VERIFY_ARE_EQUAL(range.Min(), (UINT32)100);
        VERIFY_ARE_EQUAL(range.Max(), (UINT32)299);
    }

    TEST_METHOD(AddRangeTwoAdjacentAfter)
    {
        SmartRange range;
        range.Add(100, 100);
        range.Add(200, 100);
        VERIFY_ARE_EQUAL(range.ValidCount(), (UINT32)1);
        VERIFY_ARE_EQUAL(range.Min(), (UINT32)100);
        VERIFY_ARE_EQUAL(range.Max(), (UINT32)299);
    }

    TEST_METHOD(AddRangeTwoSeparateBefore)
    {
        SmartRange range;
        range.Add(300, 100);
        range.Add(100, 100);
        VERIFY_ARE_EQUAL(range.ValidCount(), (UINT32)2);
        VERIFY_ARE_EQUAL(range.Min(), (UINT32)100);
        VERIFY_ARE_EQUAL(range.Max(), (UINT32)399);
    }

    TEST_METHOD(AddRangeTwoSeparateAfter)
    {
        SmartRange range;
        range.Add(100, 100);
        range.Add(300, 100);
        VERIFY_ARE_EQUAL(range.ValidCount(), (UINT32)2);
        VERIFY_ARE_EQUAL(range.Min(), (UINT32)100);
        VERIFY_ARE_EQUAL(range.Max(), (UINT32)399);
    }

    TEST_METHOD(AddRangeTwoOverlapBefore1)
    {
        SmartRange range;
        range.Add(200, 100);
        range.Add(100, 150);
        VERIFY_ARE_EQUAL(range.ValidCount(), (UINT32)1);
        VERIFY_ARE_EQUAL(range.Min(), (UINT32)100);
        VERIFY_ARE_EQUAL(range.Max(), (UINT32)299);
    }

    TEST_METHOD(AddRangeTwoOverlapBefore2)
    {
        SmartRange range;
        range.Add(200, 100);
        range.Add(100, 200);
        VERIFY_ARE_EQUAL(range.ValidCount(), (UINT32)1);
        VERIFY_ARE_EQUAL(range.Min(), (UINT32)100);
        VERIFY_ARE_EQUAL(range.Max(), (UINT32)299);
    }

    TEST_METHOD(AddRangeTwoOverlapBefore3)
    {
        SmartRange range;
        range.Add(200, 50);
        range.Add(100, 200);
        VERIFY_ARE_EQUAL(range.ValidCount(), (UINT32)1);
        VERIFY_ARE_EQUAL(range.Min(), (UINT32)100);
        VERIFY_ARE_EQUAL(range.Max(), (UINT32)299);
    }

    TEST_METHOD(AddRangeTwoOverlapAfter1)
    {
        SmartRange range;
        range.Add(100, 100);
        range.Add(150, 150);
        VERIFY_ARE_EQUAL(range.ValidCount(), (UINT32)1);
        VERIFY_ARE_EQUAL(range.Min(), (UINT32)100);
        VERIFY_ARE_EQUAL(range.Max(), (UINT32)299);
    }

    TEST_METHOD(AddRangeTwoOverlapAfter2)
    {
        SmartRange range;
        range.Add(100, 100);
        range.Add(100, 200);
        VERIFY_ARE_EQUAL(range.ValidCount(), (UINT32)1);
        VERIFY_ARE_EQUAL(range.Min(), (UINT32)100);
        VERIFY_ARE_EQUAL(range.Max(), (UINT32)299);
    }

    TEST_METHOD(AddRangeThreeMerge)
    {
        SmartRange range;
        range.Add(100, 100);
        range.Add(300, 100);
        range.Add(200, 100);
        VERIFY_ARE_EQUAL(range.ValidCount(), (UINT32)1);
        VERIFY_ARE_EQUAL(range.Min(), (UINT32)100);
        VERIFY_ARE_EQUAL(range.Max(), (UINT32)399);
    }

    TEST_METHOD(AddRangeThreeOverlapAndAdjacentAfter1)
    {
        SmartRange range;
        range.Add(100, 1);
        range.Add(200, 100);
        range.Add(101, 150);
        VERIFY_ARE_EQUAL(range.ValidCount(), (UINT32)1);
        VERIFY_ARE_EQUAL(range.Min(), (UINT32)100);
        VERIFY_ARE_EQUAL(range.Max(), (UINT32)299);
    }

    TEST_METHOD(AddRangeThreeOverlapAndAdjacentAfter2)
    {
        SmartRange range;
        range.Add(100, 1);
        range.Add(200, 100);
        range.Add(101, 299);
        VERIFY_ARE_EQUAL(range.ValidCount(), (UINT32)1);
        VERIFY_ARE_EQUAL(range.Min(), (UINT32)100);
        VERIFY_ARE_EQUAL(range.Max(), (UINT32)399);
    }

    TEST_METHOD(AddRangeThreeOverlapAndAdjacentAfter3)
    {
        SmartRange range;
        range.Add(100, 100);
        range.Add(300, 100);
        range.Add(150, 150);
        VERIFY_ARE_EQUAL(range.ValidCount(), (UINT32)1);
        VERIFY_ARE_EQUAL(range.Min(), (UINT32)100);
        VERIFY_ARE_EQUAL(range.Max(), (UINT32)399);
    }

    TEST_METHOD(AddRangeThreeOverlapAndAdjacentAfter4)
    {
        SmartRange range;
        range.Add(100, 100);
        range.Add(300, 100);
        range.Add(50, 250);
        VERIFY_ARE_EQUAL(range.ValidCount(), (UINT32)1);
        VERIFY_ARE_EQUAL(range.Min(), (UINT32)50);
        VERIFY_ARE_EQUAL(range.Max(), (UINT32)399);
    }

    TEST_METHOD(RemoveRangeBefore)
    {
        SmartRange range;
        range.Add(100, 100);
        VERIFY_ARE_EQUAL(range.ValidCount(), (UINT32)1);
        VERIFY_ARE_EQUAL(range.Min(), (UINT32)100);
        VERIFY_ARE_EQUAL(range.Max(), (UINT32)199);
        range.Remove(0, 99);
        VERIFY_ARE_EQUAL(range.ValidCount(), (UINT32)1);
        VERIFY_ARE_EQUAL(range.Min(), (UINT32)100);
        VERIFY_ARE_EQUAL(range.Max(), (UINT32)199);
        range.Remove(0, 100);
        VERIFY_ARE_EQUAL(range.ValidCount(), (UINT32)1);
        VERIFY_ARE_EQUAL(range.Min(), (UINT32)100);
        VERIFY_ARE_EQUAL(range.Max(), (UINT32)199);
    }

    TEST_METHOD(RemoveRangeAfter)
    {
        SmartRange range;
        range.Add(100, 100);
        VERIFY_ARE_EQUAL(range.ValidCount(), (UINT32)1);
        VERIFY_ARE_EQUAL(range.Min(), (UINT32)100);
        VERIFY_ARE_EQUAL(range.Max(), (UINT32)199);
        range.Remove(201, 99);
        VERIFY_ARE_EQUAL(range.ValidCount(), (UINT32)1);
        VERIFY_ARE_EQUAL(range.Min(), (UINT32)100);
        VERIFY_ARE_EQUAL(range.Max(), (UINT32)199);
        range.Remove(200, 100);
        VERIFY_ARE_EQUAL(range.ValidCount(), (UINT32)1);
        VERIFY_ARE_EQUAL(range.Min(), (UINT32)100);
        VERIFY_ARE_EQUAL(range.Max(), (UINT32)199);
    }

    TEST_METHOD(RemoveRangeFront)
    {
        SmartRange range;
        range.Add(100, 100);
        VERIFY_ARE_EQUAL(range.ValidCount(), (UINT32)1);
        VERIFY_ARE_EQUAL(range.Min(), (UINT32)100);
        VERIFY_ARE_EQUAL(range.Max(), (UINT32)199);
        range.Remove(100, 20);
        VERIFY_ARE_EQUAL(range.ValidCount(), (UINT32)1);
        VERIFY_ARE_EQUAL(range.Min(), (UINT32)120);
        VERIFY_ARE_EQUAL(range.Max(), (UINT32)199);
    }

    TEST_METHOD(RemoveRangeBack)
    {
        SmartRange range;
        range.Add(100, 100);
        VERIFY_ARE_EQUAL(range.ValidCount(), (UINT32)1);
        VERIFY_ARE_EQUAL(range.Min(), (UINT32)100);
        VERIFY_ARE_EQUAL(range.Max(), (UINT32)199);
        range.Remove(180, 20);
        VERIFY_ARE_EQUAL(range.ValidCount(), (UINT32)1);
        VERIFY_ARE_EQUAL(range.Min(), (UINT32)100);
        VERIFY_ARE_EQUAL(range.Max(), (UINT32)179);
    }

    TEST_METHOD(RemoveRangeAll)
    {
        SmartRange range;
        range.Add(100, 100);
        VERIFY_ARE_EQUAL(range.ValidCount(), (UINT32)1);
        VERIFY_ARE_EQUAL(range.Min(), (UINT32)100);
        VERIFY_ARE_EQUAL(range.Max(), (UINT32)199);
        range.Remove(100, 100);
        VERIFY_ARE_EQUAL(range.ValidCount(), (UINT32)0);
    }

    TEST_METHOD(ExampleAckTest)
    {
        SmartRange range;
        range.Add(10000);
        range.Add(10001);
        range.Add(10003);
        range.Add(10002);
        VERIFY_ARE_EQUAL(range.ValidCount(), (UINT32)1);
        range.Remove(10000, 2);
        VERIFY_ARE_EQUAL(range.ValidCount(), (UINT32)1);
        range.Remove(10000, 4);
        VERIFY_ARE_EQUAL(range.ValidCount(), (UINT32)0);
        range.Add(10005);
        range.Add(10006);
        range.Add(10004);
        range.Add(10007);
        VERIFY_ARE_EQUAL(range.ValidCount(), (UINT32)1);
        range.Remove(10005, 2);
        VERIFY_ARE_EQUAL(range.ValidCount(), (UINT32)2);
        range.Remove(10004, 1);
        VERIFY_ARE_EQUAL(range.ValidCount(), (UINT32)1);
        range.Remove(10007, 1);
        VERIFY_ARE_EQUAL(range.ValidCount(), (UINT32)0);
    }

    TEST_METHOD(ExampleAckWithLossTest)
    {
        SmartRange range;
        range.Add(10000);
        range.Add(10001);
        range.Add(10003);
        VERIFY_ARE_EQUAL(range.ValidCount(), (UINT32)2);
        range.Add(10002);
        VERIFY_ARE_EQUAL(range.ValidCount(), (UINT32)1);
        range.Remove(10000, 2);
        range.Remove(10003, 1);
        VERIFY_ARE_EQUAL(range.ValidCount(), (UINT32)1);
        range.Remove(10002, 1);
        VERIFY_ARE_EQUAL(range.ValidCount(), (UINT32)0);
        range.Add(10004);
        range.Add(10005);
        range.Add(10006);
        VERIFY_ARE_EQUAL(range.ValidCount(), (UINT32)1);
        range.Remove(10004, 3);
        VERIFY_ARE_EQUAL(range.ValidCount(), (UINT32)0);
        range.Add(10008);
        range.Add(10009);
        VERIFY_ARE_EQUAL(range.ValidCount(), (UINT32)1);
        range.Remove(10008, 2);
        VERIFY_ARE_EQUAL(range.ValidCount(), (UINT32)0);
    }

    TEST_METHOD(AddLots)
    {
        SmartRange range;
        for (UINT32 i = 0; i < 400; i += 2) {
            range.Add(i);
        }
        VERIFY_ARE_EQUAL(range.ValidCount(), (UINT32)200);
        for (UINT32 i = 0; i < 398; i += 2) {
            range.Remove(i, 1);
        }
        VERIFY_ARE_EQUAL(range.ValidCount(), (UINT32)1);
    }

    TEST_METHOD(HitMax)
    {
        const uint32_t MaxCount = 16;
        SmartRange range(MaxCount * sizeof(QUIC_SUBRANGE));
        for (UINT32 i = 0; i < MaxCount; i++) {
            range.Add(i*2);
        }
        VERIFY_ARE_EQUAL(range.ValidCount(), MaxCount);
        VERIFY_ARE_EQUAL(range.Min(), 0ull);
        VERIFY_ARE_EQUAL(range.Max(), (MaxCount - 1)*2);
        range.Add(MaxCount*2);
        VERIFY_ARE_EQUAL(range.ValidCount(), MaxCount);
        VERIFY_ARE_EQUAL(range.Min(), 2ull);
        VERIFY_ARE_EQUAL(range.Max(), MaxCount*2);
        range.Remove(2, 1);
        VERIFY_ARE_EQUAL(range.ValidCount(), MaxCount - 1);
        VERIFY_ARE_EQUAL(range.Min(), 4ull);
        VERIFY_ARE_EQUAL(range.Max(), MaxCount*2);
        range.Add(0);
        VERIFY_ARE_EQUAL(range.ValidCount(), MaxCount);
        VERIFY_ARE_EQUAL(range.Min(), 0ull);
        VERIFY_ARE_EQUAL(range.Max(), MaxCount*2);
    }

    TEST_METHOD(SearchZero)
    {
        SmartRange range;
        auto index = range.Find(25);
        VERIFY_IS_TRUE(IS_INSERT_INDEX(index));
        VERIFY_ARE_EQUAL(INSERT_INDEX_TO_FIND_INDEX(index), 0ul);
    }

    TEST_METHOD(SearchOne)
    {
        SmartRange range;
        range.Add(25);

        auto index = range.Find(27);
        VERIFY_IS_TRUE(IS_INSERT_INDEX(index));
        VERIFY_ARE_EQUAL(INSERT_INDEX_TO_FIND_INDEX(index), 1ul);
        index = range.Find(26);
        VERIFY_IS_TRUE(IS_INSERT_INDEX(index));
        VERIFY_ARE_EQUAL(INSERT_INDEX_TO_FIND_INDEX(index), 1ul);
        index = range.Find(24);
        VERIFY_IS_TRUE(IS_INSERT_INDEX(index));
        VERIFY_ARE_EQUAL(INSERT_INDEX_TO_FIND_INDEX(index), 0ul);
        index = range.Find(23);
        VERIFY_IS_TRUE(IS_INSERT_INDEX(index));
        VERIFY_ARE_EQUAL(INSERT_INDEX_TO_FIND_INDEX(index), 0ul);

        index = range.Find(25);
        VERIFY_IS_TRUE(IS_FIND_INDEX(index));
        VERIFY_ARE_EQUAL(index, 0);
    }

    TEST_METHOD(SearchTwo)
    {
        SmartRange range;
        range.Add(25);
        range.Add(27);

        auto index = range.Find(28);
        VERIFY_IS_TRUE(IS_INSERT_INDEX(index));
        VERIFY_ARE_EQUAL(INSERT_INDEX_TO_FIND_INDEX(index), 2ul);
        index = range.Find(26);
        VERIFY_IS_TRUE(IS_INSERT_INDEX(index));
        VERIFY_ARE_EQUAL(INSERT_INDEX_TO_FIND_INDEX(index), 1ul);
        index = range.Find(24);
        VERIFY_IS_TRUE(IS_INSERT_INDEX(index));
        VERIFY_ARE_EQUAL(INSERT_INDEX_TO_FIND_INDEX(index), 0ul);

        index = range.Find(27);
        VERIFY_IS_TRUE(IS_FIND_INDEX(index));
        VERIFY_ARE_EQUAL(index, 1);
        index = range.Find(25);
        VERIFY_IS_TRUE(IS_FIND_INDEX(index));
        VERIFY_ARE_EQUAL(index, 0);
    }

    TEST_METHOD(SearchThree)
    {
        SmartRange range;
        range.Add(25);
        range.Add(27);
        range.Add(29);

        auto index = range.Find(30);
        VERIFY_IS_TRUE(IS_INSERT_INDEX(index));
        VERIFY_ARE_EQUAL(INSERT_INDEX_TO_FIND_INDEX(index), 3ul);
        index = range.Find(28);
        VERIFY_IS_TRUE(IS_INSERT_INDEX(index));
        VERIFY_ARE_EQUAL(INSERT_INDEX_TO_FIND_INDEX(index), 2ul);
        index = range.Find(26);
        VERIFY_IS_TRUE(IS_INSERT_INDEX(index));
        VERIFY_ARE_EQUAL(INSERT_INDEX_TO_FIND_INDEX(index), 1ul);
        index = range.Find(24);
        VERIFY_IS_TRUE(IS_INSERT_INDEX(index));
        VERIFY_ARE_EQUAL(INSERT_INDEX_TO_FIND_INDEX(index), 0ul);

        index = range.Find(29);
        VERIFY_IS_TRUE(IS_FIND_INDEX(index));
        VERIFY_ARE_EQUAL(index, 2);
        index = range.Find(27);
        VERIFY_IS_TRUE(IS_FIND_INDEX(index));
        VERIFY_ARE_EQUAL(index, 1);
        index = range.Find(25);
        VERIFY_IS_TRUE(IS_FIND_INDEX(index));
        VERIFY_ARE_EQUAL(index, 0);
    }

    TEST_METHOD(SearchFour)
    {
        SmartRange range;
        range.Add(25);
        range.Add(27);
        range.Add(29);
        range.Add(31);

        auto index = range.Find(32);
        VERIFY_IS_TRUE(IS_INSERT_INDEX(index));
        VERIFY_ARE_EQUAL(INSERT_INDEX_TO_FIND_INDEX(index), 4ul);
        index = range.Find(30);
        VERIFY_IS_TRUE(IS_INSERT_INDEX(index));
        VERIFY_ARE_EQUAL(INSERT_INDEX_TO_FIND_INDEX(index), 3ul);
        index = range.Find(28);
        VERIFY_IS_TRUE(IS_INSERT_INDEX(index));
        VERIFY_ARE_EQUAL(INSERT_INDEX_TO_FIND_INDEX(index), 2ul);
        index = range.Find(26);
        VERIFY_IS_TRUE(IS_INSERT_INDEX(index));
        VERIFY_ARE_EQUAL(INSERT_INDEX_TO_FIND_INDEX(index), 1ul);
        index = range.Find(24);
        VERIFY_IS_TRUE(IS_INSERT_INDEX(index));
        VERIFY_ARE_EQUAL(INSERT_INDEX_TO_FIND_INDEX(index), 0ul);

        index = range.Find(29);
        VERIFY_IS_TRUE(IS_FIND_INDEX(index));
        VERIFY_ARE_EQUAL(index, 2);
        index = range.Find(27);
        VERIFY_IS_TRUE(IS_FIND_INDEX(index));
        VERIFY_ARE_EQUAL(index, 1);
        index = range.Find(25);
        VERIFY_IS_TRUE(IS_FIND_INDEX(index));
        VERIFY_ARE_EQUAL(index, 0);
    }

    TEST_METHOD(SearchRangeZero)
    {
        SmartRange range;
        auto index = range.FindRange(25, 17);
        VERIFY_IS_TRUE(IS_INSERT_INDEX(index));
        VERIFY_ARE_EQUAL(INSERT_INDEX_TO_FIND_INDEX(index), 0ul);
    }

    TEST_METHOD(SearchRangeOne)
    {
        SmartRange range;
        range.Add(25);

        auto index = range.FindRange(27, 3);
        VERIFY_IS_TRUE(IS_INSERT_INDEX(index));
        VERIFY_ARE_EQUAL(INSERT_INDEX_TO_FIND_INDEX(index), 1ul);
        index = range.FindRange(26, 3);
        VERIFY_IS_TRUE(IS_INSERT_INDEX(index));
        VERIFY_ARE_EQUAL(INSERT_INDEX_TO_FIND_INDEX(index), 1ul);
        index = range.FindRange(22, 3);
        VERIFY_IS_TRUE(IS_INSERT_INDEX(index));
        VERIFY_ARE_EQUAL(INSERT_INDEX_TO_FIND_INDEX(index), 0ul);
        index = range.FindRange(21, 3);
        VERIFY_IS_TRUE(IS_INSERT_INDEX(index));
        VERIFY_ARE_EQUAL(INSERT_INDEX_TO_FIND_INDEX(index), 0ul);

        index = range.FindRange(23, 3);
        VERIFY_IS_TRUE(IS_FIND_INDEX(index));
        VERIFY_ARE_EQUAL(index, 0);
        index = range.FindRange(24, 3);
        VERIFY_IS_TRUE(IS_FIND_INDEX(index));
        VERIFY_ARE_EQUAL(index, 0);
        index = range.FindRange(25, 3);
        VERIFY_IS_TRUE(IS_FIND_INDEX(index));
        VERIFY_ARE_EQUAL(index, 0);
    }

    TEST_METHOD(SearchRangeTwo)
    {
        SmartRange range;
        range.Add(25);
        range.Add(30);

        auto index = range.FindRange(32, 3);
        VERIFY_IS_TRUE(IS_INSERT_INDEX(index));
        VERIFY_ARE_EQUAL(INSERT_INDEX_TO_FIND_INDEX(index), 2ul);
        index = range.FindRange(31, 3);
        VERIFY_IS_TRUE(IS_INSERT_INDEX(index));
        VERIFY_ARE_EQUAL(INSERT_INDEX_TO_FIND_INDEX(index), 2ul);
        index = range.FindRange(26, 2);
        VERIFY_IS_TRUE(IS_INSERT_INDEX(index));
        VERIFY_ARE_EQUAL(INSERT_INDEX_TO_FIND_INDEX(index), 1ul);
        index = range.FindRange(27, 2);
        VERIFY_IS_TRUE(IS_INSERT_INDEX(index));
        VERIFY_ARE_EQUAL(INSERT_INDEX_TO_FIND_INDEX(index), 1ul);
        index = range.FindRange(28, 2);
        VERIFY_IS_TRUE(IS_INSERT_INDEX(index));
        VERIFY_ARE_EQUAL(INSERT_INDEX_TO_FIND_INDEX(index), 1ul);
        index = range.FindRange(22, 2);
        VERIFY_IS_TRUE(IS_INSERT_INDEX(index));
        VERIFY_ARE_EQUAL(INSERT_INDEX_TO_FIND_INDEX(index), 0ul);
        index = range.FindRange(23, 2);
        VERIFY_IS_TRUE(IS_INSERT_INDEX(index));
        VERIFY_ARE_EQUAL(INSERT_INDEX_TO_FIND_INDEX(index), 0ul);

        index = range.FindRange(24, 2);
        VERIFY_IS_TRUE(IS_FIND_INDEX(index));
        VERIFY_ARE_EQUAL(index, 0);
        index = range.FindRange(24, 3);
        VERIFY_IS_TRUE(IS_FIND_INDEX(index));
        VERIFY_ARE_EQUAL(index, 0);
        index = range.FindRange(25, 2);
        VERIFY_IS_TRUE(IS_FIND_INDEX(index));
        VERIFY_ARE_EQUAL(index, 0);
        index = range.FindRange(29, 2);
        VERIFY_IS_TRUE(IS_FIND_INDEX(index));
        VERIFY_ARE_EQUAL(index, 1);
        index = range.FindRange(29, 3);
        VERIFY_IS_TRUE(IS_FIND_INDEX(index));
        VERIFY_ARE_EQUAL(index, 1);
        index = range.FindRange(30, 2);
        VERIFY_IS_TRUE(IS_FIND_INDEX(index));
        VERIFY_ARE_EQUAL(index, 1);

        index = range.FindRange(24, 7);
        VERIFY_IS_TRUE(IS_FIND_INDEX(index));
#if QUIC_RANGE_USE_BINARY_SEARCH
        VERIFY_ARE_EQUAL(index, 0);
#else
        VERIFY_ARE_EQUAL(index, 1);
#endif
        index = range.FindRange(25, 6);
        VERIFY_IS_TRUE(IS_FIND_INDEX(index));
#if QUIC_RANGE_USE_BINARY_SEARCH
        VERIFY_ARE_EQUAL(index, 0);
#else
        VERIFY_ARE_EQUAL(index, 1);
#endif
    }

    TEST_METHOD(SearchRangeThree)
    {
        SmartRange range;
        range.Add(25);
        range.Add(30);
        range.Add(35);

        auto index = range.FindRange(36, 3);
        VERIFY_IS_TRUE(IS_INSERT_INDEX(index));
        VERIFY_ARE_EQUAL(INSERT_INDEX_TO_FIND_INDEX(index), 3ul);
        index = range.FindRange(32, 3);
        VERIFY_IS_TRUE(IS_INSERT_INDEX(index));
        VERIFY_ARE_EQUAL(INSERT_INDEX_TO_FIND_INDEX(index), 2ul);
        index = range.FindRange(31, 3);
        VERIFY_IS_TRUE(IS_INSERT_INDEX(index));
        VERIFY_ARE_EQUAL(INSERT_INDEX_TO_FIND_INDEX(index), 2ul);
        index = range.FindRange(26, 2);
        VERIFY_IS_TRUE(IS_INSERT_INDEX(index));
        VERIFY_ARE_EQUAL(INSERT_INDEX_TO_FIND_INDEX(index), 1ul);
        index = range.FindRange(27, 2);
        VERIFY_IS_TRUE(IS_INSERT_INDEX(index));
        VERIFY_ARE_EQUAL(INSERT_INDEX_TO_FIND_INDEX(index), 1ul);
        index = range.FindRange(28, 2);
        VERIFY_IS_TRUE(IS_INSERT_INDEX(index));
        VERIFY_ARE_EQUAL(INSERT_INDEX_TO_FIND_INDEX(index), 1ul);
        index = range.FindRange(22, 2);
        VERIFY_IS_TRUE(IS_INSERT_INDEX(index));
        VERIFY_ARE_EQUAL(INSERT_INDEX_TO_FIND_INDEX(index), 0ul);
        index = range.FindRange(23, 2);
        VERIFY_IS_TRUE(IS_INSERT_INDEX(index));
        VERIFY_ARE_EQUAL(INSERT_INDEX_TO_FIND_INDEX(index), 0ul);

        index = range.FindRange(24, 2);
        VERIFY_IS_TRUE(IS_FIND_INDEX(index));
        VERIFY_ARE_EQUAL(index, 0);
        index = range.FindRange(24, 3);
        VERIFY_IS_TRUE(IS_FIND_INDEX(index));
        VERIFY_ARE_EQUAL(index, 0);
        index = range.FindRange(25, 2);
        VERIFY_IS_TRUE(IS_FIND_INDEX(index));
        VERIFY_ARE_EQUAL(index, 0);
        index = range.FindRange(29, 2);
        VERIFY_IS_TRUE(IS_FIND_INDEX(index));
        VERIFY_ARE_EQUAL(index, 1);
        index = range.FindRange(29, 3);
        VERIFY_IS_TRUE(IS_FIND_INDEX(index));
        VERIFY_ARE_EQUAL(index, 1);
        index = range.FindRange(30, 2);
        VERIFY_IS_TRUE(IS_FIND_INDEX(index));
        VERIFY_ARE_EQUAL(index, 1);

        index = range.FindRange(24, 7);
        VERIFY_IS_TRUE(IS_FIND_INDEX(index));
        VERIFY_ARE_EQUAL(index, 1);
        index = range.FindRange(25, 6);
        VERIFY_IS_TRUE(IS_FIND_INDEX(index));
        VERIFY_ARE_EQUAL(index, 1);

        index = range.FindRange(29, 7);
        VERIFY_IS_TRUE(IS_FIND_INDEX(index));
#if QUIC_RANGE_USE_BINARY_SEARCH
        VERIFY_ARE_EQUAL(index, 1);
#else
        VERIFY_ARE_EQUAL(index, 2);
#endif
        index = range.FindRange(30, 6);
        VERIFY_IS_TRUE(IS_FIND_INDEX(index));
#if QUIC_RANGE_USE_BINARY_SEARCH
        VERIFY_ARE_EQUAL(index, 1);
#else
        VERIFY_ARE_EQUAL(index, 2);
#endif

        index = range.FindRange(24, 12);
        VERIFY_IS_TRUE(IS_FIND_INDEX(index));
#if QUIC_RANGE_USE_BINARY_SEARCH
        VERIFY_ARE_EQUAL(index, 1);
#else
        VERIFY_ARE_EQUAL(index, 2);
#endif
        index = range.FindRange(25, 11);
        VERIFY_IS_TRUE(IS_FIND_INDEX(index));
#if QUIC_RANGE_USE_BINARY_SEARCH
        VERIFY_ARE_EQUAL(index, 1);
#else
        VERIFY_ARE_EQUAL(index, 2);
#endif
    }
};
