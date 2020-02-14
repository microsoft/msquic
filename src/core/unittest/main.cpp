/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.

--*/

#include "main.h"

#ifdef QUIC_LOGS_WPP
#include "main.tmh"
#endif

extern "C" _IRQL_requires_max_(PASSIVE_LEVEL) void QuicTraceRundown(void) { }

class QuicCoreTestEnvironment : public ::testing::Environment {
public:
    void SetUp() override {
        QuicPlatformSystemLoad();
        ASSERT_TRUE(QUIC_SUCCEEDED(QuicPlatformInitialize()));
    }
    void TearDown() override {
        QuicPlatformUninitialize();
        QuicPlatformSystemUnload();
    }
};

void
LogTestFailure(
    _In_z_ const char* File,
    _In_z_ const char* Function,
    int Line,
    _Printf_format_string_ const char* Format,
    ...
    )
{
    UNREFERENCED_PARAMETER(Function);
    char Buffer[128];
    va_list Args;
    va_start(Args, Format);
    (void)_vsnprintf_s(Buffer, sizeof(Buffer), _TRUNCATE, Format, Args);
    va_end(Args);
    QuicTraceLogError("[test] FAILURE - %s:%d - %s", File, Line, Buffer);
    GTEST_MESSAGE_AT_(File, Line, Buffer, ::testing::TestPartResult::kFatalFailure);
}

struct TestLogger {
    const char* TestName;
    TestLogger(const char* Name) : TestName(Name) {
        QuicTraceLogInfo("[test] START %s", TestName);
    }
    ~TestLogger() {
        QuicTraceLogInfo("[test] END %s", TestName);
    }
};

template<class T>
struct TestLoggerT {
    const char* TestName;
    TestLoggerT(const char* Name, const T& Params) : TestName(Name) {
        std::ostringstream stream; stream << Params;
        QuicTraceLogInfo("[test] START %s, %s", TestName, stream.str().c_str());
    }
    ~TestLoggerT() {
        QuicTraceLogInfo("[test] END %s", TestName);
    }
};

//
// Frame tests
//
TEST(FrameTest, WellKnownEncode) {
    TestLogger Logger("FrameTestWellKnownEncode");
    FrameTestWellKnownEncode();
}

TEST(FrameTest, WellKnownDecode) {
    TestLogger Logger("FrameTestWellKnownDecode");
    FrameTestWellKnownDecode();
}

TEST(FrameTest, RandomEncodeDecode) {
    TestLogger Logger("FrameTestRandomEncodeDecode");
    FrameTestRandomEncodeDecode();
}

//
// Packet number tests
//
TEST(PacketNumberTest, WellKnownDecompress) {
    TestLogger Logger("FrameTestRandomEncodeDecode");
    PacketNumberTestWellKnownDecompress();
}

//
// Range test
//
TEST(RangeTest, AddSingle) {
    TestLogger Logger("RangeTestAddSingle");
    RangeTestAddSingle();
}

TEST(RangeTest, AddTwoAdjacentBefore) {
    TestLogger Logger("RangeTestAddTwoAdjacentBefore");
    RangeTestAddTwoAdjacentBefore();
}

TEST(RangeTest, AddTwoAdjacentAfter) {
    TestLogger Logger("RangeTestAddTwoAdjacentAfter");
    RangeTestAddTwoAdjacentAfter();
}

TEST(RangeTest, AddTwoSeparateBefore) {
    TestLogger Logger("RangeTestAddTwoSeparateBefore");
    RangeTestAddTwoSeparateBefore();
}

TEST(RangeTest, AddTwoSeparateAfter) {
    TestLogger Logger("RangeTestAddTwoSeparateAfter");
    RangeTestAddTwoSeparateAfter();
}

TEST(RangeTest, AddThreeMerge) {
    TestLogger Logger("RangeTestAddThreeMerge");
    RangeTestAddThreeMerge();
}

TEST(RangeTest, AddBetween) {
    TestLogger Logger("RangeTestAddBetween");
    RangeTestAddBetween();
}

TEST(RangeTest, AddRangeSingle) {
    TestLogger Logger("RangeTestAddRangeSingle");
    RangeTestAddRangeSingle();
}

TEST(RangeTest, AddRangeBetween) {
    TestLogger Logger("RangeTestAddRangeBetween");
    RangeTestAddRangeBetween();
}

TEST(RangeTest, AddRangeTwoAdjacentBefore) {
    TestLogger Logger("RangeTestAddRangeTwoAdjacentBefore");
    RangeTestAddRangeTwoAdjacentBefore();
}

TEST(RangeTest, AddRangeTwoAdjacentAfter) {
    TestLogger Logger("RangeTestAddRangeTwoAdjacentAfter");
    RangeTestAddRangeTwoAdjacentAfter();
}

TEST(RangeTest, AddRangeTwoSeparateBefore) {
    TestLogger Logger("RangeTestAddRangeTwoSeparateBefore");
    RangeTestAddRangeTwoSeparateBefore();
}

TEST(RangeTest, AddRangeTwoSeparateAfter) {
    TestLogger Logger("RangeTestAddRangeTwoSeparateAfter");
    RangeTestAddRangeTwoSeparateAfter();
}

TEST(RangeTest, AddRangeTwoOverlapBefore1) {
    TestLogger Logger("RangeTestAddRangeTwoOverlapBefore1");
    RangeTestAddRangeTwoOverlapBefore1();
}

TEST(RangeTest, AddRangeTwoOverlapBefore2) {
    TestLogger Logger("RangeTestAddRangeTwoOverlapBefore2");
    RangeTestAddRangeTwoOverlapBefore2();
}

TEST(RangeTest, AddRangeTwoOverlapBefore3) {
    TestLogger Logger("RangeTestAddRangeTwoOverlapBefore3");
    RangeTestAddRangeTwoOverlapBefore3();
}

TEST(RangeTest, AddRangeTwoOverlapAfter1) {
    TestLogger Logger("RangeTestAddRangeTwoOverlapAfter1");
    RangeTestAddRangeTwoOverlapAfter1();
}

TEST(RangeTest, AddRangeTwoOverlapAfter2) {
    TestLogger Logger("RangeTestAddRangeTwoOverlapAfter2");
    RangeTestAddRangeTwoOverlapAfter2();
}

TEST(RangeTest, AddRangeThreeMerge) {
    TestLogger Logger("RangeTestAddRangeThreeMerge");
    RangeTestAddRangeThreeMerge();
}

TEST(RangeTest, AddRangeThreeOverlapAndAdjacentAfter1) {
    TestLogger Logger("RangeTestAddRangeThreeOverlapAndAdjacentAfter1");
    RangeTestAddRangeThreeOverlapAndAdjacentAfter1();
}

TEST(RangeTest, AddRangeThreeOverlapAndAdjacentAfter2) {
    TestLogger Logger("RangeTestAddRangeThreeOverlapAndAdjacentAfter2");
    RangeTestAddRangeThreeOverlapAndAdjacentAfter2();
}

TEST(RangeTest, AddRangeThreeOverlapAndAdjacentAfter3) {
    TestLogger Logger("RangeTestAddRangeThreeOverlapAndAdjacentAfter3");
    RangeTestAddRangeThreeOverlapAndAdjacentAfter3();
}

TEST(RangeTest, AddRangeThreeOverlapAndAdjacentAfter4) {
    TestLogger Logger("RangeTestAddRangeThreeOverlapAndAdjacentAfter4");
    RangeTestAddRangeThreeOverlapAndAdjacentAfter4();
}

TEST(RangeTest, RemoveRangeBefore) {
    TestLogger Logger("RangeTestRemoveRangeBefore");
    RangeTestRemoveRangeBefore();
}

TEST(RangeTest, RemoveRangeAfter) {
    TestLogger Logger("RangeTestRemoveRangeAfter");
    RangeTestRemoveRangeAfter();
}

TEST(RangeTest, RemoveRangeFront) {
    TestLogger Logger("RangeTestRemoveRangeFront");
    RangeTestRemoveRangeFront();
}

TEST(RangeTest, RemoveRangeBack) {
    TestLogger Logger("RangeTestRemoveRangeBack");
    RangeTestRemoveRangeBack();
}

TEST(RangeTest, RemoveRangeAll) {
    TestLogger Logger("RangeTestRemoveRangeAll");
    RangeTestRemoveRangeAll();
}

TEST(RangeTest, ExampleAckTest) {
    TestLogger Logger("RangeTestExampleAckTest");
    RangeTestExampleAckTest();
}

TEST(RangeTest, ExampleAckWithLossTest) {
    TestLogger Logger("RangeTestExampleAckWithLossTest");
    RangeTestExampleAckWithLossTest();
}

TEST(RangeTest, AddLots) {
    TestLogger Logger("RangeTestAddLots");
    RangeTestAddLots();
}

TEST(RangeTest, HitMax) {
    TestLogger Logger("RangeTestHitMax");
    RangeTestHitMax();
}

TEST(RangeTest, SearchZero) {
    TestLogger Logger("RangeTestSearchZero");
    RangeTestSearchZero();
}

TEST(RangeTest, SearchOne) {
    TestLogger Logger("RangeTestSearchOne");
    RangeTestSearchOne();
}

TEST(RangeTest, SearchTwo) {
    TestLogger Logger("RangeTestSearchTwo");
    RangeTestSearchTwo();
}

TEST(RangeTest, SearchThree) {
    TestLogger Logger("RangeTestSearchThree");
    RangeTestSearchThree();
}

TEST(RangeTest, SearchFour) {
    TestLogger Logger("RangeTestSearchFour");
    RangeTestSearchFour();
}

TEST(RangeTest, SearchRangeZero) {
    TestLogger Logger("RangeTestSearchRangeZero");
    RangeTestSearchRangeZero();
}

TEST(RangeTest, SearchRangeOne) {
    TestLogger Logger("RangeTestSearchRangeOne");
    RangeTestSearchRangeOne();
}

TEST(RangeTest, SearchRangeTwo) {
    TestLogger Logger("RangeTestSearchRangeTwo");
    RangeTestSearchRangeTwo();
}

TEST(RangeTest, SearchRangeThree) {
    TestLogger Logger("RangeTestSearchRangeThree");
    RangeTestSearchRangeThree();
}

int main(int argc, char** argv) {
    ::testing::AddGlobalTestEnvironment(new QuicCoreTestEnvironment);
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
