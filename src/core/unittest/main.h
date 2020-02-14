/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.

--*/

#include "precomp.h"

#undef min // gtest headers conflict with previous definitions of min/max.
#undef max
#include "gtest/gtest.h"

#define TEST_FAILURE(Format, ...) \
    LogTestFailure(__FILE__, __FUNCTION__, __LINE__, Format, ##__VA_ARGS__)

#define TEST_EQUAL(__expected, __condition) { \
    if (__condition != __expected) { \
        TEST_FAILURE(#__condition " not equal to " #__expected); \
        return; \
    } \
}

#define TEST_NOT_EQUAL(__expected, __condition) { \
    if (__condition == __expected) { \
        TEST_FAILURE(#__condition " equals " #__expected); \
        return; \
    } \
}

#define TEST_TRUE(__condition) { \
    if (!(__condition)) { \
        TEST_FAILURE(#__condition " not true"); \
        return; \
    } \
}

#define TEST_FALSE(__condition) { \
    if (__condition) { \
        TEST_FAILURE(#__condition " not false"); \
        return; \
    } \
}

void
LogTestFailure(
    _In_z_ const char* File,
    _In_z_ const char* Function,
    int Line,
    _Printf_format_string_ const char* Format,
    ...
    );

#define TEST_QUIC_STATUS(__expected, __condition) { \
    QUIC_STATUS __status = __condition; \
    if (__status != (__expected)) { \
        TEST_FAILURE(#__condition " not equal to " #__expected ", 0x%x", __status); \
        return; \
    } \
}

#define TEST_QUIC_SUCCEEDED(__condition) { \
    QUIC_STATUS __status = __condition; \
    if (QUIC_FAILED(__status)) { \
        TEST_FAILURE(#__condition " failed, 0x%x", __status); \
        return; \
    } \
}

//
// Frame tests
//

void
FrameTestWellKnownEncode(
    );

void
FrameTestWellKnownDecode(
    );

void
FrameTestRandomEncodeDecode(
    );


//
// Packet number tests
//

void
PacketNumberTestWellKnownDecompress(
    );

//
// Range tests
//

void
RangeTestAddSingle(
    );

void
RangeTestAddTwoAdjacentBefore(
    );

void
RangeTestAddTwoAdjacentAfter(
    );

void
RangeTestAddTwoSeparateBefore(
    );

void
RangeTestAddTwoSeparateAfter(
    );

void
RangeTestAddThreeMerge(
    );

void
RangeTestAddBetween(
    );

void
RangeTestAddRangeSingle(
    );

void
RangeTestAddRangeBetween(
    );

void
RangeTestAddRangeTwoAdjacentBefore(
    );

void
RangeTestAddRangeTwoAdjacentAfter(
    );

void
RangeTestAddRangeTwoSeparateBefore(
    );

void
RangeTestAddRangeTwoSeparateAfter(
    );

void
RangeTestAddRangeTwoOverlapBefore1(
    );

void
RangeTestAddRangeTwoOverlapBefore2(
    );

void
RangeTestAddRangeTwoOverlapBefore3(
    );

void
RangeTestAddRangeTwoOverlapAfter1(
    );

void
RangeTestAddRangeTwoOverlapAfter2(
    );

void
RangeTestAddRangeThreeMerge(
    );

void
RangeTestAddRangeThreeOverlapAndAdjacentAfter1(
    );

void
RangeTestAddRangeThreeOverlapAndAdjacentAfter2(
    );

void
RangeTestAddRangeThreeOverlapAndAdjacentAfter3(
    );

void
RangeTestAddRangeThreeOverlapAndAdjacentAfter4(
    );

void
RangeTestRemoveRangeBefore(
    );

void
RangeTestRemoveRangeAfter(
    );


void
RangeTestRemoveRangeFront(
    );

void
RangeTestRemoveRangeBack(
    );

void
RangeTestRemoveRangeAll(
    );

void
RangeTestExampleAckTest(
    );

void
RangeTestExampleAckWithLossTest(
    );

void
RangeTestAddLots(
    );

void
RangeTestHitMax(
    );

void
RangeTestSearchZero(
    );

void
RangeTestSearchOne(
    );

void
RangeTestSearchTwo(
    );

void
RangeTestSearchThree(
    );

void
RangeTestSearchFour(
    );

void
RangeTestSearchRangeZero(
    );

void
RangeTestSearchRangeOne(
    );

void
RangeTestSearchRangeTwo(
    );

void
RangeTestSearchRangeThree(
    );

