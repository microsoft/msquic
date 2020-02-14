/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.

--*/

#include "precomp.h"

#undef min // gtest headers conflict with previous definitions of min/max.
#undef max
#include "gtest/gtest.h"

#define TEST_EQUAL(__expected, __condition) ASSERT_EQ(__expected, __condition)

#define TEST_NOT_EQUAL(__expected, __condition) ASSERT_NE(__expected, __condition)

#define TEST_TRUE(__condition) ASSERT_TRUE(__condition)

#define TEST_FALSE(__condition) ASSERT_FALSE(__condition)

#define TEST_QUIC_STATUS(__expected, __condition) ASSERT_EQ(__expected, __condition)

#define TEST_QUIC_SUCCEEDED(__condition) ASSERT_FALSE(QUIC_FAILED(__condition))
