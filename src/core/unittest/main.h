/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.

--*/

#include "precomp.h"

#undef min // gtest headers conflict with previous definitions of min/max.
#undef max
#include "gtest/gtest.h"

#define TEST_QUIC_SUCCEEDED(__condition) ASSERT_FALSE(QUIC_FAILED(__condition))
