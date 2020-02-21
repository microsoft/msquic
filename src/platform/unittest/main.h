/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.

--*/

#undef min // gtest headers conflict with previous definitions of min/max.
#undef max
#include "gtest/gtest.h"

#include "quic_platform.h"

#include "quic_trace.h"

#define VERIFY_QUIC_SUCCESS(result) ASSERT_EQ(QUIC_STATUS_SUCCESS, result)

#define GTEST_SKIP_NO_RETURN_(message) \
  GTEST_MESSAGE_(message, ::testing::TestPartResult::kSkip)

extern void* SecConfigCertContext;
