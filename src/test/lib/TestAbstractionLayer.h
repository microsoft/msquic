/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.

Abstract:

    Platform independent test abstraction layer.

--*/

#include <quic_platform.h>
#include <quic_datapath.h>
#include <MsQuicTests.h>

const uint32_t TestWaitTimeout = 2000;

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

#define TEST_HRESULT(__condition) { \
    HRESULT __hr = __condition; \
    if (FAILED(__hr)) { \
        TEST_FAILURE(#__condition " failed, 0x%x", __hr); \
        return; \
    } \
}

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
