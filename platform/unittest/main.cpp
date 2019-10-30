/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.

--*/

#include "quic_platform.h"

#define LOG_ONLY_FAILURES
#define INLINE_TEST_METHOD_MARKUP
#include <wextestclass.h>
#include <logcontroller.h>

#include "quic_trace.h"
#include "main.tmh"

using namespace WEX::Common;

BEGIN_MODULE()
    MODULE_PROPERTY(L"BinaryUnderTest", L"platform.lib")
    MODULE_PROPERTY(L"Description", L"Tests the QUIC platform user-mode library")
    MODULE_PROPERTY(L"Owner", L"nibanks")
END_MODULE()

extern "C" void QuicTraceRundown(void) { }

MODULE_SETUP(GlobalTestSetup)
{
    QuicPlatformSystemLoad();
    if (QUIC_FAILED(QuicPlatformInitialize())) {
        QuicPlatformSystemUnload();
        return false;
    }
    return true;
}

MODULE_CLEANUP(GlobalTestCleanup)
{
    QuicPlatformUninitialize();
    QuicPlatformSystemUnload();
    return true;
}
