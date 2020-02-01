/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.

--*/

#include "precomp.h"
#define LOG_ONLY_FAILURES
#define INLINE_TEST_METHOD_MARKUP
#include <wextestclass.h>
#include <logcontroller.h>

#if defined(QUIC_LOGS_WPP) || defined(QUIC_LOGS_CLOG)
#include "main.tmh"
#endif

using namespace WEX::Common;

BEGIN_MODULE()
    MODULE_PROPERTY(L"BinaryUnderTest", L"core.lib")
    MODULE_PROPERTY(L"Description", L"Tests the QUIC core user-mode library")
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
