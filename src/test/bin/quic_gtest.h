/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.

--*/

#define QUIC_TEST_APIS 1

#include "quic_platform.h"
#include "MsQuicTests.h"
#include "msquichelper.h"
#include "quic_trace.h"
#include "quic_driver_helpers.h"
#undef min // gtest headers conflict with previous definitions of min/max.
#undef max
#include "gtest/gtest.h"
#ifdef QUIC_CLOG
#include "quic_gtest.h.clog.h"
#endif

extern bool TestingKernelMode;
extern bool UseDuoNic;
#if defined(QUIC_API_ENABLE_PREVIEW_FEATURES)
extern bool UseQTIP;
#endif

class WithBool : public testing::Test,
    public testing::WithParamInterface<bool> {
};

// To run a test over IPv4 and IPv6.
struct WithFamilyArgs :
    public testing::Test,
    public testing::WithParamInterface<FamilyArgs> {

    static ::std::vector<FamilyArgs> Generate() {
        return {{4}, {6}};
    }
};

std::ostream& operator << (std::ostream& o, const FamilyArgs& args) {
    return o << (args.Family == 4 ? "v4" : "v6");
}