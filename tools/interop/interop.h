/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.

--*/

#include <quic_platform.h>
#include <MsQuic.h>
#include <MsQuicp.h>
#include <MsQuichelper.h>

//
// Different features tested by this tool.
//
enum QuicTestFeature {
    VersionNegotiation  = 0x0001,
    Handshake           = 0x0002,
    StreamData          = 0x0004,
    ConnectionClose     = 0x0008,
    Resumption          = 0x0010,
    ZeroRtt             = 0x0020,
    StatelessRetry      = 0x0040,
    PostQuantum         = 0x0080,
    KeyUpdate           = 0x0100
};

const uint32_t QuicTestFeatureCount = 9;
const uint32_t QuicTestFeatureAll = ((1 << QuicTestFeatureCount) - 1);

const char QuicTestFeatureCode[] = {
    'V', 'H', 'D', 'C', 'R', 'Z', 'S', 'Q', 'U'
};

inline QuicTestFeature operator|(QuicTestFeature a, QuicTestFeature b)
{
    return static_cast<QuicTestFeature>(static_cast<int>(a) | static_cast<int>(b));
}
