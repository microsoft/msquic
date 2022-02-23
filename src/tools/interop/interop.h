/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.

--*/

#define _CRT_NONSTDC_NO_DEPRECATE 1
#define _CRT_SECURE_NO_WARNINGS 1

#define QUIC_API_ENABLE_PREVIEW_FEATURES

#include <string>
#include <vector>
#include "msquichelper.h"
#include "quic_trace.h"

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
    KeyUpdate           = 0x0100,
    CidUpdate           = 0x0200,
    NatRebinding        = 0x0400,
    Datagram            = 0x0800,
    ChaCha20            = 0x1000
};

#define QuicTestFeatureCodes "VHDCRZSQUMBG2"

const uint32_t QuicTestFeatureCount = sizeof(QuicTestFeatureCodes) - 1;
const uint32_t QuicTestFeatureAll = ((1 << QuicTestFeatureCount) - 1);

inline QuicTestFeature operator|(QuicTestFeature a, QuicTestFeature b)
{
    return static_cast<QuicTestFeature>(static_cast<int>(a) | static_cast<int>(b));
}

const QuicTestFeature QuicTestFeatureDataPath = StreamData | ZeroRtt;
