/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.

Abstract:

    Fuzzing msquic api

--*/

#define QUIC_API_ENABLE_PREVIEW_FEATURES 1
#define CX_PLATFORM_LINUX 1
#define QUIC_TEST_APIS 1

#include <stdlib.h>
#include <stdint.h>
#include <string>
#include "msquic.h"
#include "msquic.hpp"
#include "quic_platform.h"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	const MsQuicApi* MsQuic = new(std::nothrow) MsQuicApi();

	for (uint32_t Param = QUIC_PARAM_GLOBAL_RETRY_MEMORY_PERCENT;
		Param <= QUIC_PARAM_GLOBAL_TLS_PROVIDER;
		Param++) {
        if (Param != QUIC_PARAM_GLOBAL_VERSION_SETTINGS) {
            MsQuic->SetParam(
                nullptr,
                Param,
                size,
                data);
        }
	}

	delete MsQuic;
	return 0;
}
