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
	uint8_t *Buf = (uint8_t *)malloc(size);
	if (Buf == NULL) {
		return 0;
	}
	memcpy(Buf, data, size);

	const MsQuicApi* MsQuic = new(std::nothrow) MsQuicApi();

	for (uint32_t Param = QUIC_PARAM_GLOBAL_RETRY_MEMORY_PERCENT;
		Param <= QUIC_PARAM_GLOBAL_TLS_PROVIDER;
		Param++) {
		MsQuic->SetParam(
			nullptr,
			Param,
			size,
			&Buf);
	}

	delete MsQuic;
	free(Buf);
	return 0;
}