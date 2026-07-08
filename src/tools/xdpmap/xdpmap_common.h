// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#pragma once

#include <stdint.h>

#define XDPMAP_CIBIR_MAX_DATA_LEN 6
#define XDPMAP_CIBIR_RAW_MAX_LEN (1 + XDPMAP_CIBIR_MAX_DATA_LEN)

static inline uint8_t
XdpMapDecodeHexChar(
    char c
    )
{
    if (c >= '0' && c <= '9') return (uint8_t)(c - '0');
    if (c >= 'A' && c <= 'F') return (uint8_t)(10 + c - 'A');
    if (c >= 'a' && c <= 'f') return (uint8_t)(10 + c - 'a');
    return 0;
}
