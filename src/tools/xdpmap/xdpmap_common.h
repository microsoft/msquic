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

static inline uint32_t
XdpMapDecodeHexBuffer(
    const char* HexBuffer,
    uint32_t OutBufferLen,
    uint8_t* OutBuffer
    )
{
    uint32_t HexBufferLen = 0;
    while (HexBuffer[HexBufferLen * 2] != '\0' && HexBuffer[HexBufferLen * 2 + 1] != '\0') {
        HexBufferLen++;
    }

    if (HexBufferLen > OutBufferLen) {
        return 0;
    }

    for (uint32_t i = 0; i < HexBufferLen; i++) {
        OutBuffer[i] =
            (XdpMapDecodeHexChar(HexBuffer[i * 2]) << 4) |
            XdpMapDecodeHexChar(HexBuffer[i * 2 + 1]);
    }

    return HexBufferLen;
}
