// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#pragma once

#include <stdint.h>

#define XDPMAP_CIBIR_MAX_DATA_LEN 6
#define XDPMAP_CIBIR_RAW_MAX_LEN (1 + XDPMAP_CIBIR_MAX_DATA_LEN)

// Returns -1 on invalid hex character.
static inline int
XdpMapDecodeHexChar(
    char c
    )
{
    if (c >= '0' && c <= '9') return (c - '0');
    if (c >= 'A' && c <= 'F') return (10 + c - 'A');
    if (c >= 'a' && c <= 'f') return (10 + c - 'a');
    return -1;
}

// Returns 0 on invalid input (non-hex digit or odd-length string).
static inline uint32_t
XdpMapDecodeHexBuffer(
    const char* HexBuffer,
    uint32_t OutBufferLen,
    uint8_t* OutBuffer
    )
{
    uint32_t HexStrLen = (uint32_t)strlen(HexBuffer);
    if (HexStrLen % 2 != 0) {
        return 0; // Reject odd-length input.
    }

    uint32_t HexBufferLen = HexStrLen / 2;
    if (HexBufferLen > OutBufferLen) {
        return 0;
    }

    for (uint32_t i = 0; i < HexBufferLen; i++) {
        int Hi = XdpMapDecodeHexChar(HexBuffer[i * 2]);
        int Lo = XdpMapDecodeHexChar(HexBuffer[i * 2 + 1]);
        if (Hi < 0 || Lo < 0) {
            return 0; // Reject non-hex digits.
        }
        OutBuffer[i] = (uint8_t)((Hi << 4) | Lo);
    }

    return HexBufferLen;
}
