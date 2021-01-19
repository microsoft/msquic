/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.

Abstract:

    This file defines the logic for version negotiation.

--*/

#include "precomp.h"
#ifdef QUIC_CLOG
#include "version_neg.c.clog.h"
#endif

typedef struct QUIC_COMPATIBLE_VERSION_MAP {
    uint32_t OriginalVersion;
    uint32_t CompatibleVersion;
} QUIC_COMPATIBLE_VERSION_MAP;

QUIC_COMPATIBLE_VERSION_MAP CompatibleVersions[] = {
    {QUIC_VERSION_DRAFT_29, QUIC_VERSION_DRAFT_29},
    {QUIC_VERSION_MS_1, QUIC_VERSION_MS_1},
    {QUIC_VERSION_MS_1, QUIC_VERSION_1},
    {QUIC_VERSION_1, QUIC_VERSION_1},
    {QUIC_VERSION_1, QUIC_VERSION_MS_1}
};

//
// This list is the versions the server advertises support for.
//
uint32_t DefaultSupportedVersionsList[] = {
    QUIC_VERSION_1,
    QUIC_VERSION_MS_1,
    QUIC_VERSION_DRAFT_29
};
uint32_t DefaultSupportedVersionsListLength = ARRAYSIZE(DefaultSupportedVersionsList);

uint32_t DefaultCompatibleVersionsList[] = {
    QUIC_VERSION_1,
    QUIC_VERSION_MS_1
};
uint32_t DefaultCompatibleVersionsListLength = ARRAYSIZE(DefaultCompatibleVersionsList);

QUIC_STATUS
QuicVersionNegotiationExtGenerateCompatibleVersionsList(
    _In_ uint32_t OriginalVersion,
    _Out_writes_bytes_(*BufferLength) uint8_t* Buffer,
    _Inout_ uint32_t* BufferLength
    )
{
    uint32_t NeededBufferLength = 0;
    for (uint32_t i = 0; i < ARRAYSIZE(CompatibleVersions); ++i) {
        if (CompatibleVersions[i].OriginalVersion == OriginalVersion) {
            NeededBufferLength += sizeof(uint32_t);
        }
    }
    if (*BufferLength < NeededBufferLength) {
        *BufferLength = NeededBufferLength;
        return QUIC_STATUS_BUFFER_TOO_SMALL;
    }
    if (Buffer == NULL) {
        return QUIC_STATUS_INVALID_PARAMETER;
    }
    uint32_t BufferIndex = 0;
    for (uint32_t i = 0; i < ARRAYSIZE(CompatibleVersions); ++i) {
        if (CompatibleVersions[i].OriginalVersion == OriginalVersion) {
            memcpy(
                Buffer + BufferIndex,
                &CompatibleVersions[i].CompatibleVersion,
                sizeof(CompatibleVersions[i].CompatibleVersion));
            BufferIndex += sizeof(CompatibleVersions[i].CompatibleVersion);
        }
    }
    CXPLAT_DBG_ASSERT(BufferIndex <= *BufferLength);
    return QUIC_STATUS_SUCCESS;
}
