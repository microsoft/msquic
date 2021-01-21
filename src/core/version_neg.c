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

QUIC_COMPATIBLE_VERSION_MAP CompatibleVersionsMap[] = {
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
    _In_reads_bytes_(DesiredVersionsLength * sizeof(uint32_t))
        const uint32_t* const DesiredVersions,
    _In_ uint32_t DesiredVersionsLength,
    _Out_writes_bytes_(*BufferLength) uint8_t* Buffer,
    _Inout_ uint32_t* BufferLength
    )
{
    uint32_t NeededBufferLength = 0;
    for (uint32_t i = 0; i < ARRAYSIZE(CompatibleVersionsMap); ++i) {
        if (CompatibleVersionsMap[i].OriginalVersion == OriginalVersion) {
            for (uint32_t j = 0; j < DesiredVersionsLength; ++j) {
                if (CompatibleVersionsMap[i].CompatibleVersion == DesiredVersions[j]) {
                    NeededBufferLength += sizeof(uint32_t);
                    break; // bail from the inner loop
                }
            }
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
    for (uint32_t i = 0; i < ARRAYSIZE(CompatibleVersionsMap); ++i) {
        if (CompatibleVersionsMap[i].OriginalVersion == OriginalVersion) { // review: Does this need to be bidirectional?
            for (uint32_t j = 0; j < DesiredVersionsLength; ++j) { // TODO: this doesn't preserve the order of the app-supplied list, reorder loops
                if (CompatibleVersionsMap[i].CompatibleVersion == DesiredVersions[j]) {
                    CxPlatCopyMemory(
                        Buffer + BufferIndex,
                        &CompatibleVersionsMap[i].CompatibleVersion,
                        sizeof(CompatibleVersionsMap[i].CompatibleVersion));
                    BufferIndex += sizeof(CompatibleVersionsMap[i].CompatibleVersion);
                    break;
                }
            }
        }
    }
    CXPLAT_DBG_ASSERT(BufferIndex <= *BufferLength);
    return QUIC_STATUS_SUCCESS;
}

QUIC_STATUS
QuicVersionNegotiationExtParseClientVerNegInfo(
    _In_reads_bytes_(BufferLength)
        const uint8_t* const Buffer,
    _In_ uint16_t BufferLength,
    _Out_ QUIC_CLIENT_VER_NEG_INFO* ClientVNI
    )
{
    uint16_t Offset = 0;
    if (BufferLength < sizeof(uint32_t)) {
        return QUIC_STATUS_INVALID_PARAMETER;
    }
    CxPlatCopyMemory(&ClientVNI->CurrentVersion, Buffer, sizeof(ClientVNI->CurrentVersion));
    Offset += sizeof(uint32_t);

    if (BufferLength - Offset < sizeof(uint32_t)) {
        return QUIC_STATUS_INVALID_PARAMETER;
    }

    CxPlatCopyMemory(&ClientVNI->PreviousVersion, Buffer + Offset, sizeof(ClientVNI->PreviousVersion));
    Offset += sizeof(uint32_t);

    if (!QuicVarIntDecode(BufferLength, Buffer, &Offset, &ClientVNI->RecvNegotiationVerCount)) {
        return QUIC_STATUS_INVALID_PARAMETER;
    }

    if (ClientVNI->RecvNegotiationVerCount > 0) {
        ClientVNI->RecvNegotiationVersions = (uint32_t*)Buffer + Offset;
    } else {
        ClientVNI->RecvNegotiationVersions = NULL;
    }
    Offset += (uint16_t)(ClientVNI->RecvNegotiationVerCount * sizeof(uint32_t));

    if (!QuicVarIntDecode(BufferLength, Buffer, &Offset, &ClientVNI->CompatibleVersionCount)) {
        return QUIC_STATUS_INVALID_PARAMETER;
    }

    if (ClientVNI->CompatibleVersionCount > 0) {
        ClientVNI->CompatibleVersions = (uint32_t*)Buffer + Offset;
    } else {
        ClientVNI->CompatibleVersions = NULL;
    }
    Offset += (uint16_t)(ClientVNI->CompatibleVersionCount * sizeof(uint32_t));
    CXPLAT_DBG_ASSERT(Offset == BufferLength);

    return QUIC_STATUS_SUCCESS;
}
