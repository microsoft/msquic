/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.

Abstract:

    This file contains definitions for version negotiation.

--*/

#pragma once

#if defined(__cplusplus)
extern "C" {
#endif

//
// This list is the versions that the server advertises support for.
//
extern const uint32_t DefaultSupportedVersionsList[4];

typedef struct QUIC_VERSION_INFORMATION_V1 {
    uint32_t ChosenVersion;
    uint32_t OtherVersionsCount;
    const uint32_t* OtherVersions;
} QUIC_VERSION_INFORMATION_V1;

#define MIN_VERSION_INFO_LENGTH sizeof(uint32_t)

BOOLEAN
QuicVersionNegotiationExtIsVersionServerSupported(
    _In_ uint32_t Version
    );

BOOLEAN
QuicVersionNegotiationExtIsVersionClientSupported(
    _In_ QUIC_CONNECTION* Connection,
    _In_ uint32_t Version
    );

BOOLEAN
QuicVersionNegotiationExtAreVersionsCompatible(
    _In_ uint32_t OriginalVersion,
    _In_ uint32_t UpgradedVersion
    );

BOOLEAN
QuicVersionNegotiationExtIsVersionCompatible(
    _In_ QUIC_CONNECTION* Connection,
    _In_ uint32_t NegotiatedVersion
    );

QUIC_STATUS
QuicVersionNegotiationExtGenerateCompatibleVersionsList(
    _In_ uint32_t OriginalVersion,
    _In_reads_bytes_(FullyDeployedVersionsLength * sizeof(uint32_t))
        const uint32_t* const FullyDeployedVersions,
    _In_ uint32_t FullyDeployedVersionsLength,
    _Out_writes_bytes_(*BufferLength) uint8_t* Buffer,
    _Inout_ uint32_t* BufferLength
    );

QUIC_STATUS
QuicVersionNegotiationExtParseVersionInfo(
    _In_ QUIC_CONNECTION* Connection,
    _In_reads_bytes_(BufferLength)
        const uint8_t* const Buffer,
    _In_ uint16_t BufferLength,
    _Out_ QUIC_VERSION_INFORMATION_V1* VersionInfo
    );

//
// Encodes Version Information into the opaque blob used by the extension.
//
_IRQL_requires_max_(PASSIVE_LEVEL)
__drv_allocatesMem(Mem)
_Must_inspect_result_
_Success_(return != NULL)
_Ret_writes_bytes_(*VerInfoLength)
const uint8_t*
QuicVersionNegotiationExtEncodeVersionInfo(
    _In_ QUIC_CONNECTION* Connection,
    _Out_ uint32_t* VerInfoLength
    );

#if defined(__cplusplus)
}
#endif
