/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.

Abstract:

    This file contains definitions for version negotiation.

--*/

#pragma once

//
// This list is the versions that the server advertises support for.
//
extern const uint32_t DefaultSupportedVersionsList[];
extern const uint32_t DefaultSupportedVersionsListLength;

//
// This list of compatible versions is for the default client version, QUIC_VERSION_1
//
extern const uint32_t DefaultCompatibleVersionsList[];
extern const uint32_t DefaultCompatibleVersionsListLength;

typedef struct QUIC_CLIENT_VER_NEG_INFO {
    uint32_t CurrentVersion;
    uint32_t PreviousVersion;
    QUIC_VAR_INT RecvNegotiationVerCount;
    const uint32_t* RecvNegotiationVersions;
    QUIC_VAR_INT CompatibleVersionCount;
    const uint32_t* CompatibleVersions;
} QUIC_CLIENT_VER_NEG_INFO;

typedef struct QUIC_SERVER_VER_NEG_INFO {
    uint32_t NegotiatedVersion;
    QUIC_VAR_INT SupportedVersionCount;
    const uint32_t* SupportedVersions;
} QUIC_SERVER_VER_NEG_INFO;

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
    _In_reads_bytes_(DesiredVersionsLength * sizeof(uint32_t))
        const uint32_t* const DesiredVersions,
    _In_ uint32_t DesiredVersionsLength,
    _Out_writes_bytes_(*BufferLength) uint8_t* Buffer,
    _Inout_ uint32_t* BufferLength
    );

QUIC_STATUS
QuicVersionNegotiationExtParseClientVerNegInfo(
    _In_reads_bytes_(BufferLength)
        const uint8_t* const Buffer,
    _In_ uint16_t BufferLength,
    _Out_ QUIC_CLIENT_VER_NEG_INFO* ClientVNI
    );

QUIC_STATUS
QuicVersionNegotiationExtParseServerVerNegInfo(
    _In_reads_bytes_(BufferLength)
        const uint8_t* const Buffer,
    _In_ uint16_t BufferLength,
    _Out_ QUIC_SERVER_VER_NEG_INFO* ServerVNI
    );

//
// Encodes Version Negotiation Information into the opaque blob used by the
// extension.
//
_IRQL_requires_max_(DISPATCH_LEVEL)
_Success_(return != NULL)
const uint8_t*
QuicVersionNegotiationExtEncodeVersionNegotiationInfo(
    _In_ QUIC_CONNECTION* Connection,
    _Out_ uint32_t* VNInfoLength
    );
