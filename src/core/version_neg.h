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
extern uint32_t DefaultSupportedVersionsList[];
extern uint32_t DefaultSupportedVersionsListLength;

//
// This list of compatible versions is for the default client version, QUIC_VERSION_1
//
extern uint32_t DefaultCompatibleVersionsList[];
extern uint32_t DefaultCompatibleVersionsListLength;

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
