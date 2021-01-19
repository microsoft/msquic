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

QUIC_STATUS
QuicVersionNegotiationExtGenerateCompatibleVersionsList(
    _In_ uint32_t OriginalVersion,
    _Out_writes_bytes_(*BufferLength) uint8_t* Buffer,
    _Inout_ uint32_t* BufferLength
    );
