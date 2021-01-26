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
    const uint32_t OriginalVersion;
    const uint32_t CompatibleVersion;
} QUIC_COMPATIBLE_VERSION_MAP;

const QUIC_COMPATIBLE_VERSION_MAP CompatibleVersionsMap[] = {
    {QUIC_VERSION_DRAFT_29, QUIC_VERSION_DRAFT_29},
    {QUIC_VERSION_MS_1, QUIC_VERSION_MS_1},
    {QUIC_VERSION_MS_1, QUIC_VERSION_1},
    {QUIC_VERSION_1, QUIC_VERSION_1},
    {QUIC_VERSION_1, QUIC_VERSION_MS_1}
};

//
// This list is the versions the server advertises support for.
//
const uint32_t DefaultSupportedVersionsList[] = {
    QUIC_VERSION_1,
    QUIC_VERSION_MS_1,
    QUIC_VERSION_DRAFT_29
};
const uint32_t DefaultSupportedVersionsListLength = ARRAYSIZE(DefaultSupportedVersionsList);

const uint32_t DefaultCompatibleVersionsList[] = {
    QUIC_VERSION_1,
    QUIC_VERSION_MS_1
};
const uint32_t DefaultCompatibleVersionsListLength = ARRAYSIZE(DefaultCompatibleVersionsList);

BOOLEAN
QuicVersionNegotiationExtIsVersionServerSupported(
    _In_ uint32_t Version
    )
{
    if (MsQuicLib.Settings.IsSet.DesiredVersionsList) {
        for (uint32_t i = 0; i < MsQuicLib.Settings.DesiredVersionsListLength; ++i) {
            if (MsQuicLib.Settings.DesiredVersionsList[i] == Version) {
                return TRUE;
            }
        }
        return FALSE;
    } else {
        return QuicIsVersionSupported(Version);
    }
}

BOOLEAN
QuicVersionNegotiationExtIsVersionClientSupported(
    _In_ QUIC_CONNECTION* Connection,
    _In_ uint32_t Version
    )
{
    if (Connection->Settings.IsSet.DesiredVersionsList) {
        for (uint32_t i = 0; i < Connection->Settings.DesiredVersionsListLength; ++i) {
            if (Connection->Settings.DesiredVersionsList[i] == Version) {
                return TRUE;
            }
        }
        return FALSE;
    } else {
        return QuicIsVersionSupported(Version);
    }
}

BOOLEAN
QuicVersionNegotiationExtAreVersionsCompatible(
    _In_ uint32_t OriginalVersion,
    _In_ uint32_t UpgradedVersion
    )
{
    for (unsigned i = 0; i < ARRAYSIZE(CompatibleVersionsMap); ++i) {
        if (CompatibleVersionsMap[i].OriginalVersion == OriginalVersion) {
            while (CompatibleVersionsMap[i].OriginalVersion == OriginalVersion) {
                if (CompatibleVersionsMap[i].CompatibleVersion == UpgradedVersion) {
                    return TRUE;
                }
                ++i;
            }
            return FALSE;
        }
    }
    return FALSE;
}

BOOLEAN
QuicVersionNegotiationExtIsVersionCompatible(
    _In_ QUIC_CONNECTION* Connection,
    _In_ uint32_t NegotiatedVersion
    )
{
    const uint32_t* CompatibleVersions;
    uint32_t CompatibleVersionsLength;
    if (Connection->Settings.IsSet.DesiredVersionsList) {
        CompatibleVersions = Connection->Settings.DesiredVersionsList;
        CompatibleVersionsLength = Connection->Settings.DesiredVersionsListLength;
    } else {
        CompatibleVersions = DefaultCompatibleVersionsList;
        CompatibleVersionsLength = DefaultCompatibleVersionsListLength;
    }

    for (uint32_t i = 0; i < CompatibleVersionsLength; ++i) {
        if (CompatibleVersions[i] == NegotiatedVersion) {
            return TRUE;
        }
    }

    return FALSE;
}

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

    if ((unsigned)(BufferLength - Offset) < sizeof(uint32_t)) {
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

QUIC_STATUS
QuicVersionNegotiationExtParseServerVerNegInfo(
    _In_reads_bytes_(BufferLength)
        const uint8_t* const Buffer,
    _In_ uint16_t BufferLength,
    _Out_ QUIC_SERVER_VER_NEG_INFO* ServerVNI
    )
{
    uint16_t Offset = 0;
    if (BufferLength < sizeof(uint32_t)) {
        return QUIC_STATUS_INVALID_PARAMETER;
    }
    CxPlatCopyMemory(&ServerVNI->NegotiatedVersion, Buffer, sizeof(ServerVNI->NegotiatedVersion));
    Offset += sizeof(uint32_t);

    if (!QuicVarIntDecode(BufferLength, Buffer, &Offset, &ServerVNI->SupportedVersionCount)) {
        return QUIC_STATUS_INVALID_PARAMETER;
    }

    if (ServerVNI->SupportedVersionCount > 0) {
        ServerVNI->SupportedVersions = (uint32_t*)Buffer + Offset;
    } else {
        ServerVNI->SupportedVersions = NULL;
    }
    Offset += (uint16_t)(ServerVNI->SupportedVersionCount * sizeof(uint32_t));
    CXPLAT_DBG_ASSERT(Offset == BufferLength);

    return QUIC_STATUS_SUCCESS;
}

_IRQL_requires_max_(DISPATCH_LEVEL)
_Success_(return != NULL)
const uint8_t*
QuicVersionNegotiationExtEncodeVersionNegotiationInfo(
    _In_ QUIC_CONNECTION* Connection,
    _Out_ uint32_t* VNInfoLength
    )
{
    uint32_t VNILen = 0;
    uint8_t* VNIBuf = NULL;
    uint8_t* VersionNegotiationInfo = NULL;
    *VNInfoLength = 0;
    if (QuicConnIsServer(Connection)) {
        const uint32_t* DesiredVersionsList = NULL;
        uint32_t DesiredVersionsListLength = 0;
        if (MsQuicLib.Settings.IsSet.DesiredVersionsList) {
            DesiredVersionsList = MsQuicLib.Settings.DesiredVersionsList;
            DesiredVersionsListLength = MsQuicLib.Settings.DesiredVersionsListLength;
        } else {
            DesiredVersionsList = DefaultSupportedVersionsList;
            DesiredVersionsListLength = DefaultSupportedVersionsListLength;
        }
        //
        // Generate Server VNI.
        //
        VNILen = 4 + QuicVarIntSize(DesiredVersionsListLength) +
            (DesiredVersionsListLength * sizeof(uint32_t));

        VersionNegotiationInfo = CXPLAT_ALLOC_NONPAGED(VNILen, QUIC_POOL_VER_NEG_INFO);
        if (VersionNegotiationInfo == NULL) {
            QuicTraceEvent(
                AllocFailure,
                "Allocation of '%s' failed. (%llu bytes)",
                "Server Version Negotiation Info",
                VNILen);
            return NULL;
        }
        VNIBuf = VersionNegotiationInfo;

        CxPlatCopyMemory(VNIBuf, &Connection->Stats.QuicVersion, sizeof(Connection->Stats.QuicVersion)); // TODO: test that this is getting set
        VNIBuf += 4;
        VNIBuf = QuicVarIntEncode(DesiredVersionsListLength, VNIBuf);
        CxPlatCopyMemory(
            VNIBuf,
            DesiredVersionsList,
            DesiredVersionsListLength * sizeof(uint32_t));
    } else {
        //
        // Generate Client VNI
        //
        uint32_t CompatibilityListLength = 0;
        VNILen = 4 + 4;
        if (Connection->Settings.IsSet.GeneratedCompatibleVersions) {
            VNILen +=
                QuicVarIntSize(Connection->Settings.GeneratedCompatibleVersionsListLength) +
                (Connection->Settings.GeneratedCompatibleVersionsListLength * sizeof(uint32_t));
        } else if (Connection->Settings.IsSet.DesiredVersionsList) {
            QuicVersionNegotiationExtGenerateCompatibleVersionsList(
                Connection->Stats.QuicVersion,
                Connection->Settings.DesiredVersionsList,
                Connection->Settings.DesiredVersionsListLength,
                NULL, &CompatibilityListLength);
            VNILen += QuicVarIntSize(CompatibilityListLength) + CompatibilityListLength;
        } else {
            VNILen +=
                QuicVarIntSize(DefaultSupportedVersionsList) +
                (DefaultSupportedVersionsListLength * sizeof(uint32_t));
        }
        VNILen +=
            QuicVarIntSize(Connection->ReceivedNegotiationVersionsLength) +
            (Connection->ReceivedNegotiationVersionsLength * sizeof(uint32_t));

        VersionNegotiationInfo = CXPLAT_ALLOC_NONPAGED(VNILen, QUIC_POOL_VER_NEG_INFO);
        if (VersionNegotiationInfo == NULL) {
            QuicTraceEvent(
                AllocFailure,
                "Allocation of '%s' failed. (%llu bytes)",
                "Client Version Negotiation Info",
                VNILen);
            return NULL;
        }
        VNIBuf = VersionNegotiationInfo;

        CxPlatCopyMemory(VNIBuf, &Connection->Stats.QuicVersion, sizeof(Connection->Stats.QuicVersion));
        VNIBuf += 4;
        CxPlatCopyMemory(VNIBuf, &Connection->PreviousQuicVersion, sizeof(Connection->PreviousQuicVersion));
        VNIBuf += 4;
        VNIBuf = QuicVarIntEncode(Connection->ReceivedNegotiationVersionsLength, VNIBuf);
        if (Connection->ReceivedNegotiationVersionsLength > 0) {
            CxPlatCopyMemory(
                VNIBuf,
                Connection->ReceivedNegotiationVersions,
                Connection->ReceivedNegotiationVersionsLength * sizeof(uint32_t));
            VNIBuf += Connection->ReceivedNegotiationVersionsLength;
        }
        if (Connection ->Settings.IsSet.GeneratedCompatibleVersions) {
            VNIBuf = QuicVarIntEncode(Connection->Settings.GeneratedCompatibleVersionsListLength, VNIBuf);
            CxPlatCopyMemory(
                VNIBuf,
                Connection->Settings.GeneratedCompatibleVersionsList,
                Connection->Settings.GeneratedCompatibleVersionsListLength * sizeof(uint32_t));
        } else if (Connection->Settings.IsSet.DesiredVersionsList) {
            VNIBuf = QuicVarIntEncode(CompatibilityListLength, VNIBuf);
            uint32_t RemainingBuffer = VNILen - (uint32_t)(VNIBuf - VersionNegotiationInfo);
            CXPLAT_DBG_ASSERT(RemainingBuffer == CompatibilityListLength);
            QuicVersionNegotiationExtGenerateCompatibleVersionsList(
                Connection->Stats.QuicVersion,
                Connection->Settings.DesiredVersionsList,
                Connection->Settings.DesiredVersionsListLength,
                VNIBuf,
                &RemainingBuffer);
        } else {
            VNIBuf = QuicVarIntEncode(DefaultSupportedVersionsListLength, VNIBuf);
            memcpy(VNIBuf, DefaultSupportedVersionsList, DefaultSupportedVersionsListLength * sizeof(uint32_t));
        }
    }
    *VNInfoLength = VNILen;
    return VersionNegotiationInfo;
}
