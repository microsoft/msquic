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
    {QUIC_VERSION_MS_1, QUIC_VERSION_1},
    {QUIC_VERSION_1, QUIC_VERSION_MS_1}
};

//
// This list is the versions the server advertises support for.
//
const uint32_t DefaultSupportedVersionsList[3] = {
    QUIC_VERSION_1,
    QUIC_VERSION_MS_1,
    QUIC_VERSION_DRAFT_29
};

BOOLEAN
QuicVersionNegotiationExtIsVersionServerSupported(
    _In_ uint32_t Version
    )
{
    if (MsQuicLib.Settings.IsSet.DesiredVersionsList) {
        if (QuicIsVersionReserved(Version)) {
            return FALSE;
        }
        for (uint32_t i = 0; i < MsQuicLib.Settings.DesiredVersionsListLength; ++i) {
            if (MsQuicLib.Settings.DesiredVersionsList[i] == Version) {
                return TRUE;
            }
        }
    } else {
        return QuicIsVersionSupported(Version);
    }
    return FALSE;
}

BOOLEAN
QuicVersionNegotiationExtIsVersionClientSupported(
    _In_ QUIC_CONNECTION* Connection,
    _In_ uint32_t Version
    )
{
    if (Connection->Settings.IsSet.DesiredVersionsList) {
        if (QuicIsVersionReserved(Version)) {
            return FALSE;
        }
        for (uint32_t i = 0; i < Connection->Settings.DesiredVersionsListLength; ++i) {
            if (Connection->Settings.DesiredVersionsList[i] == Version) {
                return TRUE;
            }
        }
    } else {
        return QuicIsVersionSupported(Version);
    }
    return FALSE;
}

BOOLEAN
QuicVersionNegotiationExtAreVersionsCompatible(
    _In_ uint32_t OriginalVersion,
    _In_ uint32_t UpgradedVersion
    )
{
    if (OriginalVersion == UpgradedVersion) {
        return TRUE;
    }
    for (unsigned i = 0; i < ARRAYSIZE(CompatibleVersionsMap); ++i) {
        if (CompatibleVersionsMap[i].OriginalVersion == OriginalVersion) {
            while (i < ARRAYSIZE(CompatibleVersionsMap) && CompatibleVersionsMap[i].OriginalVersion == OriginalVersion) {
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
        CompatibleVersions = MsQuicLib.DefaultCompatibilityList;
        CompatibleVersionsLength = MsQuicLib.DefaultCompatibilityListLength;
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
    uint32_t NeededBufferLength = sizeof(OriginalVersion);
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
    uint32_t Offset = 0;
    for (uint32_t i = 0; i < DesiredVersionsLength; ++i) {
        for (uint32_t j = 0; j < ARRAYSIZE(CompatibleVersionsMap); ++j) {
            if (CompatibleVersionsMap[j].OriginalVersion == OriginalVersion &&
                CompatibleVersionsMap[j].CompatibleVersion == DesiredVersions[i]) {
                CxPlatCopyMemory(
                    Buffer + Offset,
                    &CompatibleVersionsMap[j].CompatibleVersion,
                    sizeof(CompatibleVersionsMap[j].CompatibleVersion));
                Offset += sizeof(CompatibleVersionsMap[j].CompatibleVersion);
                break;
            }
        }
    }
    CxPlatCopyMemory(Buffer + Offset, &OriginalVersion, sizeof(uint32_t));
    Offset += sizeof(uint32_t);
    CXPLAT_DBG_ASSERT(Offset <= *BufferLength);
    return QUIC_STATUS_SUCCESS;
}

QUIC_STATUS
QuicVersionNegotiationExtParseVersionInfo(
    _In_ QUIC_CONNECTION* Connection,
    _In_reads_bytes_(BufferLength)
        const uint8_t* const Buffer,
    _In_ uint16_t BufferLength,
    _In_ BOOLEAN IsServer,
    _Out_ QUIC_VERSION_INFORMATION_V1* VersionInfo
    )
{
    const char* const Source = (IsServer ? "Server" : "Client");
    uint16_t Offset = 0;
    if (BufferLength < sizeof(uint32_t)) {
        QuicTraceLogConnError(
            VersionInfoDecodeFailed1,
            Connection,
            "%s version info too short to contain Chosen Version (%hu bytes)",
            Source,
            BufferLength);
        return QUIC_STATUS_INVALID_PARAMETER;
    }
    CxPlatCopyMemory(&VersionInfo->ChosenVersion, Buffer, sizeof(VersionInfo->ChosenVersion));
    Offset += sizeof(uint32_t);

    if ((unsigned)(BufferLength - Offset) < sizeof(uint32_t)) {
        QuicTraceLogConnError(
            VersionInfoDecodeFailed2,
            Connection,
            "%s version info too short to contain any Other Versions (%hu bytes)",
            Source,
            BufferLength);
        return QUIC_STATUS_INVALID_PARAMETER;
    }

    if ((BufferLength - Offset) % sizeof(uint32_t) > 0) {
        QuicTraceLogConnError(
            ServerVersionInfoDecodeFailed3,
            Connection,
            "%s version info contains partial Other Version (%hu bytes vs. %llu bytes)",
            Source,
            (unsigned)(BufferLength - Offset),
            (BufferLength - Offset) / sizeof(uint32_t));
        return QUIC_STATUS_INVALID_PARAMETER;
    }

    VersionInfo->OtherVersionsCount = (BufferLength - Offset) / sizeof(uint32_t);
    VersionInfo->OtherVersions = (uint32_t*)(Buffer + Offset);
    Offset += (uint16_t)(VersionInfo->OtherVersionsCount * sizeof(uint32_t));

    if (Offset != BufferLength) {
        QuicTraceLogConnError(
            ServerVersionInfoDecodeFailed4,
            Connection,
            "%s version info parsed less than full buffer (%hu bytes vs. %hu bytes",
            Source,
            Offset,
            BufferLength);
        return QUIC_STATUS_INVALID_PARAMETER;
    }

    QuicTraceLogConnInfo(
        ServerVersionInfoDecoded,
        Connection,
        "%s VI Decoded: Chosen Ver:%x Other Ver Count:%llu",
        Source,
        VersionInfo->ChosenVersion,
        VersionInfo->OtherVersionsCount);

    QuicTraceEvent(
        ConnVNEOtherVersionList,
        "[conn][%p] %s VI Other Versions List: %!VNL!",
        Connection,
        Source,
        CASTED_CLOG_BYTEARRAY(VersionInfo->OtherVersionsCount * sizeof(uint32_t), VersionInfo->OtherVersions));

    return QUIC_STATUS_SUCCESS;
}

_IRQL_requires_max_(DISPATCH_LEVEL)
_Success_(return != NULL)
const uint8_t*
QuicVersionNegotiationExtEncodeVersionInfo(
    _In_ QUIC_CONNECTION* Connection,
    _Out_ uint32_t* VNInfoLength
    )
{
    uint32_t VILen = 0;
    uint8_t* VIBuf = NULL;
    uint8_t* VersionInfo = NULL;
    *VNInfoLength = 0;
    if (QuicConnIsServer(Connection)) {
        const uint32_t* DesiredVersionsList = NULL;
        uint32_t DesiredVersionsListLength = 0;
        if (MsQuicLib.Settings.IsSet.DesiredVersionsList) {
            DesiredVersionsList = MsQuicLib.Settings.DesiredVersionsList;
            DesiredVersionsListLength = MsQuicLib.Settings.DesiredVersionsListLength;
        } else {
            DesiredVersionsList = DefaultSupportedVersionsList;
            DesiredVersionsListLength = ARRAYSIZE(DefaultSupportedVersionsList);
        }
        //
        // Generate Server VNI.
        //
        VILen = sizeof(uint32_t) + (DesiredVersionsListLength * sizeof(uint32_t));

        VersionInfo = CXPLAT_ALLOC_NONPAGED(VILen, QUIC_POOL_VERSION_INFO);
        if (VersionInfo == NULL) {
            QuicTraceEvent(
                AllocFailure,
                "Allocation of '%s' failed. (%llu bytes)",
                "Server Version Info",
                VILen);
            return NULL;
        }
        VIBuf = VersionInfo;

        _Analysis_assume_(VILen >= sizeof(uint32_t));
        CxPlatCopyMemory(VIBuf, &Connection->Stats.QuicVersion, sizeof(Connection->Stats.QuicVersion));
        VIBuf += sizeof(Connection->Stats.QuicVersion);
        CxPlatCopyMemory(
            VIBuf,
            DesiredVersionsList,
            DesiredVersionsListLength * sizeof(uint32_t));

        QuicTraceLogConnInfo(
            ServerVersionNegotiationInfoEncoded,
            Connection,
            "Server VNI Encoded: Chosen Ver:%x Other Ver Count:%u",
            Connection->Stats.QuicVersion,
            DesiredVersionsListLength);

        QuicTraceEvent(
            ConnVNEOtherVersionList,
            "[conn][%p] %s VI Other Versions List: %!VNL!",
            Connection,
            "Server",
            CASTED_CLOG_BYTEARRAY(DesiredVersionsListLength * sizeof(uint32_t), VIBuf));
    } else {
        //
        // Generate Client VNI
        //
        uint32_t CompatibilityListByteLength = 0;
        VILen = sizeof(Connection->Stats.QuicVersion);
        if (Connection->Settings.IsSet.DesiredVersionsList) {
            QuicVersionNegotiationExtGenerateCompatibleVersionsList(
                Connection->Stats.QuicVersion,
                Connection->Settings.DesiredVersionsList,
                Connection->Settings.DesiredVersionsListLength,
                NULL, &CompatibilityListByteLength);
            VILen += CompatibilityListByteLength;
        } else {
            VILen +=
                MsQuicLib.DefaultCompatibilityListLength * sizeof(uint32_t);
        }

        VersionInfo = CXPLAT_ALLOC_NONPAGED(VILen, QUIC_POOL_VERSION_INFO);
        if (VersionInfo == NULL) {
            QuicTraceEvent(
                AllocFailure,
                "Allocation of '%s' failed. (%llu bytes)",
                "Client Version Info",
                VILen);
            return NULL;
        }
        VIBuf = VersionInfo;

        _Analysis_assume_(VILen >= sizeof(uint32_t));
        CxPlatCopyMemory(VIBuf, &Connection->Stats.QuicVersion, sizeof(Connection->Stats.QuicVersion));
        VIBuf += sizeof(Connection->Stats.QuicVersion);
        if (Connection->Settings.IsSet.DesiredVersionsList) {
            uint32_t RemainingBuffer = VILen - (uint32_t)(VIBuf - VersionInfo);
            CXPLAT_DBG_ASSERT(RemainingBuffer == CompatibilityListByteLength);
            QuicVersionNegotiationExtGenerateCompatibleVersionsList(
                Connection->Stats.QuicVersion,
                Connection->Settings.DesiredVersionsList,
                Connection->Settings.DesiredVersionsListLength,
                VIBuf,
                &RemainingBuffer);
            CXPLAT_DBG_ASSERT(VILen == (uint32_t)(VIBuf - VersionInfo) + RemainingBuffer);
        } else {
            CxPlatCopyMemory(
                VIBuf,
                MsQuicLib.DefaultCompatibilityList,
                MsQuicLib.DefaultCompatibilityListLength * sizeof(uint32_t));
        }
        QuicTraceLogConnInfo(
            ClientVersionNegotiationInfoEncoded,
            Connection,
            "Client VNI Encoded: Current Ver:%x Prev Ver:%x Recv Ver Count:%u Compat Ver Count:%u",
            Connection->Stats.QuicVersion,
            Connection->PreviousQuicVersion,
            Connection->ReceivedNegotiationVersionsLength,
            CompatibilityListByteLength == 0 ?
                MsQuicLib.DefaultCompatibilityListLength :
                (uint32_t)(CompatibilityListByteLength / sizeof(uint32_t)));

        QuicTraceEvent(
            ConnVNEOtherVersionList,
            "[conn][%p] %s VI Other Versions List: %!VNL!",
            Connection,
            "Client",
            CASTED_CLOG_BYTEARRAY(
                CompatibilityListByteLength == 0 ?
                    MsQuicLib.DefaultCompatibilityListLength * sizeof(uint32_t):
                    CompatibilityListByteLength,
                VIBuf));
        }
    *VNInfoLength = VILen;
    return VersionInfo;
}
