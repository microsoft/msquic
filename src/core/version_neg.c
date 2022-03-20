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
    {QUIC_VERSION_1, QUIC_VERSION_MS_1},
    {QUIC_VERSION_1, QUIC_VERSION_2}
};

//
// This list is the versions the server advertises support for.
//
const uint32_t DefaultSupportedVersionsList[4] = {
    QUIC_VERSION_2,
    QUIC_VERSION_1,
    QUIC_VERSION_MS_1,
    QUIC_VERSION_DRAFT_29,
};

BOOLEAN
QuicVersionNegotiationExtIsVersionServerSupported(
    _In_ uint32_t Version
    )
{
    if (MsQuicLib.Settings.IsSet.VersionSettings) {
        if (QuicIsVersionReserved(Version)) {
            return FALSE;
        }
        for (uint32_t i = 0; i < MsQuicLib.Settings.VersionSettings->AcceptableVersionsLength; ++i) {
            if (MsQuicLib.Settings.VersionSettings->AcceptableVersions[i] == Version) {
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
    if (Connection->Settings.IsSet.VersionSettings) {
        if (QuicIsVersionReserved(Version)) {
            return FALSE;
        }
        for (uint32_t i = 0; i < Connection->Settings.VersionSettings->FullyDeployedVersionsLength; ++i) {
            if (Connection->Settings.VersionSettings->FullyDeployedVersions[i] == Version) {
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
    if (Connection->Settings.IsSet.VersionSettings) {
        uint32_t* CompatibleVersions = Connection->Settings.VersionSettings->FullyDeployedVersions;
        uint32_t CompatibleVersionsLength = Connection->Settings.VersionSettings->FullyDeployedVersionsLength;

        for (uint32_t i = 0; i < CompatibleVersionsLength; ++i) {
            if (QuicVersionNegotiationExtAreVersionsCompatible(CompatibleVersions[i], NegotiatedVersion)) {
                return TRUE;
            }
        }
    } else {
        for (uint32_t i = 0; i < MsQuicLib.DefaultCompatibilityListLength; ++i) {
            if (MsQuicLib.DefaultCompatibilityList[i] == NegotiatedVersion) {
                return TRUE;
            }
        }
    }

    return FALSE;
}

QUIC_STATUS
QuicVersionNegotiationExtGenerateCompatibleVersionsList(
    _In_ uint32_t OriginalVersion,
    _In_reads_bytes_(FullyDeployedVersionsLength * sizeof(uint32_t))
        const uint32_t* const FullyDeployedVersions,
    _In_ uint32_t FullyDeployedVersionsLength,
    _Out_writes_bytes_(*BufferLength) uint8_t* Buffer,
    _Inout_ uint32_t* BufferLength
    )
{
    uint32_t NeededBufferLength = sizeof(OriginalVersion);
    for (uint32_t i = 0; i < ARRAYSIZE(CompatibleVersionsMap); ++i) {
        if (CompatibleVersionsMap[i].OriginalVersion == OriginalVersion) {
            for (uint32_t j = 0; j < FullyDeployedVersionsLength; ++j) {
                if (CompatibleVersionsMap[i].CompatibleVersion == FullyDeployedVersions[j]) {
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
    uint32_t Offset = sizeof(uint32_t);
    CxPlatCopyMemory(Buffer, &OriginalVersion, sizeof(uint32_t));
    for (uint32_t i = 0; i < FullyDeployedVersionsLength; ++i) {
        for (uint32_t j = 0; j < ARRAYSIZE(CompatibleVersionsMap); ++j) {
            if (CompatibleVersionsMap[j].OriginalVersion == OriginalVersion &&
                CompatibleVersionsMap[j].CompatibleVersion == FullyDeployedVersions[i]) {
                CxPlatCopyMemory(
                    Buffer + Offset,
                    &CompatibleVersionsMap[j].CompatibleVersion,
                    sizeof(CompatibleVersionsMap[j].CompatibleVersion));
                Offset += sizeof(CompatibleVersionsMap[j].CompatibleVersion);
                break;
            }
        }
    }
    CXPLAT_DBG_ASSERT(Offset <= *BufferLength);
    return QUIC_STATUS_SUCCESS;
}

QUIC_STATUS
QuicVersionNegotiationExtParseVersionInfo(
    _In_ QUIC_CONNECTION* Connection,
    _In_reads_bytes_(BufferLength)
        const uint8_t* const Buffer,
    _In_ uint16_t BufferLength,
    _Out_ QUIC_VERSION_INFORMATION_V1* VersionInfo
    )
{
    uint16_t Offset = 0;
    if (BufferLength < sizeof(uint32_t)) {
        QuicTraceLogConnError(
            VersionInfoDecodeFailed1,
            Connection,
            "Version info too short to contain Chosen Version (%hu bytes)",
            BufferLength);
        return QUIC_STATUS_INVALID_PARAMETER;
    }
    CxPlatCopyMemory(&VersionInfo->ChosenVersion, Buffer, sizeof(VersionInfo->ChosenVersion));
    Offset += sizeof(uint32_t);

    if (QuicConnIsServer(Connection)) {
        //
        // Client-sent Version Info *MUST* contain OtherVersions.
        //
        if ((unsigned)(BufferLength - Offset) < sizeof(uint32_t)) {
            QuicTraceLogConnError(
                VersionInfoDecodeFailed2,
                Connection,
                "Version info too short to contain any Other Versions (%hu bytes)",
                (unsigned)(BufferLength - Offset));
            return QUIC_STATUS_INVALID_PARAMETER;
        }
    }

    if ((BufferLength - Offset) % sizeof(uint32_t) > 0) {
        QuicTraceLogConnError(
            ServerVersionInfoDecodeFailed3,
            Connection,
            "Version info contains partial Other Version (%hu bytes vs. %u bytes)",
            (unsigned)(BufferLength - Offset),
            (BufferLength - Offset) / (unsigned)sizeof(uint32_t));
        return QUIC_STATUS_INVALID_PARAMETER;
    }

    VersionInfo->OtherVersionsCount = (BufferLength - Offset) / sizeof(uint32_t);
    VersionInfo->OtherVersions = (uint32_t*)(Buffer + Offset);
    Offset += (uint16_t)(VersionInfo->OtherVersionsCount * sizeof(uint32_t));

    if (Offset != BufferLength) {
        QuicTraceLogConnError(
            ServerVersionInfoDecodeFailed4,
            Connection,
            "Version info parsed less than full buffer (%hu bytes vs. %hu bytes",
            Offset,
            BufferLength);
        return QUIC_STATUS_INVALID_PARAMETER;
    }

    QuicTraceLogConnInfo(
        ServerVersionInfoDecoded,
        Connection,
        "VerInfo Decoded: Chosen Ver:%x Other Ver Count:%u",
        VersionInfo->ChosenVersion,
        VersionInfo->OtherVersionsCount);

    QuicTraceEvent(
        ConnVNEOtherVersionList,
        "[conn][%p] VerInfo Other Versions List: %!VNL!",
        Connection,
        CASTED_CLOG_BYTEARRAY(VersionInfo->OtherVersionsCount * sizeof(uint32_t), VersionInfo->OtherVersions));

    return QUIC_STATUS_SUCCESS;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
__drv_allocatesMem(Mem)
_Must_inspect_result_
_Success_(return != NULL)
_Ret_writes_bytes_(*VerInfoLength)
const uint8_t*
QuicVersionNegotiationExtEncodeVersionInfo(
    _In_ QUIC_CONNECTION* Connection,
    _Out_ uint32_t* VerInfoLength
    )
{
    uint32_t VILen = 0;
    uint8_t* VIBuf = NULL;
    uint8_t* VersionInfo = NULL;
    *VerInfoLength = 0;
    if (QuicConnIsServer(Connection)) {
        const uint32_t* OtherVersionsList = NULL;
        uint32_t OtherVersionsListLength = 0;
        if (MsQuicLib.Settings.IsSet.VersionSettings) {
            OtherVersionsList = MsQuicLib.Settings.VersionSettings->FullyDeployedVersions;
            OtherVersionsListLength = MsQuicLib.Settings.VersionSettings->FullyDeployedVersionsLength;
        } else {
            OtherVersionsList = DefaultSupportedVersionsList;
            OtherVersionsListLength = ARRAYSIZE(DefaultSupportedVersionsList);
        }
        //
        // Generate Server Version Info.
        //
        VILen = sizeof(uint32_t) + (OtherVersionsListLength * sizeof(uint32_t));
        CXPLAT_DBG_ASSERT((OtherVersionsListLength * sizeof(uint32_t)) + sizeof(uint32_t) > OtherVersionsListLength + sizeof(uint32_t));

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

        CXPLAT_DBG_ASSERT(VILen >= sizeof(uint32_t));
        CxPlatCopyMemory(VIBuf, &Connection->Stats.QuicVersion, sizeof(Connection->Stats.QuicVersion));
        VIBuf += sizeof(Connection->Stats.QuicVersion);
        CXPLAT_DBG_ASSERT(VILen - sizeof(uint32_t) == OtherVersionsListLength * sizeof(uint32_t));
        CxPlatCopyMemory(
            VIBuf,
            OtherVersionsList,
            OtherVersionsListLength * sizeof(uint32_t));

        QuicTraceLogConnInfo(
            ServerVersionNegotiationInfoEncoded,
            Connection,
            "Server VI Encoded: Chosen Ver:%x Other Ver Count:%u",
            Connection->Stats.QuicVersion,
            OtherVersionsListLength);

        QuicTraceEvent(
            ConnVNEOtherVersionList,
            "[conn][%p] VerInfo Other Versions List: %!VNL!",
            Connection,
            CASTED_CLOG_BYTEARRAY(OtherVersionsListLength * sizeof(uint32_t), VIBuf));
    } else {
        //
        // Generate Client Version Info.
        //
        uint32_t CompatibilityListByteLength = 0;
        VILen = sizeof(Connection->Stats.QuicVersion);
        if (Connection->Settings.IsSet.VersionSettings) {
            QuicVersionNegotiationExtGenerateCompatibleVersionsList(
                Connection->Stats.QuicVersion,
                Connection->Settings.VersionSettings->FullyDeployedVersions,
                Connection->Settings.VersionSettings->FullyDeployedVersionsLength,
                NULL, &CompatibilityListByteLength);
            VILen += CompatibilityListByteLength;
        } else {
            CXPLAT_DBG_ASSERT(MsQuicLib.DefaultCompatibilityListLength * (uint32_t)sizeof(uint32_t) > MsQuicLib.DefaultCompatibilityListLength);
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

        CXPLAT_DBG_ASSERT(VILen >= sizeof(uint32_t));
        CxPlatCopyMemory(VIBuf, &Connection->Stats.QuicVersion, sizeof(Connection->Stats.QuicVersion));
        VIBuf += sizeof(Connection->Stats.QuicVersion);
        if (Connection->Settings.IsSet.VersionSettings) {
            uint32_t RemainingBuffer = VILen - (uint32_t)(VIBuf - VersionInfo);
            CXPLAT_DBG_ASSERT(RemainingBuffer == CompatibilityListByteLength);
            QuicVersionNegotiationExtGenerateCompatibleVersionsList(
                Connection->Stats.QuicVersion,
                Connection->Settings.VersionSettings->FullyDeployedVersions,
                Connection->Settings.VersionSettings->FullyDeployedVersionsLength,
                VIBuf,
                &RemainingBuffer);
            CXPLAT_DBG_ASSERT(VILen == (uint32_t)(VIBuf - VersionInfo) + RemainingBuffer);
        } else {
            CXPLAT_DBG_ASSERT(VILen - sizeof(uint32_t) == MsQuicLib.DefaultCompatibilityListLength * sizeof(uint32_t));
            CxPlatCopyMemory(
                VIBuf,
                MsQuicLib.DefaultCompatibilityList,
                MsQuicLib.DefaultCompatibilityListLength * sizeof(uint32_t));
        }
        QuicTraceLogConnInfo(
            ClientVersionInfoEncoded,
            Connection,
            "Client VI Encoded: Current Ver:%x Prev Ver:%x Compat Ver Count:%u",
            Connection->Stats.QuicVersion,
            Connection->PreviousQuicVersion,
            CompatibilityListByteLength == 0 ?
                MsQuicLib.DefaultCompatibilityListLength :
                (uint32_t)(CompatibilityListByteLength / sizeof(uint32_t)));

        QuicTraceEvent(
            ConnVNEOtherVersionList,
            "[conn][%p] VerInfo Other Versions List: %!VNL!",
            Connection,
            CASTED_CLOG_BYTEARRAY(
                CompatibilityListByteLength == 0 ?
                    MsQuicLib.DefaultCompatibilityListLength * sizeof(uint32_t):
                    CompatibilityListByteLength,
                VIBuf));
        }
    *VerInfoLength = VILen;
    return VersionInfo;
}
