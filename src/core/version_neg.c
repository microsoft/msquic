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
QuicVersionNegotiationExtParseClientVerNegInfo(
    _In_ QUIC_CONNECTION* Connection,
    _In_reads_bytes_(BufferLength)
        const uint8_t* const Buffer,
    _In_ uint16_t BufferLength,
    _Out_ QUIC_CLIENT_VER_NEG_INFO* ClientVNI
    )
{
    uint16_t Offset = 0;
    if (BufferLength < sizeof(uint32_t)) {
        QuicTraceLogConnError(
            ClientVersionNegotiationInfoDecodeFailed1,
            Connection,
            "Client version negotiation info too short to contain Current Version (%hu bytes)",
            BufferLength);
        return QUIC_STATUS_INVALID_PARAMETER;
    }
    CxPlatCopyMemory(&ClientVNI->CurrentVersion, Buffer, sizeof(ClientVNI->CurrentVersion));
    Offset += sizeof(uint32_t);

    if ((unsigned)(BufferLength - Offset) < sizeof(uint32_t)) {
        QuicTraceLogConnError(
            ClientVersionNegotiationInfoDecodeFailed2,
            Connection,
            "Client version negotiation info too short to contain Previous Version (%hu bytes)",
            BufferLength);
        return QUIC_STATUS_INVALID_PARAMETER;
    }

    CxPlatCopyMemory(&ClientVNI->PreviousVersion, Buffer + Offset, sizeof(ClientVNI->PreviousVersion));
    Offset += sizeof(uint32_t);

    if (!QuicVarIntDecode(BufferLength, Buffer, &Offset, &ClientVNI->RecvNegotiationVerCount)) {
        QuicTraceLogConnError(
            ClientVersionNegotiationInfoDecodeFailed3,
            Connection,
            "Client version negotiation info too short to contain Recv Negotiation Version count (%hu bytes)",
            BufferLength);
        return QUIC_STATUS_INVALID_PARAMETER;
    }

    if (ClientVNI->RecvNegotiationVerCount * sizeof(uint32_t) >= (uint64_t)BufferLength - Offset) {
        QuicTraceLogConnError(
            ClientVersionNegotiationInfoDecodeFailed4,
            Connection,
            "Client version negotiation info too short to contain Recv Negotiation Version list (%hu bytes vs. %llu bytes)",
            BufferLength,
            ClientVNI->RecvNegotiationVerCount * sizeof(uint32_t));
        return QUIC_STATUS_INVALID_PARAMETER;
    }

    if (ClientVNI->RecvNegotiationVerCount > 0) {
        ClientVNI->RecvNegotiationVersions = (uint32_t*)(Buffer + Offset);
        Offset += (uint16_t)(ClientVNI->RecvNegotiationVerCount * sizeof(uint32_t));
    } else {
        ClientVNI->RecvNegotiationVersions = NULL;
    }

    if (!QuicVarIntDecode(BufferLength, Buffer, &Offset, &ClientVNI->CompatibleVersionCount)) {
        QuicTraceLogConnError(
            ClientVersionNegotiationInfoDecodeFailed5,
            Connection,
            "Client version negotiation info too short to contain Compatible Version count (%hu bytes)",
            BufferLength);
        return QUIC_STATUS_INVALID_PARAMETER;
    }

    if (ClientVNI->CompatibleVersionCount * sizeof(uint32_t) > (uint64_t)BufferLength - Offset) {
        QuicTraceLogConnError(
            ClientVersionNegotiationInfoDecodeFailed6,
            Connection,
            "Client version negotiation info too short to contain Compatible Version list (%hu bytes vs. %llu bytes)",
            BufferLength,
            ClientVNI->CompatibleVersionCount * sizeof(uint32_t));
        return QUIC_STATUS_INVALID_PARAMETER;
    }

    if (ClientVNI->CompatibleVersionCount > 0) {
        ClientVNI->CompatibleVersions = (uint32_t*)(Buffer + Offset);
        Offset += (uint16_t)(ClientVNI->CompatibleVersionCount * sizeof(uint32_t));
    } else {
        ClientVNI->CompatibleVersions = NULL;
        QuicTraceLogConnError(
            ClientVersionNegotiationInfoDecodeFailed7,
            Connection,
            "Client version negotiation info has empty Compatible Version list");
        return QUIC_STATUS_INVALID_PARAMETER;
    }

    if (Offset != BufferLength) {
        QuicTraceLogConnError(
            ClientVersionNegotiationInfoDecodeFailed8,
            Connection,
            "Client version negotiation info parsed less than full buffer (%hu bytes vs. %hu bytes",
            Offset,
            BufferLength);
        return QUIC_STATUS_INVALID_PARAMETER;
    }

    QuicTraceLogConnInfo(
        ClientVersionNegotiationInfoDecoded,
        Connection,
        "Client VNI Decoded: Current Ver:%x Prev Ver:%x Recv Ver Count:%llu Compat Ver Count:%llu",
        ClientVNI->CurrentVersion,
        ClientVNI->PreviousVersion,
        ClientVNI->RecvNegotiationVerCount,
        ClientVNI->CompatibleVersionCount);

    QuicTraceEvent(
        ConnClientCompatibleVersionList,
        "[conn][%p] Client VNI Compatible Version List: %!VNL!",
        Connection,
        CLOG_BYTEARRAY(ClientVNI->CompatibleVersionCount * sizeof(uint32_t), ClientVNI->CompatibleVersions));

    QuicTraceEvent(
        ConnClientReceivedVersionList,
        "[conn][%p] Client VNI Received Version List: %!VNL!",
        Connection,
        CLOG_BYTEARRAY(ClientVNI->RecvNegotiationVerCount * sizeof(uint32_t), ClientVNI->RecvNegotiationVersions));

    return QUIC_STATUS_SUCCESS;
}

QUIC_STATUS
QuicVersionNegotiationExtParseServerVerNegInfo(
    _In_ QUIC_CONNECTION* Connection,
    _In_reads_bytes_(BufferLength)
        const uint8_t* const Buffer,
    _In_ uint16_t BufferLength,
    _Out_ QUIC_SERVER_VER_NEG_INFO* ServerVNI
    )
{
    uint16_t Offset = 0;
    if (BufferLength < sizeof(uint32_t)) {
        QuicTraceLogConnError(
            ServerVersionNegotiationInfoDecodeFailed1,
            Connection,
            "Server version negotiation info too short to contain Negotiated Version (%hu bytes)",
            BufferLength);
        return QUIC_STATUS_INVALID_PARAMETER;
    }
    CxPlatCopyMemory(&ServerVNI->NegotiatedVersion, Buffer, sizeof(ServerVNI->NegotiatedVersion));
    Offset += sizeof(uint32_t);

    if (!QuicVarIntDecode(BufferLength, Buffer, &Offset, &ServerVNI->SupportedVersionCount)) {
        QuicTraceLogConnError(
            ServerVersionNegotiationInfoDecodeFailed2,
            Connection,
            "Server version negotiation info too short to contain Supported Version count (%hu bytes)",
            BufferLength);
        return QUIC_STATUS_INVALID_PARAMETER;
    }

    if (ServerVNI->SupportedVersionCount * sizeof(uint32_t) > (uint64_t)BufferLength - Offset) {
        QuicTraceLogConnError(
            ServerVersionNegotiationInfoDecodeFailed3,
            Connection,
            "Server version negotiation info too short to contain Supported Versions list (%hu bytes vs. %llu bytes)",
            BufferLength,
            ServerVNI->SupportedVersionCount * sizeof(uint32_t));
        return QUIC_STATUS_INVALID_PARAMETER;
    }

    if (ServerVNI->SupportedVersionCount > 0) {
        ServerVNI->SupportedVersions = (uint32_t*)(Buffer + Offset);
        Offset += (uint16_t)(ServerVNI->SupportedVersionCount * sizeof(uint32_t));
    } else {
        ServerVNI->SupportedVersions = NULL;
        QuicTraceLogConnError(
            ServerVersionNegotiationInfoDecodeFailed4,
            Connection,
            "Server version negotiation info has empty Supported Versions list");
        return QUIC_STATUS_INVALID_PARAMETER;
    }
    if (Offset != BufferLength) {
        QuicTraceLogConnError(
            ServerVersionNegotiationInfoDecodeFailed5,
            Connection,
            "Server version negotiation info parsed less than full buffer (%hu bytes vs. %hu bytes",
            Offset,
            BufferLength);
        return QUIC_STATUS_INVALID_PARAMETER;
    }

    QuicTraceLogConnInfo(
        ServerVersionNegotiationInfoDecoded,
        Connection,
        "Server VNI Decoded: Negotiated Ver:%x Supported Ver Count:%llu",
        ServerVNI->NegotiatedVersion,
        ServerVNI->SupportedVersionCount);

    QuicTraceEvent(
        ConnServerSupportedVersionList,
        "[conn][%p] Server VNI Supported Version List: %!VNL!",
        Connection,
        CLOG_BYTEARRAY(ServerVNI->SupportedVersionCount * sizeof(uint32_t), ServerVNI->SupportedVersions));

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
            DesiredVersionsListLength = ARRAYSIZE(DefaultSupportedVersionsList);
        }
        //
        // Generate Server VNI.
        //
        VNILen = sizeof(uint32_t) + QuicVarIntSize(DesiredVersionsListLength) +
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

        CxPlatCopyMemory(VNIBuf, &Connection->Stats.QuicVersion, sizeof(Connection->Stats.QuicVersion));
        VNIBuf += sizeof(Connection->Stats.QuicVersion);
        VNIBuf = QuicVarIntEncode(DesiredVersionsListLength, VNIBuf);
        CxPlatCopyMemory(
            VNIBuf,
            DesiredVersionsList,
            DesiredVersionsListLength * sizeof(uint32_t));

        QuicTraceLogConnInfo(
            ServerVersionNegotiationInfoEncoded,
            Connection,
            "Server VNI Encoded: Negotiated Ver:%x Supported Ver Count:%u",
            Connection->Stats.QuicVersion,
            DesiredVersionsListLength);

        QuicTraceEvent(
            ConnServerSupportedVersionList,
            "[conn][%p] Server VNI Supported Version List: %!VNL!",
            Connection,
            CLOG_BYTEARRAY(DesiredVersionsListLength * sizeof(uint32_t), VNIBuf));
    } else {
        //
        // Generate Client VNI
        //
        uint32_t CompatibilityListByteLength = 0;
        VNILen = sizeof(Connection->Stats.QuicVersion) + sizeof(Connection->PreviousQuicVersion);
        if (Connection->Settings.IsSet.DesiredVersionsList) {
            QuicVersionNegotiationExtGenerateCompatibleVersionsList(
                Connection->Stats.QuicVersion,
                Connection->Settings.DesiredVersionsList,
                Connection->Settings.DesiredVersionsListLength,
                NULL, &CompatibilityListByteLength);
            VNILen += QuicVarIntSize(CompatibilityListByteLength / sizeof(uint32_t)) + CompatibilityListByteLength;
        } else {
            VNILen +=
                QuicVarIntSize(MsQuicLib.DefaultCompatibilityListLength) +
                (MsQuicLib.DefaultCompatibilityListLength * sizeof(uint32_t));
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

        _Analysis_assume_(VNILen >= sizeof(uint32_t) + sizeof(uint32_t));
        CxPlatCopyMemory(VNIBuf, &Connection->Stats.QuicVersion, sizeof(Connection->Stats.QuicVersion));
        VNIBuf += sizeof(Connection->Stats.QuicVersion);
        CxPlatCopyMemory(VNIBuf, &Connection->PreviousQuicVersion, sizeof(Connection->PreviousQuicVersion));
        VNIBuf += sizeof(Connection->PreviousQuicVersion);
        VNIBuf = QuicVarIntEncode(Connection->ReceivedNegotiationVersionsLength, VNIBuf);
        if (Connection->ReceivedNegotiationVersionsLength > 0) {
            CxPlatCopyMemory(
                VNIBuf,
                Connection->ReceivedNegotiationVersions,
                Connection->ReceivedNegotiationVersionsLength * sizeof(uint32_t));
            VNIBuf += (Connection->ReceivedNegotiationVersionsLength * sizeof(uint32_t));
        }
        if (Connection->Settings.IsSet.DesiredVersionsList) {
            VNIBuf = QuicVarIntEncode(CompatibilityListByteLength / sizeof(uint32_t), VNIBuf);
            uint32_t RemainingBuffer = VNILen - (uint32_t)(VNIBuf - VersionNegotiationInfo);
            CXPLAT_DBG_ASSERT(RemainingBuffer == CompatibilityListByteLength);
            QuicVersionNegotiationExtGenerateCompatibleVersionsList(
                Connection->Stats.QuicVersion,
                Connection->Settings.DesiredVersionsList,
                Connection->Settings.DesiredVersionsListLength,
                VNIBuf,
                &RemainingBuffer);
            CXPLAT_DBG_ASSERT(VNILen == (uint32_t)(VNIBuf - VersionNegotiationInfo) + RemainingBuffer);
        } else {
            VNIBuf = QuicVarIntEncode(MsQuicLib.DefaultCompatibilityListLength, VNIBuf);
            CxPlatCopyMemory(
                VNIBuf,
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

        #ifdef BUGBUG
        uicTraceEvent(
            ConnClientCompatibleVersionList,
            "[conn][%p] Client VNI Compatible Version List: %!VNL!",
            Connection,
            CLOG_BYTEARRAY(
                CompatibilityListByteLength == 0 ?
                    MsQuicLib.DefaultCompatibilityListLength * sizeof(uint32_t):
                    CompatibilityListByteLength,
                VNIBuf));
        #endif

        QuicTraceEvent(
            ConnClientReceivedVersionList,
            "[conn][%p] Client VNI Received Version List: %!VNL!",
            Connection,
            CLOG_BYTEARRAY(
                Connection->ReceivedNegotiationVersionsLength * sizeof(uint32_t),
                Connection->ReceivedNegotiationVersions));
        }
    *VNInfoLength = VNILen;
    return VersionNegotiationInfo;
}
