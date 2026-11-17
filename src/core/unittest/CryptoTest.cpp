/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.

Abstract:

    Unit tests for the Initial packet key derivation when the QUIC version
    changes, for example during compatible version negotiation.

--*/

#include "main.h"
#ifdef QUIC_CLOG
#include "CryptoTest.cpp.clog.h"
#endif

static const uint8_t OriginalDestCidData[] = {
    0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88
};

//
// Simulates a Source Connection ID chosen by the server, which is different
// from the client's original Destination Connection ID.
//
static const uint8_t ServerSourceCidData[] = {
    0x9a, 0x8b, 0x7c, 0x6d, 0x5e, 0x4f, 0x30, 0x21, 0x12, 0x03,
    0xf4, 0xe5, 0xd6, 0xc7, 0xb8, 0xa9, 0x9a, 0x8b, 0x7c, 0x6d
};

class CryptoTest : public ::testing::Test {
protected:
    QUIC_CONNECTION Connection {};
    const QUIC_VERSION_INFO* VersionInfo {nullptr};
    QUIC_CID* OriginalDestCid {nullptr};
    QUIC_CID_LIST_ENTRY* ServerDestCid {nullptr};

    void SetUp() override
    {
        for (uint32_t i = 0; i < ARRAYSIZE(QuicSupportedVersionList); ++i) {
            if (QuicSupportedVersionList[i].Number == QUIC_VERSION_2) {
                VersionInfo = &QuicSupportedVersionList[i];
                break;
            }
        }
        ASSERT_NE(nullptr, VersionInfo);

        Connection._.Type = QUIC_HANDLE_TYPE_CONNECTION_CLIENT;
        Connection.Stats.QuicVersion = QUIC_VERSION_2;
        Connection.Crypto.Initialized = TRUE;
        CxPlatListInitializeHead(&Connection.DestCids);

        OriginalDestCid =
            (QUIC_CID*)CXPLAT_ALLOC_NONPAGED(
                sizeof(QUIC_CID) + sizeof(OriginalDestCidData),
                QUIC_POOL_CID);
        ASSERT_NE(nullptr, OriginalDestCid);
        CxPlatZeroMemory(OriginalDestCid, sizeof(QUIC_CID));
        OriginalDestCid->Length = (uint8_t)sizeof(OriginalDestCidData);
        CxPlatCopyMemory(
            OriginalDestCid->Data,
            OriginalDestCidData,
            sizeof(OriginalDestCidData));
        Connection.OrigDestCID = OriginalDestCid;

        ServerDestCid =
            QuicCidNewDestination(
                (uint8_t)sizeof(ServerSourceCidData),
                ServerSourceCidData);
        ASSERT_NE(nullptr, ServerDestCid);
        CxPlatListInsertTail(&Connection.DestCids, &ServerDestCid->Link);
    }

    void TearDown() override
    {
        for (size_t i = 0; i < QUIC_PACKET_KEY_COUNT; ++i) {
            if (Connection.Crypto.TlsState.ReadKeys[i] != nullptr) {
                QuicPacketKeyFree(Connection.Crypto.TlsState.ReadKeys[i]);
                Connection.Crypto.TlsState.ReadKeys[i] = nullptr;
            }
            if (Connection.Crypto.TlsState.WriteKeys[i] != nullptr) {
                QuicPacketKeyFree(Connection.Crypto.TlsState.WriteKeys[i]);
                Connection.Crypto.TlsState.WriteKeys[i] = nullptr;
            }
        }

        if (ServerDestCid != nullptr) {
            CxPlatListEntryRemove(&ServerDestCid->Link);
            CXPLAT_FREE(ServerDestCid, QUIC_POOL_CIDLIST);
            ServerDestCid = nullptr;
        }

        if (OriginalDestCid != nullptr) {
            CXPLAT_FREE(OriginalDestCid, QUIC_POOL_CID);
            OriginalDestCid = nullptr;
        }
        Connection.OrigDestCID = nullptr;
    }

    void DeriveExpectedKeys(
        _In_reads_(CidLength) const uint8_t* Cid,
        _In_ uint8_t CidLength,
        _Out_ QUIC_PACKET_KEY** ReadKey,
        _Out_ QUIC_PACKET_KEY** WriteKey
        )
    {
        ASSERT_NE(nullptr, VersionInfo);
        QUIC_STATUS Status =
            QuicPacketKeyCreateInitial(
                FALSE,
                &VersionInfo->HkdfLabels,
                VersionInfo->Salt,
                CidLength,
                Cid,
                ReadKey,
                WriteKey);
        ASSERT_FALSE(QUIC_FAILED(Status));
        ASSERT_NE(nullptr, *ReadKey);
        ASSERT_NE(nullptr, *WriteKey);
    }

    static void AssertKeysMatch(
        _In_ const QUIC_PACKET_KEY* Actual,
        _In_ const QUIC_PACKET_KEY* Expected
        )
    {
        ASSERT_NE(nullptr, Actual);
        ASSERT_NE(nullptr, Expected);
        ASSERT_EQ(0, memcmp(Actual->Iv, Expected->Iv, CXPLAT_IV_LENGTH));

        uint8_t Sample[CXPLAT_HP_SAMPLE_LENGTH];
        for (uint8_t i = 0; i < CXPLAT_HP_SAMPLE_LENGTH; ++i) {
            Sample[i] = i;
        }
        uint8_t ActualMask[CXPLAT_HP_SAMPLE_LENGTH];
        uint8_t ExpectedMask[CXPLAT_HP_SAMPLE_LENGTH];
        ASSERT_FALSE(
            QUIC_FAILED(
                CxPlatHpComputeMask(Actual->HeaderKey, 1, Sample, ActualMask)));
        ASSERT_FALSE(
            QUIC_FAILED(
                CxPlatHpComputeMask(Expected->HeaderKey, 1, Sample, ExpectedMask)));
        ASSERT_EQ(0, memcmp(ActualMask, ExpectedMask, CXPLAT_HP_SAMPLE_LENGTH));

        uint8_t ActualBuffer[32 + CXPLAT_ENCRYPTION_OVERHEAD];
        uint8_t ExpectedBuffer[32 + CXPLAT_ENCRYPTION_OVERHEAD];
        for (uint8_t i = 0; i < 32; ++i) {
            ActualBuffer[i] = i;
            ExpectedBuffer[i] = i;
        }
        uint8_t Aad[4] = {0};
        uint64_t PacketNumber = 1;
        uint8_t Iv[CXPLAT_IV_LENGTH];
        QuicCryptoCombineIvAndPacketNumber(Actual->Iv, (uint8_t*)&PacketNumber, Iv);
        ASSERT_FALSE(
            QUIC_FAILED(
                CxPlatEncrypt(
                    Actual->PacketKey,
                    Iv,
                    sizeof(Aad),
                    Aad,
                    sizeof(ActualBuffer),
                    ActualBuffer)));
        QuicCryptoCombineIvAndPacketNumber(Expected->Iv, (uint8_t*)&PacketNumber, Iv);
        ASSERT_FALSE(
            QUIC_FAILED(
                CxPlatEncrypt(
                    Expected->PacketKey,
                    Iv,
                    sizeof(Aad),
                    Aad,
                    sizeof(ExpectedBuffer),
                    ExpectedBuffer)));
        ASSERT_EQ(0, memcmp(ActualBuffer, ExpectedBuffer, sizeof(ActualBuffer)));
    }

    static void AssertKeysDiffer(
        _In_ const QUIC_PACKET_KEY* Actual,
        _In_ const QUIC_PACKET_KEY* Other
        )
    {
        ASSERT_NE(nullptr, Actual);
        ASSERT_NE(nullptr, Other);
        ASSERT_NE(0, memcmp(Actual->Iv, Other->Iv, CXPLAT_IV_LENGTH));
    }
};

//
// A version change, such as a compatible version negotiation, must keep
// deriving the client's Initial keys from the Destination Connection ID of the
// client's first Initial packet, even after the server changed the connection
// ID the client sends to (RFC 9001 Section 5.2).
//
TEST_F(CryptoTest, InitialKeysUseOriginalDestinationCid)
{
    ASSERT_FALSE(QUIC_FAILED(QuicCryptoOnVersionChange(&Connection.Crypto)));

    QUIC_PACKET_KEY* ExpectedReadKey = nullptr;
    QUIC_PACKET_KEY* ExpectedWriteKey = nullptr;
    DeriveExpectedKeys(
        OriginalDestCidData,
        sizeof(OriginalDestCidData),
        &ExpectedReadKey,
        &ExpectedWriteKey);

    QUIC_PACKET_KEY* ServerReadKey = nullptr;
    QUIC_PACKET_KEY* ServerWriteKey = nullptr;
    DeriveExpectedKeys(
        ServerSourceCidData,
        sizeof(ServerSourceCidData),
        &ServerReadKey,
        &ServerWriteKey);

    AssertKeysMatch(
        Connection.Crypto.TlsState.ReadKeys[QUIC_PACKET_KEY_INITIAL],
        ExpectedReadKey);
    AssertKeysMatch(
        Connection.Crypto.TlsState.WriteKeys[QUIC_PACKET_KEY_INITIAL],
        ExpectedWriteKey);
    AssertKeysDiffer(
        Connection.Crypto.TlsState.ReadKeys[QUIC_PACKET_KEY_INITIAL],
        ServerReadKey);
    AssertKeysDiffer(
        Connection.Crypto.TlsState.WriteKeys[QUIC_PACKET_KEY_INITIAL],
        ServerWriteKey);

    QuicPacketKeyFree(ExpectedReadKey);
    QuicPacketKeyFree(ExpectedWriteKey);
    QuicPacketKeyFree(ServerReadKey);
    QuicPacketKeyFree(ServerWriteKey);
}

//
// After a Retry, the client's Initial keys are derived from the Source
// Connection ID of the Retry packet, which is the current destination
// connection ID, not the original one (RFC 9001 Section 5.2).
//
TEST_F(CryptoTest, InitialKeysUseRetrySourceCid)
{
    Connection.State.HandshakeUsedRetryPacket = TRUE;

    ASSERT_FALSE(QUIC_FAILED(QuicCryptoOnVersionChange(&Connection.Crypto)));

    QUIC_PACKET_KEY* ExpectedReadKey = nullptr;
    QUIC_PACKET_KEY* ExpectedWriteKey = nullptr;
    DeriveExpectedKeys(
        ServerSourceCidData,
        sizeof(ServerSourceCidData),
        &ExpectedReadKey,
        &ExpectedWriteKey);

    QUIC_PACKET_KEY* OriginalReadKey = nullptr;
    QUIC_PACKET_KEY* OriginalWriteKey = nullptr;
    DeriveExpectedKeys(
        OriginalDestCidData,
        sizeof(OriginalDestCidData),
        &OriginalReadKey,
        &OriginalWriteKey);

    AssertKeysMatch(
        Connection.Crypto.TlsState.ReadKeys[QUIC_PACKET_KEY_INITIAL],
        ExpectedReadKey);
    AssertKeysMatch(
        Connection.Crypto.TlsState.WriteKeys[QUIC_PACKET_KEY_INITIAL],
        ExpectedWriteKey);
    AssertKeysDiffer(
        Connection.Crypto.TlsState.ReadKeys[QUIC_PACKET_KEY_INITIAL],
        OriginalReadKey);
    AssertKeysDiffer(
        Connection.Crypto.TlsState.WriteKeys[QUIC_PACKET_KEY_INITIAL],
        OriginalWriteKey);

    QuicPacketKeyFree(ExpectedReadKey);
    QuicPacketKeyFree(ExpectedWriteKey);
    QuicPacketKeyFree(OriginalReadKey);
    QuicPacketKeyFree(OriginalWriteKey);
}

//
// Before the connection configuration has been set the original destination
// connection ID has not been saved yet, so the current destination connection
// ID is the original one and must be used.
//
TEST_F(CryptoTest, InitialKeysUseCurrentDestinationCidBeforeOriginalIsSaved)
{
    Connection.OrigDestCID = nullptr;

    ASSERT_FALSE(QUIC_FAILED(QuicCryptoOnVersionChange(&Connection.Crypto)));

    QUIC_PACKET_KEY* ExpectedReadKey = nullptr;
    QUIC_PACKET_KEY* ExpectedWriteKey = nullptr;
    DeriveExpectedKeys(
        ServerSourceCidData,
        sizeof(ServerSourceCidData),
        &ExpectedReadKey,
        &ExpectedWriteKey);

    AssertKeysMatch(
        Connection.Crypto.TlsState.ReadKeys[QUIC_PACKET_KEY_INITIAL],
        ExpectedReadKey);
    AssertKeysMatch(
        Connection.Crypto.TlsState.WriteKeys[QUIC_PACKET_KEY_INITIAL],
        ExpectedWriteKey);

    QuicPacketKeyFree(ExpectedReadKey);
    QuicPacketKeyFree(ExpectedWriteKey);
}
