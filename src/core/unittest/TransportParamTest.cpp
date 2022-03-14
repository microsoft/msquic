/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.

Abstract:

    Unit test for the QUIC transport parameter encoding and decoding logic.

--*/

#include "main.h"
#ifdef QUIC_CLOG
#include "TransportParamTest.cpp.clog.h"
#endif

static QUIC_CONNECTION JunkConnection;

void CompareTransportParams(
    _In_ const QUIC_TRANSPORT_PARAMETERS* A,
    _In_ const QUIC_TRANSPORT_PARAMETERS* B,
    _In_ bool IsServer = false
    )
{
    ASSERT_EQ(A->Flags, B->Flags);
    COMPARE_TP_FIELD(INITIAL_MAX_DATA, InitialMaxData);
    COMPARE_TP_FIELD(INITIAL_MAX_STRM_DATA_BIDI_LOCAL, InitialMaxStreamDataBidiLocal);
    COMPARE_TP_FIELD(INITIAL_MAX_STRM_DATA_BIDI_REMOTE, InitialMaxStreamDataBidiRemote);
    COMPARE_TP_FIELD(INITIAL_MAX_STRM_DATA_UNI, InitialMaxStreamDataUni);
    COMPARE_TP_FIELD(INITIAL_MAX_STRMS_BIDI, InitialMaxBidiStreams);
    COMPARE_TP_FIELD(INITIAL_MAX_STRMS_UNI, InitialMaxUniStreams);
    COMPARE_TP_FIELD(MAX_UDP_PAYLOAD_SIZE, MaxUdpPayloadSize);
    COMPARE_TP_FIELD(ACK_DELAY_EXPONENT, AckDelayExponent);
    COMPARE_TP_FIELD(IDLE_TIMEOUT, IdleTimeout);
    COMPARE_TP_FIELD(MAX_ACK_DELAY, MaxAckDelay);
    COMPARE_TP_FIELD(ACTIVE_CONNECTION_ID_LIMIT, ActiveConnectionIdLimit);
    COMPARE_TP_FIELD(CIBIR_ENCODING, CibirLength);
    COMPARE_TP_FIELD(CIBIR_ENCODING, CibirOffset);
    if (A->Flags & QUIC_TP_FLAG_VERSION_NEGOTIATION) {
        ASSERT_EQ(A->VersionInfoLength, B->VersionInfoLength);
        ASSERT_EQ(
            memcmp(A->VersionInfo, B->VersionInfo, (size_t)A->VersionInfoLength),
            0);
    }
    //COMPARE_TP_FIELD(InitialSourceConnectionID);
    //COMPARE_TP_FIELD(InitialSourceConnectionIDLength);
    if (IsServer) { // TODO
        //COMPARE_TP_FIELD(StatelessResetToken);
        //COMPARE_TP_FIELD(AckPreferredAddressDelayExponent);
        //COMPARE_TP_FIELD(OriginalDestinationConnectionID);
        //COMPARE_TP_FIELD(OriginalDestinationConnectionIDLength);
        //COMPARE_TP_FIELD(RetrySourceConnectionID);
        //COMPARE_TP_FIELD(RetrySourceConnectionIDLength);
    }
}

struct TransportParametersScope
{
    QUIC_TRANSPORT_PARAMETERS* const TP;
    TransportParametersScope(QUIC_TRANSPORT_PARAMETERS* const value) : TP(value) {}
    ~TransportParametersScope() {
        if (TP != nullptr) {
            QuicCryptoTlsCleanupTransportParameters(TP);
        }
    }
};

void EncodeDecodeAndCompare(
    _In_ const QUIC_TRANSPORT_PARAMETERS* Original,
    _In_ bool IsServer = false,
    _In_ bool ShouldDecodeSuccessfully = true
    )
{
    uint32_t BufferLength;
    auto Buffer =
        QuicCryptoTlsEncodeTransportParameters(
            &JunkConnection, IsServer, Original, NULL, &BufferLength);
    ASSERT_NE(nullptr, Buffer);

    ASSERT_TRUE(UINT16_MAX >= (BufferLength - CxPlatTlsTPHeaderSize));

    auto TPBuffer = Buffer + CxPlatTlsTPHeaderSize;
    uint16_t TPBufferLength = (uint16_t)(BufferLength - CxPlatTlsTPHeaderSize);

    QUIC_TRANSPORT_PARAMETERS Decoded;
    BOOLEAN DecodedSuccessfully =
        QuicCryptoTlsDecodeTransportParameters(
            &JunkConnection, IsServer, TPBuffer, TPBufferLength, &Decoded);

    CXPLAT_FREE(Buffer, QUIC_POOL_TLS_TRANSPARAMS);
    TransportParametersScope TPScope(&Decoded);

    ASSERT_EQ(ShouldDecodeSuccessfully, DecodedSuccessfully);

    if (ShouldDecodeSuccessfully) {
        CompareTransportParams(Original, &Decoded, IsServer);
    }
}

TEST(TransportParamTest, EmptyClient)
{
    QUIC_TRANSPORT_PARAMETERS Original;
    CxPlatZeroMemory(&Original, sizeof(Original));
    EncodeDecodeAndCompare(&Original);
}

TEST(TransportParamTest, EmptyServer)
{
    QUIC_TRANSPORT_PARAMETERS Original;
    CxPlatZeroMemory(&Original, sizeof(Original));
    EncodeDecodeAndCompare(&Original, true);
}

TEST(TransportParamTest, Preset1)
{
    QUIC_TRANSPORT_PARAMETERS Original;
    CxPlatZeroMemory(&Original, sizeof(Original));
    Original.Flags |= QUIC_TP_FLAG_IDLE_TIMEOUT;
    Original.IdleTimeout = 100000;
    EncodeDecodeAndCompare(&Original);
}

TEST(TransportParamTest, ZeroTP)
{
    QUIC_TRANSPORT_PARAMETERS OriginalTP;
    CxPlatZeroMemory(&OriginalTP, sizeof(OriginalTP));
    OriginalTP.Flags =
        QUIC_TP_FLAG_ACTIVE_CONNECTION_ID_LIMIT |
        QUIC_TP_FLAG_INITIAL_MAX_DATA |
        QUIC_TP_FLAG_INITIAL_MAX_STRM_DATA_BIDI_LOCAL |
        QUIC_TP_FLAG_INITIAL_MAX_STRM_DATA_BIDI_REMOTE |
        QUIC_TP_FLAG_INITIAL_MAX_STRM_DATA_UNI |
        QUIC_TP_FLAG_INITIAL_MAX_STRMS_BIDI |
        QUIC_TP_FLAG_INITIAL_MAX_STRMS_UNI;
    OriginalTP.ActiveConnectionIdLimit = QUIC_TP_ACTIVE_CONNECTION_ID_LIMIT_MIN;

    EncodeDecodeAndCompare(&OriginalTP);
}

TEST(TransportParamTest, VersionNegotiationExtension)
{
    QUIC_TRANSPORT_PARAMETERS OriginalTP;
    CxPlatZeroMemory(&OriginalTP, sizeof(OriginalTP));
    uint8_t VerInfo[21];
    OriginalTP.VersionInfo = VerInfo;
    OriginalTP.VersionInfoLength = sizeof(VerInfo);
    OriginalTP.Flags = QUIC_TP_FLAG_VERSION_NEGOTIATION;

    EncodeDecodeAndCompare(&OriginalTP);
}

TEST(TransportParamTest, CibirEncodingOne)
{
    QUIC_TRANSPORT_PARAMETERS OriginalTP;
    CxPlatZeroMemory(&OriginalTP, sizeof(OriginalTP));
    OriginalTP.Flags = QUIC_TP_FLAG_CIBIR_ENCODING;
    OriginalTP.CibirLength = 1;
    EncodeDecodeAndCompare(&OriginalTP);
}

TEST(TransportParamTest, CibirEncodingMax)
{
    QUIC_TRANSPORT_PARAMETERS OriginalTP;
    CxPlatZeroMemory(&OriginalTP, sizeof(OriginalTP));
    OriginalTP.Flags = QUIC_TP_FLAG_CIBIR_ENCODING;
    OriginalTP.CibirLength = 255;
    EncodeDecodeAndCompare(&OriginalTP);
}

TEST(TransportParamTest, CibirEncodingMax2)
{
    QUIC_TRANSPORT_PARAMETERS OriginalTP;
    CxPlatZeroMemory(&OriginalTP, sizeof(OriginalTP));
    OriginalTP.Flags = QUIC_TP_FLAG_CIBIR_ENCODING;
    OriginalTP.CibirLength = 254;
    OriginalTP.CibirOffset = 1;
    EncodeDecodeAndCompare(&OriginalTP);
}

TEST(TransportParamTest, CibirEncodingZero)
{
    QUIC_TRANSPORT_PARAMETERS OriginalTP;
    CxPlatZeroMemory(&OriginalTP, sizeof(OriginalTP));
    OriginalTP.Flags = QUIC_TP_FLAG_CIBIR_ENCODING;
    EncodeDecodeAndCompare(&OriginalTP, false, false);
}

TEST(TransportParamTest, CibirEncodingOverMax)
{
    QUIC_TRANSPORT_PARAMETERS OriginalTP;
    CxPlatZeroMemory(&OriginalTP, sizeof(OriginalTP));
    OriginalTP.Flags = QUIC_TP_FLAG_CIBIR_ENCODING;
    OriginalTP.CibirLength = 256;
    EncodeDecodeAndCompare(&OriginalTP, false, false);
}

TEST(TransportParamTest, CibirEncodingOverMax2)
{
    QUIC_TRANSPORT_PARAMETERS OriginalTP;
    CxPlatZeroMemory(&OriginalTP, sizeof(OriginalTP));
    OriginalTP.Flags = QUIC_TP_FLAG_CIBIR_ENCODING;
    OriginalTP.CibirLength = 255;
    OriginalTP.CibirOffset = 1;
    EncodeDecodeAndCompare(&OriginalTP, false, false);
}
