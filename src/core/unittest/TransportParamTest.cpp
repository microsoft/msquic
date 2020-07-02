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
#define COMPARE_TP_FIELD(TpName, Field) \
    if (A->Flags & QUIC_TP_FLAG_##TpName) { ASSERT_EQ(A->Field, B->Field); }

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

void EncodeDecodeAndCompare(
    _In_ const QUIC_TRANSPORT_PARAMETERS* Original,
    _In_ bool IsServer = false
    )
{
    uint32_t BufferLength;
    auto Buffer =
        QuicCryptoTlsEncodeTransportParameters(
            &JunkConnection, Original, &BufferLength);
    ASSERT_NE(nullptr, Buffer);

    ASSERT_TRUE(UINT16_MAX >= (BufferLength - QuicTlsTPHeaderSize));

    auto TPBuffer = Buffer + QuicTlsTPHeaderSize;
    uint16_t TPBufferLength = (uint16_t)(BufferLength - QuicTlsTPHeaderSize);

    QUIC_TRANSPORT_PARAMETERS Decoded;
    BOOLEAN DecodedSuccessfully =
        QuicCryptoTlsDecodeTransportParameters(
            &JunkConnection, TPBuffer, TPBufferLength, &Decoded);

    QUIC_FREE(Buffer);

    ASSERT_TRUE(DecodedSuccessfully);

    CompareTransportParams(Original, &Decoded, IsServer);
}

TEST(TransportParamTest, EmptyClient)
{
    QUIC_TRANSPORT_PARAMETERS Original;
    QuicZeroMemory(&Original, sizeof(Original));
    EncodeDecodeAndCompare(&Original);
}

TEST(TransportParamTest, EmptyServer)
{
    QUIC_TRANSPORT_PARAMETERS Original;
    QuicZeroMemory(&Original, sizeof(Original));
    EncodeDecodeAndCompare(&Original, true);
}

TEST(TransportParamTest, Preset1)
{
    QUIC_TRANSPORT_PARAMETERS Original;
    QuicZeroMemory(&Original, sizeof(Original));
    Original.Flags |= QUIC_TP_FLAG_IDLE_TIMEOUT;
    Original.IdleTimeout = 100000;
    EncodeDecodeAndCompare(&Original);
}
