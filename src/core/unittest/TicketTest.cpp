/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.

Abstract:

    Test the resumption ticket encoding and decoding logic.

--*/

#include "main.h"
#ifdef QUIC_CLOG
#include "TicketTest.cpp.clog.h"
#endif

void
CompareTransportParameters(
    const QUIC_TRANSPORT_PARAMETERS* A,
    const QUIC_TRANSPORT_PARAMETERS* B
    )
{
    ASSERT_EQ(A->Flags, B->Flags);
    COMPARE_TP_FIELD(INITIAL_MAX_DATA, InitialMaxData);
    COMPARE_TP_FIELD(INITIAL_MAX_STRM_DATA_BIDI_LOCAL, InitialMaxStreamDataBidiLocal);
    COMPARE_TP_FIELD(INITIAL_MAX_STRM_DATA_BIDI_REMOTE, InitialMaxStreamDataBidiRemote);
    COMPARE_TP_FIELD(INITIAL_MAX_STRM_DATA_UNI, InitialMaxStreamDataUni);
    COMPARE_TP_FIELD(INITIAL_MAX_STRMS_BIDI, InitialMaxBidiStreams);
    COMPARE_TP_FIELD(INITIAL_MAX_STRMS_UNI, InitialMaxUniStreams);
    COMPARE_TP_FIELD(ACTIVE_CONNECTION_ID_LIMIT, ActiveConnectionIdLimit);
}

TEST(ResumptionTicketTest, ClientEncDec)
{
    //
    // Original parameters
    //
    uint8_t ServerTicket[] = {0, 1, 2, 3, 4, 5};
    QUIC_TRANSPORT_PARAMETERS OriginalTP;
    const uint8_t* EncodedClientTicket = nullptr;
    uint32_t EncodedClientTicketLength = 0;

    //
    // Parameters to compare against
    //
    QUIC_TRANSPORT_PARAMETERS DecodedTP;
    uint8_t* DecodedServerTicket = nullptr;
    uint32_t DecodedServerTicketLength = 0;
    uint32_t DecodedQuicVersion = 0;

    QuicZeroMemory(&DecodedTP, sizeof(DecodedTP));
    QuicZeroMemory(&OriginalTP, sizeof(OriginalTP));
    OriginalTP.Flags =
        QUIC_TP_FLAG_ACTIVE_CONNECTION_ID_LIMIT |
        QUIC_TP_FLAG_INITIAL_MAX_DATA |
        QUIC_TP_FLAG_INITIAL_MAX_STRM_DATA_BIDI_LOCAL |
        QUIC_TP_FLAG_INITIAL_MAX_STRM_DATA_BIDI_REMOTE |
        QUIC_TP_FLAG_INITIAL_MAX_STRM_DATA_UNI |
        QUIC_TP_FLAG_INITIAL_MAX_STRMS_BIDI |
        QUIC_TP_FLAG_INITIAL_MAX_STRMS_UNI;
    OriginalTP.ActiveConnectionIdLimit = QUIC_TP_ACTIVE_CONNECTION_ID_LIMIT_MIN;

    TEST_QUIC_SUCCEEDED(
        QuicCryptoEncodeClientTicket(
            nullptr,
            ServerTicket,
            sizeof(ServerTicket),
            &OriginalTP,
            QUIC_VERSION_LATEST,
            &EncodedClientTicket,
            &EncodedClientTicketLength));

    ASSERT_NE(EncodedClientTicket, nullptr);
    ASSERT_NE(EncodedClientTicketLength, 0);

    TEST_QUIC_SUCCEEDED(
        QuicCryptoDecodeClientTicket(
            nullptr,
            EncodedClientTicket,
            (uint16_t)EncodedClientTicketLength,
            &DecodedTP,
            &DecodedServerTicket,
            &DecodedServerTicketLength,
            &DecodedQuicVersion));

    ASSERT_EQ(QUIC_VERSION_LATEST, DecodedQuicVersion);
    ASSERT_EQ(DecodedServerTicketLength, sizeof(ServerTicket));
    ASSERT_NE(DecodedServerTicket, nullptr);
    ASSERT_TRUE(memcmp(DecodedServerTicket, ServerTicket, sizeof(ServerTicket)) == 0);
    CompareTransportParameters(&OriginalTP, &DecodedTP);

    QUIC_FREE(EncodedClientTicket);
    QUIC_FREE(DecodedServerTicket);
}

TEST(ResumptionTicketTest, ServerEncDec)
{
    uint8_t AppData[] = {10, 9, 8, 7, 6};
    QUIC_TRANSPORT_PARAMETERS HandshakeTP;
    uint8_t NegotiatedAlpn[] = {4, 't', 'e', 's', 't'};
    uint8_t* EncodedServerTicket = nullptr;
    uint32_t EncodedServerTicketLength = 0;


    QUIC_TRANSPORT_PARAMETERS DecodedTP;
    const uint8_t* DecodedAppData = nullptr;
    uint32_t DecodedAppDataLength = 0;

    QuicZeroMemory(&HandshakeTP, sizeof(HandshakeTP));
    QuicZeroMemory(&DecodedTP, sizeof(DecodedTP));
    HandshakeTP.Flags =
        QUIC_TP_FLAG_ACTIVE_CONNECTION_ID_LIMIT |
        QUIC_TP_FLAG_INITIAL_MAX_DATA |
        QUIC_TP_FLAG_INITIAL_MAX_STRM_DATA_BIDI_LOCAL |
        QUIC_TP_FLAG_INITIAL_MAX_STRM_DATA_BIDI_REMOTE |
        QUIC_TP_FLAG_INITIAL_MAX_STRM_DATA_UNI |
        QUIC_TP_FLAG_INITIAL_MAX_STRMS_BIDI |
        QUIC_TP_FLAG_INITIAL_MAX_STRMS_UNI;
    HandshakeTP.ActiveConnectionIdLimit = QUIC_TP_ACTIVE_CONNECTION_ID_LIMIT_MIN;

    TEST_QUIC_SUCCEEDED(
        QuicCryptoEncodeServerTicket(
            nullptr,
            QUIC_VERSION_LATEST,
            AppData,
            sizeof(AppData),
            &HandshakeTP,
            NegotiatedAlpn + 1,
            NegotiatedAlpn[0],
            &EncodedServerTicket,
            &EncodedServerTicketLength));

    ASSERT_NE(EncodedServerTicket, nullptr);
    ASSERT_NE(EncodedServerTicketLength, 0);

    TEST_QUIC_SUCCEEDED(
        QuicCryptoDecodeServerTicket(
            nullptr,
            EncodedServerTicket,
            EncodedServerTicketLength,
            NegotiatedAlpn,
            sizeof(NegotiatedAlpn),
            &DecodedTP,
            &DecodedAppData,
            &DecodedAppDataLength));

    ASSERT_EQ(DecodedAppDataLength, sizeof(AppData));
    ASSERT_NE(DecodedAppData, nullptr);
    ASSERT_TRUE(memcmp(AppData, DecodedAppData, sizeof(AppData)) == 0);
    CompareTransportParameters(&HandshakeTP, &DecodedTP);

    QUIC_FREE(EncodedServerTicket);
}