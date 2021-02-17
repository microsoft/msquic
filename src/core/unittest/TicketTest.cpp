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
    QUIC_TRANSPORT_PARAMETERS ClientTP;
    const uint8_t* EncodedClientTicket = nullptr;
    uint32_t EncodedClientTicketLength = 0;

    //
    // Parameters to compare against
    //
    QUIC_TRANSPORT_PARAMETERS DecodedTP;
    uint8_t* DecodedServerTicket = nullptr;
    uint32_t DecodedServerTicketLength = 0;
    uint32_t DecodedQuicVersion = 0;

    CxPlatZeroMemory(&DecodedTP, sizeof(DecodedTP));
    CxPlatZeroMemory(&ClientTP, sizeof(ClientTP));
    ClientTP.Flags =
        QUIC_TP_FLAG_ACTIVE_CONNECTION_ID_LIMIT |
        QUIC_TP_FLAG_INITIAL_MAX_DATA |
        QUIC_TP_FLAG_INITIAL_MAX_STRM_DATA_BIDI_LOCAL |
        QUIC_TP_FLAG_INITIAL_MAX_STRM_DATA_BIDI_REMOTE |
        QUIC_TP_FLAG_INITIAL_MAX_STRM_DATA_UNI |
        QUIC_TP_FLAG_INITIAL_MAX_STRMS_BIDI |
        QUIC_TP_FLAG_INITIAL_MAX_STRMS_UNI;
    ClientTP.ActiveConnectionIdLimit = QUIC_TP_ACTIVE_CONNECTION_ID_LIMIT_MIN;

    TEST_QUIC_SUCCEEDED(
        QuicCryptoEncodeClientTicket(
            nullptr,
            sizeof(ServerTicket),
            ServerTicket,
            &ClientTP,
            QUIC_VERSION_LATEST,
            &EncodedClientTicket,
            &EncodedClientTicketLength));

    ASSERT_NE(EncodedClientTicket, nullptr);
    ASSERT_NE((uint16_t)EncodedClientTicketLength, 0);

    TEST_QUIC_SUCCEEDED(
        QuicCryptoDecodeClientTicket(
            nullptr,
            (uint16_t)EncodedClientTicketLength,
            EncodedClientTicket,
            &DecodedTP,
            &DecodedServerTicket,
            &DecodedServerTicketLength,
            &DecodedQuicVersion));

    ASSERT_EQ(QUIC_VERSION_LATEST, DecodedQuicVersion);
    ASSERT_EQ(DecodedServerTicketLength, sizeof(ServerTicket));
    ASSERT_NE(DecodedServerTicket, nullptr);
    ASSERT_TRUE(memcmp(DecodedServerTicket, ServerTicket, sizeof(ServerTicket)) == 0);
    CompareTransportParameters(&ClientTP, &DecodedTP);

    CXPLAT_FREE(EncodedClientTicket, QUIC_POOL_CLIENT_CRYPTO_TICKET);
    CXPLAT_FREE(DecodedServerTicket, QUIC_POOL_CRYPTO_RESUMPTION_TICKET);
}

TEST(ResumptionTicketTest, ClientDecFail)
{
    const uint8_t TransportParametersLength = 31;
    const uint8_t ServerTicket[] = {1,2,3,4,5};
    QUIC_TRANSPORT_PARAMETERS ServerTP;
    QUIC_TRANSPORT_PARAMETERS DecodedTP;
    const uint8_t* EncodedServerTP = nullptr;
    uint32_t EncodedTPLength = 0;
    uint8_t* DecodedServerTicket = nullptr;
    uint32_t DecodedServerTicketLength = 0;
    uint32_t DecodedQuicVersion = 0;

    uint8_t InputTicketBuffer[7 + TransportParametersLength + sizeof(ServerTicket)] = {
        CXPLAT_TLS_RESUMPTION_CLIENT_TICKET_VERSION,
        0,0,0,1,                    // QUIC version
        (uint8_t)(TransportParametersLength - (uint8_t)CxPlatTlsTPHeaderSize),
        5,                          // Server Ticket Length
    };

    CxPlatZeroMemory(&DecodedTP, sizeof(DecodedTP));
    CxPlatZeroMemory(&ServerTP, sizeof(ServerTP));
    ServerTP.Flags =
        QUIC_TP_FLAG_ACTIVE_CONNECTION_ID_LIMIT |
        QUIC_TP_FLAG_INITIAL_MAX_DATA |
        QUIC_TP_FLAG_INITIAL_MAX_STRM_DATA_BIDI_LOCAL |
        QUIC_TP_FLAG_INITIAL_MAX_STRM_DATA_BIDI_REMOTE |
        QUIC_TP_FLAG_INITIAL_MAX_STRM_DATA_UNI |
        QUIC_TP_FLAG_INITIAL_MAX_STRMS_BIDI |
        QUIC_TP_FLAG_INITIAL_MAX_STRMS_UNI;
    ServerTP.ActiveConnectionIdLimit = QUIC_TP_ACTIVE_CONNECTION_ID_LIMIT_MIN;

    EncodedServerTP =
        QuicCryptoTlsEncodeTransportParameters(
            nullptr,
            TRUE,
            &ServerTP,
            nullptr,
            &EncodedTPLength);
    ASSERT_NE(EncodedServerTP, nullptr);
    ASSERT_EQ(EncodedTPLength, TransportParametersLength); // Update if TP size changes
    ASSERT_GT(sizeof(InputTicketBuffer), EncodedTPLength);

    CxPlatCopyMemory(
        &InputTicketBuffer[7],
        EncodedServerTP + CxPlatTlsTPHeaderSize,
        EncodedTPLength - CxPlatTlsTPHeaderSize);

    ASSERT_GT(sizeof(InputTicketBuffer), EncodedTPLength + sizeof(ServerTicket));
    CxPlatCopyMemory(
        &InputTicketBuffer[7 + TransportParametersLength - CxPlatTlsTPHeaderSize],
        ServerTicket,
        sizeof(ServerTicket));

    //
    // Validate that the hand-crafted ticket is correct
    //
    TEST_QUIC_SUCCEEDED(
        QuicCryptoDecodeClientTicket(
            nullptr,
            7 + (uint16_t)(EncodedTPLength - CxPlatTlsTPHeaderSize) + (uint16_t)sizeof(ServerTicket),
            InputTicketBuffer,
            &DecodedTP,
            &DecodedServerTicket,
            &DecodedServerTicketLength,
            &DecodedQuicVersion));
    ASSERT_EQ(DecodedQuicVersion, QUIC_VERSION_1);
    ASSERT_EQ(DecodedServerTicketLength, sizeof(ServerTicket));
    CompareTransportParameters(&ServerTP, &DecodedTP);

    //
    // Test decoding of a valid ticket fails when the length is wrong
    //

    // Not enough space to decode ticket version
    ASSERT_EQ(
        QUIC_STATUS_INVALID_PARAMETER,
        QuicCryptoDecodeClientTicket(
            nullptr,
            0,
            InputTicketBuffer,
            &DecodedTP,
            &DecodedServerTicket,
            &DecodedServerTicketLength,
            &DecodedQuicVersion));

    // Not enough space to decode QUIC version
    ASSERT_EQ(
        QUIC_STATUS_INVALID_PARAMETER,
        QuicCryptoDecodeClientTicket(
            nullptr,
            4,
            InputTicketBuffer,
            &DecodedTP,
            &DecodedServerTicket,
            &DecodedServerTicketLength,
            &DecodedQuicVersion));

    // Not enough space to decode TP length
    ASSERT_EQ(
        QUIC_STATUS_INVALID_PARAMETER,
        QuicCryptoDecodeClientTicket(
            nullptr,
            5,
            InputTicketBuffer,
            &DecodedTP,
            &DecodedServerTicket,
            &DecodedServerTicketLength,
            &DecodedQuicVersion));

    // Not enough space to decode server ticket length
    ASSERT_EQ(
        QUIC_STATUS_INVALID_PARAMETER,
        QuicCryptoDecodeClientTicket(
            nullptr,
            6,
            InputTicketBuffer,
            &DecodedTP,
            &DecodedServerTicket,
            &DecodedServerTicketLength,
            &DecodedQuicVersion));

    // Not enough space to decode TP
    ASSERT_EQ(
        QUIC_STATUS_INVALID_PARAMETER,
        QuicCryptoDecodeClientTicket(
            nullptr,
            7,
            InputTicketBuffer,
            &DecodedTP,
            &DecodedServerTicket,
            &DecodedServerTicketLength,
            &DecodedQuicVersion));

    ASSERT_EQ(
        QUIC_STATUS_INVALID_PARAMETER,
        QuicCryptoDecodeClientTicket(
            nullptr,
            7 + ((uint16_t)(EncodedTPLength - CxPlatTlsTPHeaderSize) / 2),
            InputTicketBuffer,
            &DecodedTP,
            &DecodedServerTicket,
            &DecodedServerTicketLength,
            &DecodedQuicVersion));

    ASSERT_EQ(
        QUIC_STATUS_INVALID_PARAMETER,
        QuicCryptoDecodeClientTicket(
            nullptr,
            7 + ((uint16_t)(EncodedTPLength - CxPlatTlsTPHeaderSize) - 1),
            InputTicketBuffer,
            &DecodedTP,
            &DecodedServerTicket,
            &DecodedServerTicketLength,
            &DecodedQuicVersion));

    // Not enough space to decode server ticket
    ASSERT_EQ(
        QUIC_STATUS_INVALID_PARAMETER,
        QuicCryptoDecodeClientTicket(
            nullptr,
            7 + (uint16_t)(EncodedTPLength - CxPlatTlsTPHeaderSize),
            InputTicketBuffer,
            &DecodedTP,
            &DecodedServerTicket,
            &DecodedServerTicketLength,
            &DecodedQuicVersion));

    ASSERT_EQ(
        QUIC_STATUS_INVALID_PARAMETER,
        QuicCryptoDecodeClientTicket(
            nullptr,
            7 + (uint16_t)(EncodedTPLength - CxPlatTlsTPHeaderSize) + ((uint16_t)sizeof(ServerTicket) - 1),
            InputTicketBuffer,
            &DecodedTP,
            &DecodedServerTicket,
            &DecodedServerTicketLength,
            &DecodedQuicVersion));

    //
    // Invalidate some of the fields of the ticket to ensure
    // decoding fails
    //

    // Incorrect ticket version
    InputTicketBuffer[0] = CXPLAT_TLS_RESUMPTION_CLIENT_TICKET_VERSION + 1;
    ASSERT_EQ(
        QUIC_STATUS_INVALID_PARAMETER,
        QuicCryptoDecodeClientTicket(
            nullptr,
            7 + (uint16_t)(EncodedTPLength - CxPlatTlsTPHeaderSize) + (uint16_t)sizeof(ServerTicket),
            InputTicketBuffer,
            &DecodedTP,
            &DecodedServerTicket,
            &DecodedServerTicketLength,
            &DecodedQuicVersion));
    InputTicketBuffer[0] = CXPLAT_TLS_RESUMPTION_CLIENT_TICKET_VERSION;

    // Unsupported QUIC version
    InputTicketBuffer[1] = 1;
    InputTicketBuffer[2] = 1;
    InputTicketBuffer[3] = 1;
    InputTicketBuffer[4] = 1;
    ASSERT_EQ(
        QUIC_STATUS_INVALID_PARAMETER,
        QuicCryptoDecodeClientTicket(
            nullptr,
            7 + (uint16_t)(EncodedTPLength - CxPlatTlsTPHeaderSize) + (uint16_t)sizeof(ServerTicket),
            InputTicketBuffer,
            &DecodedTP,
            &DecodedServerTicket,
            &DecodedServerTicketLength,
            &DecodedQuicVersion));
    InputTicketBuffer[1] = 0;
    InputTicketBuffer[2] = 0;
    InputTicketBuffer[3] = 0;
    InputTicketBuffer[4] = 1;

    // Client TP length shorter than actual
    for (uint8_t s = 0; s < (uint8_t)TransportParametersLength - (uint8_t)CxPlatTlsTPHeaderSize; ++s) {
        QuicTraceLogInfo(
            ClientResumptionTicketDecodeFailTpLengthShort,
            "[test] Attempting to decode Server TP with length %u (Actual: %u)",
            s,
            EncodedTPLength - CxPlatTlsTPHeaderSize);

        InputTicketBuffer[5] = s;
        ASSERT_EQ(
            QUIC_STATUS_INVALID_PARAMETER,
            QuicCryptoDecodeClientTicket(
                nullptr,
                7 + (uint16_t)(EncodedTPLength - CxPlatTlsTPHeaderSize) + (uint16_t)sizeof(ServerTicket),
                InputTicketBuffer,
                &DecodedTP,
                &DecodedServerTicket,
                &DecodedServerTicketLength,
                &DecodedQuicVersion));
    }

    // Client TP length longer than actual
    InputTicketBuffer[5] = (uint8_t)(TransportParametersLength - (uint8_t)CxPlatTlsTPHeaderSize) + 1;
    ASSERT_EQ(
        QUIC_STATUS_INVALID_PARAMETER,
        QuicCryptoDecodeClientTicket(
            nullptr,
            7 + (uint16_t)(EncodedTPLength - CxPlatTlsTPHeaderSize) + (uint16_t)sizeof(ServerTicket),
            InputTicketBuffer,
            &DecodedTP,
            &DecodedServerTicket,
            &DecodedServerTicketLength,
            &DecodedQuicVersion));

    // Client TP length improperly encoded QUIC_VAR_INT
    for (uint8_t i = 1; i < 4; ++i) {
        InputTicketBuffer[5] = (uint8_t)(i << 6);

        QuicTraceLogInfo(
            ClientResumptionTicketDecodeFailTpLengthEncodedWrong,
            "[test] Attempting to decode Server TP length (improperly encoded) %x (Actual: %u)",
            InputTicketBuffer[5],
            EncodedTPLength - CxPlatTlsTPHeaderSize);

        ASSERT_EQ(
            QUIC_STATUS_INVALID_PARAMETER,
            QuicCryptoDecodeClientTicket(
                nullptr,
                7 + (uint16_t)(EncodedTPLength - CxPlatTlsTPHeaderSize) + (uint16_t)sizeof(ServerTicket),
                InputTicketBuffer,
                &DecodedTP,
                &DecodedServerTicket,
                &DecodedServerTicketLength,
                &DecodedQuicVersion));
    }
    InputTicketBuffer[5] = (uint8_t)(TransportParametersLength - (uint8_t)CxPlatTlsTPHeaderSize);

    // Server Ticket length shorter than actual
    for (uint8_t s = 0; s < (uint8_t)sizeof(ServerTicket); ++s) {
        QuicTraceLogInfo(
            ClientResumptionTicketDecodeFailTicketLengthShort,
            "[test] Attempting to decode Server Ticket with length %u (Actual: %u)",
            s,
            (uint8_t)sizeof(ServerTicket));

        InputTicketBuffer[6] = s;
        ASSERT_EQ(
            QUIC_STATUS_INVALID_PARAMETER,
            QuicCryptoDecodeClientTicket(
                nullptr,
                7 + (uint16_t)(EncodedTPLength - CxPlatTlsTPHeaderSize) + (uint16_t)sizeof(ServerTicket),
                InputTicketBuffer,
                &DecodedTP,
                &DecodedServerTicket,
                &DecodedServerTicketLength,
                &DecodedQuicVersion));
    }

    // Server Ticket length longer than actual
    InputTicketBuffer[6] = (uint8_t)sizeof(ServerTicket) + 1;
    ASSERT_EQ(
        QUIC_STATUS_INVALID_PARAMETER,
        QuicCryptoDecodeClientTicket(
            nullptr,
            7 + (uint16_t)(EncodedTPLength - CxPlatTlsTPHeaderSize) + (uint16_t)sizeof(ServerTicket),
            InputTicketBuffer,
            &DecodedTP,
            &DecodedServerTicket,
            &DecodedServerTicketLength,
            &DecodedQuicVersion));

    // Server Ticket length improperly encoded QUIC VAR INT
    for (uint8_t i = 1; i < 4; ++i) {
        InputTicketBuffer[6] = (uint8_t)(i << 6);
        QuicTraceLogInfo(
            ClientResumptionTicketDecodeFailTicketLengthEncodedWrong,
            "[test] Attempting to decode Server Ticket length (improperly encoded) %x (Actual: %u)",
            InputTicketBuffer[6],
            (uint8_t)sizeof(ServerTicket));

        ASSERT_EQ(
            QUIC_STATUS_INVALID_PARAMETER,
            QuicCryptoDecodeClientTicket(
                nullptr,
                7 + (uint16_t)(EncodedTPLength - CxPlatTlsTPHeaderSize) + (uint16_t)sizeof(ServerTicket),
                InputTicketBuffer,
                &DecodedTP,
                &DecodedServerTicket,
                &DecodedServerTicketLength,
                &DecodedQuicVersion));
    }
}

TEST(ResumptionTicketTest, ServerEncDec)
{
    uint8_t AppData[] = {10, 9, 8, 7, 6};
    QUIC_TRANSPORT_PARAMETERS ServerTP;
    uint8_t NegotiatedAlpn[] = {4, 't', 'e', 's', 't'};
    uint8_t* EncodedServerTicket = nullptr;
    uint32_t EncodedServerTicketLength = 0;


    QUIC_TRANSPORT_PARAMETERS DecodedTP;
    const uint8_t* DecodedAppData = nullptr;
    uint32_t DecodedAppDataLength = 0;

    CxPlatZeroMemory(&ServerTP, sizeof(ServerTP));
    CxPlatZeroMemory(&DecodedTP, sizeof(DecodedTP));
    ServerTP.Flags =
        QUIC_TP_FLAG_ACTIVE_CONNECTION_ID_LIMIT |
        QUIC_TP_FLAG_INITIAL_MAX_DATA |
        QUIC_TP_FLAG_INITIAL_MAX_STRM_DATA_BIDI_LOCAL |
        QUIC_TP_FLAG_INITIAL_MAX_STRM_DATA_BIDI_REMOTE |
        QUIC_TP_FLAG_INITIAL_MAX_STRM_DATA_UNI |
        QUIC_TP_FLAG_INITIAL_MAX_STRMS_BIDI |
        QUIC_TP_FLAG_INITIAL_MAX_STRMS_UNI;
    ServerTP.ActiveConnectionIdLimit = QUIC_TP_ACTIVE_CONNECTION_ID_LIMIT_MIN;

    TEST_QUIC_SUCCEEDED(
        QuicCryptoEncodeServerTicket(
            nullptr,
            QUIC_VERSION_LATEST,
            sizeof(AppData),
            AppData,
            &ServerTP,
            NegotiatedAlpn[0],
            NegotiatedAlpn + 1,
            &EncodedServerTicket,
            &EncodedServerTicketLength));

    ASSERT_NE(EncodedServerTicket, nullptr);
    ASSERT_NE((uint16_t)EncodedServerTicketLength, 0);

    TEST_QUIC_SUCCEEDED(
        QuicCryptoDecodeServerTicket(
            nullptr,
            (uint16_t)EncodedServerTicketLength,
            EncodedServerTicket,
            NegotiatedAlpn,
            sizeof(NegotiatedAlpn),
            &DecodedTP,
            &DecodedAppData,
            &DecodedAppDataLength));

    ASSERT_EQ(DecodedAppDataLength, sizeof(AppData));
    ASSERT_NE(DecodedAppData, nullptr);
    ASSERT_TRUE(memcmp(AppData, DecodedAppData, sizeof(AppData)) == 0);
    CompareTransportParameters(&ServerTP, &DecodedTP);

    CXPLAT_FREE(EncodedServerTicket, QUIC_POOL_SERVER_CRYPTO_TICKET);
}

TEST(ResumptionTicketTest, ServerEncDecNoAppData)
{
    QUIC_TRANSPORT_PARAMETERS ServerTP;
    uint8_t NegotiatedAlpn[] = {4, 't', 'e', 's', 't'};
    uint8_t* EncodedServerTicket = nullptr;
    uint32_t EncodedServerTicketLength = 0;

    QUIC_TRANSPORT_PARAMETERS DecodedServerTP;
    const uint8_t* DecodedAppData = nullptr;
    uint32_t DecodedAppDataLength = 0;

    CxPlatZeroMemory(&ServerTP, sizeof(ServerTP));
    CxPlatZeroMemory(&DecodedServerTP, sizeof(DecodedServerTP));
    ServerTP.Flags =
        QUIC_TP_FLAG_ACTIVE_CONNECTION_ID_LIMIT |
        QUIC_TP_FLAG_INITIAL_MAX_DATA |
        QUIC_TP_FLAG_INITIAL_MAX_STRM_DATA_BIDI_LOCAL |
        QUIC_TP_FLAG_INITIAL_MAX_STRM_DATA_BIDI_REMOTE |
        QUIC_TP_FLAG_INITIAL_MAX_STRM_DATA_UNI |
        QUIC_TP_FLAG_INITIAL_MAX_STRMS_BIDI |
        QUIC_TP_FLAG_INITIAL_MAX_STRMS_UNI;
    ServerTP.ActiveConnectionIdLimit = QUIC_TP_ACTIVE_CONNECTION_ID_LIMIT_MIN;

    TEST_QUIC_SUCCEEDED(
        QuicCryptoEncodeServerTicket(
            nullptr,
            QUIC_VERSION_LATEST,
            0,
            nullptr,
            &ServerTP,
            NegotiatedAlpn[0],
            NegotiatedAlpn + 1,
            &EncodedServerTicket,
            &EncodedServerTicketLength));

    ASSERT_NE(EncodedServerTicket, nullptr);
    ASSERT_NE((uint16_t)EncodedServerTicketLength, 0);

    TEST_QUIC_SUCCEEDED(
        QuicCryptoDecodeServerTicket(
            nullptr,
            (uint16_t)EncodedServerTicketLength,
            EncodedServerTicket,
            NegotiatedAlpn,
            sizeof(NegotiatedAlpn),
            &DecodedServerTP,
            &DecodedAppData,
            &DecodedAppDataLength));

    ASSERT_EQ((uint16_t)DecodedAppDataLength, 0);
    ASSERT_EQ(DecodedAppData, nullptr);
    CompareTransportParameters(&ServerTP, &DecodedServerTP);

    CXPLAT_FREE(EncodedServerTicket, QUIC_POOL_SERVER_CRYPTO_TICKET);
}

TEST(ResumptionTicketTest, ServerDecFail)
{
    const uint8_t TransportParametersLength = 31;
    const uint8_t AppData[] = {1,2,3,4,5};
    const uint8_t Alpn[] = {'t', 'e', 's', 't'};
    const uint8_t AlpnList[] = {4, 't', 'e', 's', 't'};
    QUIC_TRANSPORT_PARAMETERS HandshakeTP;
    QUIC_TRANSPORT_PARAMETERS DecodedTP;
    const uint8_t* EncodedHandshakeTP = nullptr;
    uint32_t EncodedTPLength = 0;
    const uint8_t* DecodedAppData = nullptr;
    uint32_t DecodedAppDataLength = 0;

    uint8_t InputTicketBuffer[8 + TransportParametersLength + sizeof(Alpn) + sizeof(AppData)] = {
        CXPLAT_TLS_RESUMPTION_TICKET_VERSION,
        0,0,0,1,                    // QUIC version
        4,                          // ALPN length
        (uint8_t)(TransportParametersLength - (uint8_t)CxPlatTlsTPHeaderSize),
        (uint8_t)sizeof(AppData),   // App Data Length
    };

    CxPlatZeroMemory(&DecodedTP, sizeof(DecodedTP));
    CxPlatZeroMemory(&HandshakeTP, sizeof(HandshakeTP));
    HandshakeTP.Flags =
        QUIC_TP_FLAG_ACTIVE_CONNECTION_ID_LIMIT |
        QUIC_TP_FLAG_INITIAL_MAX_DATA |
        QUIC_TP_FLAG_INITIAL_MAX_STRM_DATA_BIDI_LOCAL |
        QUIC_TP_FLAG_INITIAL_MAX_STRM_DATA_BIDI_REMOTE |
        QUIC_TP_FLAG_INITIAL_MAX_STRM_DATA_UNI |
        QUIC_TP_FLAG_INITIAL_MAX_STRMS_BIDI |
        QUIC_TP_FLAG_INITIAL_MAX_STRMS_UNI;
    HandshakeTP.ActiveConnectionIdLimit = QUIC_TP_ACTIVE_CONNECTION_ID_LIMIT_MIN;

    EncodedHandshakeTP =
        QuicCryptoTlsEncodeTransportParameters(
            nullptr,
            TRUE,
            &HandshakeTP,
            nullptr,
            &EncodedTPLength);
    ASSERT_NE(EncodedHandshakeTP, nullptr);
    ASSERT_EQ(EncodedTPLength, TransportParametersLength); // Update if TP size changes
    ASSERT_GT(sizeof(InputTicketBuffer), EncodedTPLength);

    CxPlatCopyMemory(
        &InputTicketBuffer[8],
        Alpn,
        sizeof(Alpn));

    CxPlatCopyMemory(
        &InputTicketBuffer[8 + sizeof(Alpn)],
        EncodedHandshakeTP + CxPlatTlsTPHeaderSize,
        EncodedTPLength - CxPlatTlsTPHeaderSize);

    ASSERT_GT(sizeof(InputTicketBuffer), EncodedTPLength + sizeof(AppData));
    CxPlatCopyMemory(
        &InputTicketBuffer[8 + sizeof(Alpn) + (TransportParametersLength - CxPlatTlsTPHeaderSize)],
        AppData,
        sizeof(AppData));

    //
    // Validate that the hand-crafted ticket is correct
    //
    TEST_QUIC_SUCCEEDED(
        QuicCryptoDecodeServerTicket(
            nullptr,
            8 + (uint16_t)sizeof(Alpn) + (uint16_t)(EncodedTPLength - CxPlatTlsTPHeaderSize) + (uint16_t)sizeof(AppData),
            InputTicketBuffer,
            AlpnList,
            sizeof(AlpnList),
            &DecodedTP,
            &DecodedAppData,
            &DecodedAppDataLength));
    ASSERT_EQ(DecodedAppDataLength, sizeof(AppData));
    CompareTransportParameters(&HandshakeTP, &DecodedTP);

    //
    // Test decoding of a valid ticket fails when the length is wrong
    //

    // Not enough space to decode ticket version
    ASSERT_EQ(
        QUIC_STATUS_INVALID_PARAMETER,
        QuicCryptoDecodeServerTicket(
            nullptr,
            0,
            InputTicketBuffer,
            AlpnList,
            sizeof(AlpnList),
            &DecodedTP,
            &DecodedAppData,
            &DecodedAppDataLength));

    // Not enough room for QUIC version
    ASSERT_EQ(
        QUIC_STATUS_INVALID_PARAMETER,
        QuicCryptoDecodeServerTicket(
            nullptr,
            4,
            InputTicketBuffer,
            AlpnList,
            sizeof(AlpnList),
            &DecodedTP,
            &DecodedAppData,
            &DecodedAppDataLength));

    // Not enough room for negotiated ALPN length
    ASSERT_EQ(
        QUIC_STATUS_INVALID_PARAMETER,
        QuicCryptoDecodeServerTicket(
            nullptr,
            5,
            InputTicketBuffer,
            AlpnList,
            sizeof(AlpnList),
            &DecodedTP,
            &DecodedAppData,
            &DecodedAppDataLength));

    // Not enough room for TP length
    ASSERT_EQ(
        QUIC_STATUS_INVALID_PARAMETER,
        QuicCryptoDecodeServerTicket(
            nullptr,
            6,
            InputTicketBuffer,
            AlpnList,
            sizeof(AlpnList),
            &DecodedTP,
            &DecodedAppData,
            &DecodedAppDataLength));

    // Not enough room for App Data length
    ASSERT_EQ(
        QUIC_STATUS_INVALID_PARAMETER,
        QuicCryptoDecodeServerTicket(
            nullptr,
            7,
            InputTicketBuffer,
            AlpnList,
            sizeof(AlpnList),
            &DecodedTP,
            &DecodedAppData,
            &DecodedAppDataLength));

    // Not enough room for negotiated ALPN length
    ASSERT_EQ(
        QUIC_STATUS_INVALID_PARAMETER,
        QuicCryptoDecodeServerTicket(
            nullptr,
            8,
            InputTicketBuffer,
            AlpnList,
            sizeof(AlpnList),
            &DecodedTP,
            &DecodedAppData,
            &DecodedAppDataLength));
    ASSERT_EQ(
        QUIC_STATUS_INVALID_PARAMETER,
        QuicCryptoDecodeServerTicket(
            nullptr,
            8 + (uint16_t)(sizeof(Alpn) / 2),
            InputTicketBuffer,
            AlpnList,
            sizeof(AlpnList),
            &DecodedTP,
            &DecodedAppData,
            &DecodedAppDataLength));

    // Not enough room for handshake TP
    ASSERT_EQ(
        QUIC_STATUS_INVALID_PARAMETER,
        QuicCryptoDecodeServerTicket(
            nullptr,
            8 + (uint16_t)sizeof(Alpn),
            InputTicketBuffer,
            AlpnList,
            sizeof(AlpnList),
            &DecodedTP,
            &DecodedAppData,
            &DecodedAppDataLength));
    ASSERT_EQ(
        QUIC_STATUS_INVALID_PARAMETER,
        QuicCryptoDecodeServerTicket(
            nullptr,
            8 + (uint16_t)sizeof(Alpn) + (uint16_t)((EncodedTPLength - CxPlatTlsTPHeaderSize) / 2),
            InputTicketBuffer,
            AlpnList,
            sizeof(AlpnList),
            &DecodedTP,
            &DecodedAppData,
            &DecodedAppDataLength));
    ASSERT_EQ(
        QUIC_STATUS_INVALID_PARAMETER,
        QuicCryptoDecodeServerTicket(
            nullptr,
            8 + (uint16_t)sizeof(Alpn) + (uint16_t)(EncodedTPLength - CxPlatTlsTPHeaderSize) - 1,
            InputTicketBuffer,
            AlpnList,
            sizeof(AlpnList),
            &DecodedTP,
            &DecodedAppData,
            &DecodedAppDataLength));

    // Not enough room for App Data
    ASSERT_EQ(
        QUIC_STATUS_INVALID_PARAMETER,
        QuicCryptoDecodeServerTicket(
            nullptr,
            8 + (uint16_t)sizeof(Alpn) + (uint16_t)(EncodedTPLength - CxPlatTlsTPHeaderSize),
            InputTicketBuffer,
            AlpnList,
            sizeof(AlpnList),
            &DecodedTP,
            &DecodedAppData,
            &DecodedAppDataLength));
    ASSERT_EQ(
        QUIC_STATUS_INVALID_PARAMETER,
        QuicCryptoDecodeServerTicket(
            nullptr,
            8 + (uint16_t)sizeof(Alpn) + (uint16_t)(EncodedTPLength - CxPlatTlsTPHeaderSize) + (uint16_t)(sizeof(AppData) - 1),
            InputTicketBuffer,
            AlpnList,
            sizeof(AlpnList),
            &DecodedTP,
            &DecodedAppData,
            &DecodedAppDataLength));

    //
    // Invalidate some of the fields of the ticket to ensure
    // decoding fails
    //

    const uint16_t ActualEncodedTicketLength =
        8 + (uint16_t)sizeof(Alpn) + (uint16_t)(EncodedTPLength - CxPlatTlsTPHeaderSize) + (uint16_t)sizeof(AppData);

    // Incorrect ticket version
    InputTicketBuffer[0] = CXPLAT_TLS_RESUMPTION_TICKET_VERSION + 1;
    ASSERT_EQ(
        QUIC_STATUS_INVALID_PARAMETER,
        QuicCryptoDecodeServerTicket(
            nullptr,
            ActualEncodedTicketLength,
            InputTicketBuffer,
            AlpnList,
            sizeof(AlpnList),
            &DecodedTP,
            &DecodedAppData,
            &DecodedAppDataLength));
    InputTicketBuffer[0] = CXPLAT_TLS_RESUMPTION_CLIENT_TICKET_VERSION;

    // Unsupported QUIC version
    InputTicketBuffer[1] = 1;
    InputTicketBuffer[2] = 1;
    InputTicketBuffer[3] = 1;
    InputTicketBuffer[4] = 1;
    ASSERT_EQ(
        QUIC_STATUS_INVALID_PARAMETER,
        QuicCryptoDecodeServerTicket(
            nullptr,
            ActualEncodedTicketLength,
            InputTicketBuffer,
            AlpnList,
            sizeof(AlpnList),
            &DecodedTP,
            &DecodedAppData,
            &DecodedAppDataLength));
    InputTicketBuffer[1] = 0;
    InputTicketBuffer[2] = 0;
    InputTicketBuffer[3] = 0;
    InputTicketBuffer[4] = 1;

    // Negotiated ALPN length shorter than actual
    for (uint8_t s = 0; s < (uint8_t)sizeof(Alpn); ++s) {
        QuicTraceLogInfo(
            ServerResumptionTicketDecodeFailAlpnLengthShort,
            "[test] Attempting to decode Negotiated ALPN with length %u (Actual: %u)",
            s,
            (uint8_t)sizeof(Alpn));

        InputTicketBuffer[5] = s;
        ASSERT_EQ(
            QUIC_STATUS_INVALID_PARAMETER,
            QuicCryptoDecodeServerTicket(
                nullptr,
                ActualEncodedTicketLength,
                InputTicketBuffer,
                AlpnList,
                sizeof(AlpnList),
                &DecodedTP,
                &DecodedAppData,
                &DecodedAppDataLength));
    }

    // Negotiated ALPN length longer than actual
    InputTicketBuffer[5] = (uint8_t)sizeof(Alpn) + 1;
    ASSERT_EQ(
        QUIC_STATUS_INVALID_PARAMETER,
        QuicCryptoDecodeServerTicket(
            nullptr,
            ActualEncodedTicketLength,
            InputTicketBuffer,
            AlpnList,
            sizeof(AlpnList),
            &DecodedTP,
            &DecodedAppData,
            &DecodedAppDataLength));

    // Negotiated ALPN length improperly encoded QUIC_VAR_INT
    for (uint8_t i = 1; i < 4; ++i) {
        InputTicketBuffer[5] = (uint8_t)(i << 6);

        QuicTraceLogInfo(
            ServerResumptionTicketDecodeFailAlpnLengthEncodedWrong,
            "[test] Attempting to decode Negotiated ALPN length (improperly encoded) %x (Actual: %u)",
            InputTicketBuffer[5],
            (uint8_t)sizeof(Alpn));

        ASSERT_EQ(
            QUIC_STATUS_INVALID_PARAMETER,
            QuicCryptoDecodeServerTicket(
                nullptr,
                ActualEncodedTicketLength,
                InputTicketBuffer,
                AlpnList,
                sizeof(AlpnList),
                &DecodedTP,
                &DecodedAppData,
                &DecodedAppDataLength));
    }
    InputTicketBuffer[5] = (uint8_t)sizeof(Alpn);

    // Handshake TP length shorter than actual
    for (uint8_t s = 0; s < EncodedTPLength - CxPlatTlsTPHeaderSize; ++s) {
        QuicTraceLogInfo(
            ServerResumptionTicketDecodeFailTpLengthShort,
            "[test] Attempting to decode Handshake TP with length %u (Actual: %u)",
            s,
            EncodedTPLength - CxPlatTlsTPHeaderSize);

        InputTicketBuffer[6] = s;
        ASSERT_EQ(
            QUIC_STATUS_INVALID_PARAMETER,
            QuicCryptoDecodeServerTicket(
                nullptr,
                ActualEncodedTicketLength,
                InputTicketBuffer,
                AlpnList,
                sizeof(AlpnList),
                &DecodedTP,
                &DecodedAppData,
                &DecodedAppDataLength));
    }

    // Handshake TP length longer than actual
    InputTicketBuffer[6] = (uint8_t)(EncodedTPLength - CxPlatTlsTPHeaderSize) + 1;
    ASSERT_EQ(
        QUIC_STATUS_INVALID_PARAMETER,
        QuicCryptoDecodeServerTicket(
            nullptr,
            ActualEncodedTicketLength,
            InputTicketBuffer,
            AlpnList,
            sizeof(AlpnList),
            &DecodedTP,
            &DecodedAppData,
            &DecodedAppDataLength));

    // Handshake TP length improperly encoded QUIC_VAR_INT
    for (uint8_t i = 1; i < 4; ++i) {
        InputTicketBuffer[6] = (uint8_t)(i << 6);
        QuicTraceLogInfo(
            ServerResumptionTicketDecodeFailTpLengthEncodedWrong,
            "[test] Attempting to decode Handshake TP length (improperly encoded) %x (Actual: %u)",
            InputTicketBuffer[6],
            EncodedTPLength - CxPlatTlsTPHeaderSize);

        ASSERT_EQ(
            QUIC_STATUS_INVALID_PARAMETER,
            QuicCryptoDecodeServerTicket(
                nullptr,
                ActualEncodedTicketLength,
                InputTicketBuffer,
                AlpnList,
                sizeof(AlpnList),
                &DecodedTP,
                &DecodedAppData,
                &DecodedAppDataLength));
    }
    InputTicketBuffer[6] = (uint8_t)(EncodedTPLength - CxPlatTlsTPHeaderSize);

    // App Data length shorter than actual
    for (uint8_t s = 0; s < (uint8_t)sizeof(AppData); ++s) {
        QuicTraceLogInfo(
            ServerResumptionTicketDecodeFailAppDataLengthShort,
            "[test] Attempting to decode App Data with length %u (Actual: %u)",
            s,
            (uint8_t)sizeof(AppData));

        InputTicketBuffer[7] = s;
        ASSERT_EQ(
            QUIC_STATUS_INVALID_PARAMETER,
            QuicCryptoDecodeServerTicket(
                nullptr,
                ActualEncodedTicketLength,
                InputTicketBuffer,
                AlpnList,
                sizeof(AlpnList),
                &DecodedTP,
                &DecodedAppData,
                &DecodedAppDataLength));
    }

    // App Data length longer than actual
    InputTicketBuffer[7] = (uint8_t)sizeof(AppData) + 1;
        ASSERT_EQ(
            QUIC_STATUS_INVALID_PARAMETER,
            QuicCryptoDecodeServerTicket(
                nullptr,
                ActualEncodedTicketLength,
                InputTicketBuffer,
                AlpnList,
                sizeof(AlpnList),
                &DecodedTP,
                &DecodedAppData,
                &DecodedAppDataLength));

    // App Data length improperly encoded QUIC_VAR_INT
    for (uint8_t i = 1; i < 4; ++i) {
        InputTicketBuffer[7] = (uint8_t)(i << 6);
        QuicTraceLogInfo(
            ServerResumptionTicketDecodeFailAppDataLengthEncodedWrong,
            "[test] Attempting to decode App Data length (improperly encoded) %x (Actual: %u)",
            InputTicketBuffer[7],
            (uint8_t)sizeof(AppData));

        ASSERT_EQ(
            QUIC_STATUS_INVALID_PARAMETER,
            QuicCryptoDecodeServerTicket(
                nullptr,
                ActualEncodedTicketLength,
                InputTicketBuffer,
                AlpnList,
                sizeof(AlpnList),
                &DecodedTP,
                &DecodedAppData,
                &DecodedAppDataLength));
    }
}

TEST(ResumptionTicketTest, ClientServerEndToEnd)
{
    uint8_t AppData[] = {10, 9, 8, 7, 6, 5, 4, 3, 2, 1};
    QUIC_TRANSPORT_PARAMETERS ServerTP, ClientTP, DecodedClientTP, DecodedServerTP;
    uint8_t NegotiatedAlpn[] = {4, 't', 'e', 's', 't'};
    uint8_t* EncodedServerTicket = nullptr, *DecodedServerTicket = nullptr;
    uint32_t EncodedServerTicketLength = 0, EncodedClientTicketLength = 0, DecodedServerTicketLength = 0, DecodedAppDataLength = 0, DecodedQuicVersion = 0;
    const uint8_t* EncodedClientTicket = nullptr, *DecodedAppData = nullptr;

    CxPlatZeroMemory(&ServerTP, sizeof(ServerTP));
    CxPlatZeroMemory(&DecodedServerTP, sizeof(DecodedServerTP));
    ServerTP.Flags =
        QUIC_TP_FLAG_ACTIVE_CONNECTION_ID_LIMIT |
        QUIC_TP_FLAG_INITIAL_MAX_DATA |
        QUIC_TP_FLAG_INITIAL_MAX_STRM_DATA_BIDI_LOCAL |
        QUIC_TP_FLAG_INITIAL_MAX_STRM_DATA_BIDI_REMOTE |
        QUIC_TP_FLAG_INITIAL_MAX_STRM_DATA_UNI |
        QUIC_TP_FLAG_INITIAL_MAX_STRMS_BIDI |
        QUIC_TP_FLAG_INITIAL_MAX_STRMS_UNI;
    ServerTP.ActiveConnectionIdLimit = QUIC_TP_ACTIVE_CONNECTION_ID_LIMIT_MIN;

    CxPlatZeroMemory(&DecodedClientTP, sizeof(DecodedClientTP));
    CxPlatZeroMemory(&ClientTP, sizeof(ClientTP));
    ClientTP.Flags =
        QUIC_TP_FLAG_ACTIVE_CONNECTION_ID_LIMIT |
        QUIC_TP_FLAG_INITIAL_MAX_DATA |
        QUIC_TP_FLAG_INITIAL_MAX_STRM_DATA_BIDI_LOCAL |
        QUIC_TP_FLAG_INITIAL_MAX_STRM_DATA_BIDI_REMOTE |
        QUIC_TP_FLAG_INITIAL_MAX_STRM_DATA_UNI |
        QUIC_TP_FLAG_INITIAL_MAX_STRMS_BIDI |
        QUIC_TP_FLAG_INITIAL_MAX_STRMS_UNI;
    ClientTP.ActiveConnectionIdLimit = QUIC_TP_ACTIVE_CONNECTION_ID_LIMIT_MIN;

    TEST_QUIC_SUCCEEDED(
        QuicCryptoEncodeServerTicket(
            nullptr,
            QUIC_VERSION_LATEST,
            sizeof(AppData),
            AppData,
            &ServerTP,
            NegotiatedAlpn[0],
            NegotiatedAlpn + 1,
            &EncodedServerTicket,
            &EncodedServerTicketLength));

    ASSERT_NE(EncodedServerTicket, nullptr);
    ASSERT_NE((uint16_t)EncodedServerTicketLength, 0);

    TEST_QUIC_SUCCEEDED(
        QuicCryptoEncodeClientTicket(
            nullptr,
            (uint16_t)EncodedServerTicketLength,
            EncodedServerTicket,
            &ClientTP,
            QUIC_VERSION_LATEST,
            &EncodedClientTicket,
            &EncodedClientTicketLength));

    ASSERT_NE(EncodedClientTicket, nullptr);
    ASSERT_NE((uint16_t)EncodedClientTicketLength, 0);

    TEST_QUIC_SUCCEEDED(
        QuicCryptoDecodeClientTicket(
            nullptr,
            (uint16_t)EncodedClientTicketLength,
            EncodedClientTicket,
            &DecodedClientTP,
            &DecodedServerTicket,
            &DecodedServerTicketLength,
            &DecodedQuicVersion));

    ASSERT_EQ(QUIC_VERSION_LATEST, DecodedQuicVersion);
    ASSERT_EQ(DecodedServerTicketLength, EncodedServerTicketLength);
    ASSERT_NE(DecodedServerTicket, nullptr);
    ASSERT_TRUE(memcmp(DecodedServerTicket, EncodedServerTicket, DecodedServerTicketLength) == 0);
    CompareTransportParameters(&ClientTP, &DecodedClientTP);

    TEST_QUIC_SUCCEEDED(
        QuicCryptoDecodeServerTicket(
            nullptr,
            (uint16_t)EncodedServerTicketLength,
            EncodedServerTicket,
            NegotiatedAlpn,
            sizeof(NegotiatedAlpn),
            &DecodedServerTP,
            &DecodedAppData,
            &DecodedAppDataLength));

    ASSERT_EQ(DecodedAppDataLength, sizeof(AppData));
    ASSERT_NE(DecodedAppData, nullptr);
    ASSERT_TRUE(memcmp(AppData, DecodedAppData, sizeof(AppData)) == 0);
    CompareTransportParameters(&ServerTP, &DecodedServerTP);

    CXPLAT_FREE(EncodedClientTicket, QUIC_POOL_CLIENT_CRYPTO_TICKET);
    CXPLAT_FREE(EncodedServerTicket, QUIC_POOL_SERVER_CRYPTO_TICKET);
    CXPLAT_FREE(DecodedServerTicket, QUIC_POOL_CRYPTO_RESUMPTION_TICKET);
}
