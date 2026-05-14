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

struct TransportParamsScope {
    const uint8_t* const TP;
    TransportParamsScope(const uint8_t* newTP) : TP(newTP) {}
    ~TransportParamsScope() {
        if (TP != nullptr) {
            CXPLAT_FREE(TP, QUIC_POOL_TLS_TRANSPARAMS);
        }
    }
};

struct TicketScope {
    uint8_t* p = nullptr;

    ~TicketScope() {
        reset();
    }

    void reset() {
        if (p != nullptr) {
            CXPLAT_FREE(p, QUIC_POOL_CRYPTO_RESUMPTION_TICKET);
            p = nullptr;
        }
    }

    uint8_t** reset_and_addressof() noexcept {
        reset();
        return &p;
    }
};

TEST(ResumptionTicketTest, ClientDecFail)
{
    const uint8_t TransportParametersLength = 21; // Update if TP size changes
    const uint8_t ServerTicket[] = {1,2,3,4,5};
    QUIC_TRANSPORT_PARAMETERS ServerTP;
    QUIC_TRANSPORT_PARAMETERS DecodedTP;
    const uint8_t* EncodedServerTP = nullptr;
    uint32_t EncodedTPLength = 0;
    TicketScope DecodedServerTicket;
    uint32_t DecodedServerTicketLength = 0;
    uint32_t DecodedQuicVersion = 0;

    uint8_t InputTicketBuffer[7 + TransportParametersLength + sizeof(ServerTicket)] = {
        CXPLAT_TLS_RESUMPTION_CLIENT_TICKET_VERSION,
        0,0,0,1,                    // QUIC version
        0,                          // TP length, update after encoding
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
    TransportParamsScope TPScope(EncodedServerTP);
    ASSERT_NE(EncodedServerTP, nullptr);
    ASSERT_LE(EncodedTPLength - CxPlatTlsTPHeaderSize, TransportParametersLength);
    ASSERT_GT(sizeof(InputTicketBuffer), EncodedTPLength);

    CxPlatCopyMemory(
        &InputTicketBuffer[7],
        EncodedServerTP + CxPlatTlsTPHeaderSize,
        EncodedTPLength - CxPlatTlsTPHeaderSize);
    // Update with Encoded TP length
    InputTicketBuffer[5] = (uint8_t)(EncodedTPLength - CxPlatTlsTPHeaderSize);

    ASSERT_GE(sizeof(InputTicketBuffer), (EncodedTPLength - CxPlatTlsTPHeaderSize) + sizeof(ServerTicket));
    CxPlatCopyMemory(
        &InputTicketBuffer[7 + EncodedTPLength - CxPlatTlsTPHeaderSize],
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
            DecodedServerTicket.reset_and_addressof(),
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
            DecodedServerTicket.reset_and_addressof(),
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
            DecodedServerTicket.reset_and_addressof(),
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
            DecodedServerTicket.reset_and_addressof(),
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
            DecodedServerTicket.reset_and_addressof(),
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
            DecodedServerTicket.reset_and_addressof(),
            &DecodedServerTicketLength,
            &DecodedQuicVersion));

    ASSERT_EQ(
        QUIC_STATUS_INVALID_PARAMETER,
        QuicCryptoDecodeClientTicket(
            nullptr,
            7 + ((uint16_t)(EncodedTPLength - CxPlatTlsTPHeaderSize) / 2),
            InputTicketBuffer,
            &DecodedTP,
            DecodedServerTicket.reset_and_addressof(),
            &DecodedServerTicketLength,
            &DecodedQuicVersion));

    ASSERT_EQ(
        QUIC_STATUS_INVALID_PARAMETER,
        QuicCryptoDecodeClientTicket(
            nullptr,
            7 + ((uint16_t)(EncodedTPLength - CxPlatTlsTPHeaderSize) - 1),
            InputTicketBuffer,
            &DecodedTP,
            DecodedServerTicket.reset_and_addressof(),
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
            DecodedServerTicket.reset_and_addressof(),
            &DecodedServerTicketLength,
            &DecodedQuicVersion));

    ASSERT_EQ(
        QUIC_STATUS_INVALID_PARAMETER,
        QuicCryptoDecodeClientTicket(
            nullptr,
            7 + (uint16_t)(EncodedTPLength - CxPlatTlsTPHeaderSize) + ((uint16_t)sizeof(ServerTicket) - 1),
            InputTicketBuffer,
            &DecodedTP,
            DecodedServerTicket.reset_and_addressof(),
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
            DecodedServerTicket.reset_and_addressof(),
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
            DecodedServerTicket.reset_and_addressof(),
            &DecodedServerTicketLength,
            &DecodedQuicVersion));
    InputTicketBuffer[1] = 0;
    InputTicketBuffer[2] = 0;
    InputTicketBuffer[3] = 0;
    InputTicketBuffer[4] = 1;

    // Client TP length shorter than actual
    for (uint8_t s = 0; s < (uint8_t)(EncodedTPLength - CxPlatTlsTPHeaderSize); ++s) {
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
                DecodedServerTicket.reset_and_addressof(),
                &DecodedServerTicketLength,
                &DecodedQuicVersion));
    }

    // Client TP length longer than actual
    InputTicketBuffer[5] = (uint8_t)(EncodedTPLength - (uint8_t)CxPlatTlsTPHeaderSize) + 1;
    ASSERT_EQ(
        QUIC_STATUS_INVALID_PARAMETER,
        QuicCryptoDecodeClientTicket(
            nullptr,
            7 + (uint16_t)(EncodedTPLength - CxPlatTlsTPHeaderSize) + (uint16_t)sizeof(ServerTicket),
            InputTicketBuffer,
            &DecodedTP,
            DecodedServerTicket.reset_and_addressof(),
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
                DecodedServerTicket.reset_and_addressof(),
                &DecodedServerTicketLength,
                &DecodedQuicVersion));
    }
    InputTicketBuffer[5] = (uint8_t)(EncodedTPLength - (uint8_t)CxPlatTlsTPHeaderSize);

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
                DecodedServerTicket.reset_and_addressof(),
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
            DecodedServerTicket.reset_and_addressof(),
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
                DecodedServerTicket.reset_and_addressof(),
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

    QUIC_CONNECTION Connection;
    CxPlatZeroMemory(&Connection, sizeof(Connection));
    Connection.Stats.QuicVersion = QUIC_VERSION_1;

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
            NULL,
            NegotiatedAlpn[0],
            NegotiatedAlpn + 1,
            &EncodedServerTicket,
            &EncodedServerTicketLength));

    ASSERT_NE(EncodedServerTicket, nullptr);
    ASSERT_NE((uint16_t)EncodedServerTicketLength, 0);

    TEST_QUIC_SUCCEEDED(
        QuicCryptoDecodeServerTicket(
            &Connection,
            (uint16_t)EncodedServerTicketLength,
            EncodedServerTicket,
            NegotiatedAlpn,
            sizeof(NegotiatedAlpn),
            &DecodedTP,
            NULL,
            &DecodedAppData,
            &DecodedAppDataLength));

    ASSERT_EQ(DecodedAppDataLength, sizeof(AppData));
    ASSERT_NE(DecodedAppData, nullptr);
    ASSERT_TRUE(memcmp(AppData, DecodedAppData, sizeof(AppData)) == 0);
    CompareTransportParameters(&ServerTP, &DecodedTP);

    CXPLAT_FREE(EncodedServerTicket, QUIC_POOL_SERVER_CRYPTO_TICKET);
}

TEST(ResumptionTicketTest, ServerEncDecNoAppDataNoCR)
{
    QUIC_TRANSPORT_PARAMETERS ServerTP;
    uint8_t NegotiatedAlpn[] = {4, 't', 'e', 's', 't'};
    uint8_t* EncodedServerTicket = nullptr;
    uint32_t EncodedServerTicketLength = 0;

    QUIC_TRANSPORT_PARAMETERS DecodedServerTP;
    const uint8_t* DecodedAppData = nullptr;
    uint32_t DecodedAppDataLength = 0;

    QUIC_CONNECTION Connection;
    CxPlatZeroMemory(&Connection, sizeof(Connection));
    Connection.Stats.QuicVersion = QUIC_VERSION_1;

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
            NULL,
            NegotiatedAlpn[0],
            NegotiatedAlpn + 1,
            &EncodedServerTicket,
            &EncodedServerTicketLength));

    ASSERT_NE(EncodedServerTicket, nullptr);
    ASSERT_NE((uint16_t)EncodedServerTicketLength, 0);

    TEST_QUIC_SUCCEEDED(
        QuicCryptoDecodeServerTicket(
            &Connection,
            (uint16_t)EncodedServerTicketLength,
            EncodedServerTicket,
            NegotiatedAlpn,
            sizeof(NegotiatedAlpn),
            &DecodedServerTP,
            NULL,
            &DecodedAppData,
            &DecodedAppDataLength));

    ASSERT_EQ((uint16_t)DecodedAppDataLength, 0);
    ASSERT_EQ(DecodedAppData, nullptr);
    CompareTransportParameters(&ServerTP, &DecodedServerTP);

    CXPLAT_FREE(EncodedServerTicket, QUIC_POOL_SERVER_CRYPTO_TICKET);
}

TEST(ResumptionTicketTest, ServerEncDecNoAppDataWithIpV4CR)
{
    QUIC_TRANSPORT_PARAMETERS ServerTP;
    uint8_t NegotiatedAlpn[] = {4, 't', 'e', 's', 't'};
    uint8_t* EncodedServerTicket = nullptr;
    uint32_t EncodedServerTicketLength = 0;

    QUIC_TRANSPORT_PARAMETERS DecodedServerTP;
    const uint8_t* DecodedAppData = nullptr;
    uint32_t DecodedAppDataLength = 0;
    QUIC_CONN_CAREFUL_RESUME_STATE CarefulResumeState = {};
    QUIC_CONN_CAREFUL_RESUME_STATE DecodedCarefulResumeState = {};

    QUIC_CONNECTION Connection;
    CxPlatZeroMemory(&Connection, sizeof(Connection));
    Connection.Stats.QuicVersion = QUIC_VERSION_1;

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

    // Set IPv4 address 192.0.2.1 (do not set port)
    CxPlatZeroMemory(&CarefulResumeState.RemoteEndpoint, sizeof(CarefulResumeState.RemoteEndpoint));
    QuicAddrFromString("192.0.2.1", 0, &CarefulResumeState.RemoteEndpoint);

    // Test all valid QUIC_CONGESTION_CONTROL_ALGORITHM values
    const struct {
        QUIC_CONGESTION_CONTROL_ALGORITHM Algorithm;
        const char* Name;
    } kAlgorithms[] = {
        { QUIC_CONGESTION_CONTROL_ALGORITHM_CUBIC, "CUBIC" },
#if defined(QUIC_API_ENABLE_PREVIEW_FEATURES)
        { QUIC_CONGESTION_CONTROL_ALGORITHM_BBR, "BBR" },
#endif
    };

    for (size_t i = 0; i < ARRAYSIZE(kAlgorithms); ++i) {
        // Populate CarefulResumeState with test values
        CarefulResumeState.SmoothedRtt = 12345 + (uint64_t)i;
        CarefulResumeState.MinRtt = 2345 + (uint64_t)i;
        CarefulResumeState.Expiration = 0x1122334455667788 + (uint64_t)i;
        CarefulResumeState.Algorithm = kAlgorithms[i].Algorithm;
        CarefulResumeState.CongestionWindow = 65536 + (uint32_t)i;

        EncodedServerTicket = nullptr;
        EncodedServerTicketLength = 0;
        CxPlatZeroMemory(&DecodedServerTP, sizeof(DecodedServerTP));
        CxPlatZeroMemory(&DecodedCarefulResumeState, sizeof(DecodedCarefulResumeState));
        DecodedAppData = nullptr;
        DecodedAppDataLength = 0;

        TEST_QUIC_SUCCEEDED(
            QuicCryptoEncodeServerTicket(
                nullptr,
                QUIC_VERSION_LATEST,
                0,
                nullptr,
                &ServerTP,
                &CarefulResumeState,
                NegotiatedAlpn[0],
                NegotiatedAlpn + 1,
                &EncodedServerTicket,
                &EncodedServerTicketLength));

        ASSERT_NE(EncodedServerTicket, nullptr);
        ASSERT_NE((uint16_t)EncodedServerTicketLength, 0);

        TEST_QUIC_SUCCEEDED(
            QuicCryptoDecodeServerTicket(
                &Connection,
                (uint16_t)EncodedServerTicketLength,
                EncodedServerTicket,
                NegotiatedAlpn,
                sizeof(NegotiatedAlpn),
                &DecodedServerTP,
                &DecodedCarefulResumeState,
                &DecodedAppData,
                &DecodedAppDataLength));

        ASSERT_EQ((uint16_t)DecodedAppDataLength, 0);
        ASSERT_EQ(DecodedAppData, nullptr);
        CompareTransportParameters(&ServerTP, &DecodedServerTP);

        // Validate CarefulResumeState fields (except port)
        ASSERT_EQ(CarefulResumeState.SmoothedRtt, DecodedCarefulResumeState.SmoothedRtt) << kAlgorithms[i].Name;
        ASSERT_EQ(CarefulResumeState.MinRtt, DecodedCarefulResumeState.MinRtt) << kAlgorithms[i].Name;
        ASSERT_EQ(CarefulResumeState.Expiration, DecodedCarefulResumeState.Expiration) << kAlgorithms[i].Name;
        ASSERT_EQ(CarefulResumeState.Algorithm, DecodedCarefulResumeState.Algorithm) << kAlgorithms[i].Name;
        ASSERT_EQ(CarefulResumeState.CongestionWindow, DecodedCarefulResumeState.CongestionWindow) << kAlgorithms[i].Name;
        ASSERT_EQ(QuicAddrGetFamily(&CarefulResumeState.RemoteEndpoint),
                    QuicAddrGetFamily(&DecodedCarefulResumeState.RemoteEndpoint)) << kAlgorithms[i].Name;
        ASSERT_TRUE(QuicAddrCompareIp(&CarefulResumeState.RemoteEndpoint,
                                        &DecodedCarefulResumeState.RemoteEndpoint)) << kAlgorithms[i].Name;

        CXPLAT_FREE(EncodedServerTicket, QUIC_POOL_SERVER_CRYPTO_TICKET);
    }
}

TEST(ResumptionTicketTest, ServerEncDecAppData250WithIpV4ClassBCR)
{
    QUIC_TRANSPORT_PARAMETERS ServerTP;
    uint8_t NegotiatedAlpn[] = {4, 't', 'e', 's', 't'};
    uint8_t* EncodedServerTicket = nullptr;
    uint32_t EncodedServerTicketLength = 0;

    QUIC_TRANSPORT_PARAMETERS DecodedServerTP;
    const uint8_t* DecodedAppData = nullptr;
    uint32_t DecodedAppDataLength = 0;
    QUIC_CONN_CAREFUL_RESUME_STATE CarefulResumeState = {};
    QUIC_CONN_CAREFUL_RESUME_STATE DecodedCarefulResumeState = {};

    QUIC_CONNECTION Connection;
    CxPlatZeroMemory(&Connection, sizeof(Connection));
    Connection.Stats.QuicVersion = QUIC_VERSION_1;

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

    // Set IPv4 Class B address 172.16.0.1 (do not set port)
    CxPlatZeroMemory(&CarefulResumeState.RemoteEndpoint, sizeof(CarefulResumeState.RemoteEndpoint));
    QuicAddrFromString("172.16.0.1", 0, &CarefulResumeState.RemoteEndpoint);

    // Use only CUBIC algorithm
    CarefulResumeState.SmoothedRtt = 12345;
    CarefulResumeState.MinRtt = 2345;
    CarefulResumeState.Expiration = 0x1122334455667788;
    CarefulResumeState.Algorithm = QUIC_CONGESTION_CONTROL_ALGORITHM_CUBIC;
    CarefulResumeState.CongestionWindow = 65536;

    // AppData: 250 bytes, monotonically increasing
    uint8_t AppData[250];
    for (uint32_t i = 0; i < sizeof(AppData); ++i) {
        AppData[i] = (uint8_t)i;
    }

    EncodedServerTicket = nullptr;
    EncodedServerTicketLength = 0;
    CxPlatZeroMemory(&DecodedServerTP, sizeof(DecodedServerTP));
    CxPlatZeroMemory(&DecodedCarefulResumeState, sizeof(DecodedCarefulResumeState));
    DecodedAppData = nullptr;
    DecodedAppDataLength = 0;

    TEST_QUIC_SUCCEEDED(
        QuicCryptoEncodeServerTicket(
            nullptr,
            QUIC_VERSION_LATEST,
            sizeof(AppData),
            AppData,
            &ServerTP,
            &CarefulResumeState,
            NegotiatedAlpn[0],
            NegotiatedAlpn + 1,
            &EncodedServerTicket,
            &EncodedServerTicketLength));

    ASSERT_NE(EncodedServerTicket, nullptr);
    ASSERT_NE((uint16_t)EncodedServerTicketLength, 0);

    TEST_QUIC_SUCCEEDED(
        QuicCryptoDecodeServerTicket(
            &Connection,
            (uint16_t)EncodedServerTicketLength,
            EncodedServerTicket,
            NegotiatedAlpn,
            sizeof(NegotiatedAlpn),
            &DecodedServerTP,
            &DecodedCarefulResumeState,
            &DecodedAppData,
            &DecodedAppDataLength));

    ASSERT_EQ(DecodedAppDataLength, sizeof(AppData));
    ASSERT_NE(DecodedAppData, nullptr);
    ASSERT_TRUE(memcmp(AppData, DecodedAppData, sizeof(AppData)) == 0);
    CompareTransportParameters(&ServerTP, &DecodedServerTP);

    // Validate CarefulResumeState fields (except port)
    ASSERT_EQ(CarefulResumeState.SmoothedRtt, DecodedCarefulResumeState.SmoothedRtt);
    ASSERT_EQ(CarefulResumeState.MinRtt, DecodedCarefulResumeState.MinRtt);
    ASSERT_EQ(CarefulResumeState.Expiration, DecodedCarefulResumeState.Expiration);
    ASSERT_EQ(CarefulResumeState.Algorithm, DecodedCarefulResumeState.Algorithm);
    ASSERT_EQ(CarefulResumeState.CongestionWindow, DecodedCarefulResumeState.CongestionWindow);
    ASSERT_EQ(QuicAddrGetFamily(&CarefulResumeState.RemoteEndpoint),
                QuicAddrGetFamily(&DecodedCarefulResumeState.RemoteEndpoint));
    ASSERT_TRUE(QuicAddrCompareIp(&CarefulResumeState.RemoteEndpoint,
                                    &DecodedCarefulResumeState.RemoteEndpoint));

    CXPLAT_FREE(EncodedServerTicket, QUIC_POOL_SERVER_CRYPTO_TICKET);
}

TEST(ResumptionTicketTest, ServerEncDecNoAppDataWithIpV6CR)
{
    QUIC_TRANSPORT_PARAMETERS ServerTP;
    uint8_t NegotiatedAlpn[] = {4, 't', 'e', 's', 't'};
    uint8_t* EncodedServerTicket = nullptr;
    uint32_t EncodedServerTicketLength = 0;

    QUIC_TRANSPORT_PARAMETERS DecodedServerTP;
    const uint8_t* DecodedAppData = nullptr;
    uint32_t DecodedAppDataLength = 0;
    QUIC_CONN_CAREFUL_RESUME_STATE CarefulResumeState = {};
    QUIC_CONN_CAREFUL_RESUME_STATE DecodedCarefulResumeState = {};

    QUIC_CONNECTION Connection;
    CxPlatZeroMemory(&Connection, sizeof(Connection));
    Connection.Stats.QuicVersion = QUIC_VERSION_1;

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

    // Set IPv6 address 2001:db8::1 (do not set port)
    CxPlatZeroMemory(&CarefulResumeState.RemoteEndpoint, sizeof(CarefulResumeState.RemoteEndpoint));
    QuicAddrFromString("2001:db8::1", 0, &CarefulResumeState.RemoteEndpoint);

    // Test all valid QUIC_CONGESTION_CONTROL_ALGORITHM values
    const struct {
        QUIC_CONGESTION_CONTROL_ALGORITHM Algorithm;
        const char* Name;
    } kAlgorithms[] = {
        { QUIC_CONGESTION_CONTROL_ALGORITHM_CUBIC, "CUBIC" },
#if defined(QUIC_API_ENABLE_PREVIEW_FEATURES)
        { QUIC_CONGESTION_CONTROL_ALGORITHM_BBR, "BBR" },
#endif
    };

    for (size_t i = 0; i < ARRAYSIZE(kAlgorithms); ++i) {
        // Populate CarefulResumeState with test values
        CarefulResumeState.SmoothedRtt = 12345 + (uint64_t)i;
        CarefulResumeState.MinRtt = 2345 + (uint64_t)i;
        CarefulResumeState.Expiration = 0x1122334455667788 + (uint64_t)i;
        CarefulResumeState.Algorithm = kAlgorithms[i].Algorithm;
        CarefulResumeState.CongestionWindow = 65536 + (uint32_t)i;

        EncodedServerTicket = nullptr;
        EncodedServerTicketLength = 0;
        CxPlatZeroMemory(&DecodedServerTP, sizeof(DecodedServerTP));
        CxPlatZeroMemory(&DecodedCarefulResumeState, sizeof(DecodedCarefulResumeState));
        DecodedAppData = nullptr;
        DecodedAppDataLength = 0;

        TEST_QUIC_SUCCEEDED(
            QuicCryptoEncodeServerTicket(
                nullptr,
                QUIC_VERSION_LATEST,
                0,
                nullptr,
                &ServerTP,
                &CarefulResumeState,
                NegotiatedAlpn[0],
                NegotiatedAlpn + 1,
                &EncodedServerTicket,
                &EncodedServerTicketLength));

        ASSERT_NE(EncodedServerTicket, nullptr);
        ASSERT_NE((uint16_t)EncodedServerTicketLength, 0);

        TEST_QUIC_SUCCEEDED(
            QuicCryptoDecodeServerTicket(
                &Connection,
                (uint16_t)EncodedServerTicketLength,
                EncodedServerTicket,
                NegotiatedAlpn,
                sizeof(NegotiatedAlpn),
                &DecodedServerTP,
                &DecodedCarefulResumeState,
                &DecodedAppData,
                &DecodedAppDataLength));

        ASSERT_EQ((uint16_t)DecodedAppDataLength, 0);
        ASSERT_EQ(DecodedAppData, nullptr);
        CompareTransportParameters(&ServerTP, &DecodedServerTP);

        // Validate CarefulResumeState fields (except port)
        ASSERT_EQ(CarefulResumeState.SmoothedRtt, DecodedCarefulResumeState.SmoothedRtt) << kAlgorithms[i].Name;
        ASSERT_EQ(CarefulResumeState.MinRtt, DecodedCarefulResumeState.MinRtt) << kAlgorithms[i].Name;
        ASSERT_EQ(CarefulResumeState.Expiration, DecodedCarefulResumeState.Expiration) << kAlgorithms[i].Name;
        ASSERT_EQ(CarefulResumeState.Algorithm, DecodedCarefulResumeState.Algorithm) << kAlgorithms[i].Name;
        ASSERT_EQ(CarefulResumeState.CongestionWindow, DecodedCarefulResumeState.CongestionWindow) << kAlgorithms[i].Name;
        ASSERT_EQ(QuicAddrGetFamily(&CarefulResumeState.RemoteEndpoint),
                    QuicAddrGetFamily(&DecodedCarefulResumeState.RemoteEndpoint)) << kAlgorithms[i].Name;
        ASSERT_TRUE(QuicAddrCompareIp(&CarefulResumeState.RemoteEndpoint,
                                        &DecodedCarefulResumeState.RemoteEndpoint)) << kAlgorithms[i].Name;

        CXPLAT_FREE(EncodedServerTicket, QUIC_POOL_SERVER_CRYPTO_TICKET);
    }
}

TEST(ResumptionTicketTest, ServerEncDecAppData250WithIpV6CR)
{
    QUIC_TRANSPORT_PARAMETERS ServerTP;
    uint8_t NegotiatedAlpn[] = {4, 't', 'e', 's', 't'};
    uint8_t* EncodedServerTicket = nullptr;
    uint32_t EncodedServerTicketLength = 0;

    QUIC_TRANSPORT_PARAMETERS DecodedServerTP;
    const uint8_t* DecodedAppData = nullptr;
    uint32_t DecodedAppDataLength = 0;
    QUIC_CONN_CAREFUL_RESUME_STATE CarefulResumeState = {};
    QUIC_CONN_CAREFUL_RESUME_STATE DecodedCarefulResumeState = {};

    QUIC_CONNECTION Connection;
    CxPlatZeroMemory(&Connection, sizeof(Connection));
    Connection.Stats.QuicVersion = QUIC_VERSION_1;

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

    // Set IPv6 address 2001:db8::1 (do not set port)
    CxPlatZeroMemory(&CarefulResumeState.RemoteEndpoint, sizeof(CarefulResumeState.RemoteEndpoint));
    QuicAddrFromString("2001:db8::1", 0, &CarefulResumeState.RemoteEndpoint);

    // Use only CUBIC algorithm
    CarefulResumeState.SmoothedRtt = 12345;
    CarefulResumeState.MinRtt = 2345;
    CarefulResumeState.Expiration = 0x1122334455667788;
    CarefulResumeState.Algorithm = QUIC_CONGESTION_CONTROL_ALGORITHM_CUBIC;
    CarefulResumeState.CongestionWindow = 65536;

    // AppData: 250 bytes, monotonically increasing
    uint8_t AppData[250];
    for (uint32_t i = 0; i < sizeof(AppData); ++i) {
        AppData[i] = (uint8_t)i;
    }

    EncodedServerTicket = nullptr;
    EncodedServerTicketLength = 0;
    CxPlatZeroMemory(&DecodedServerTP, sizeof(DecodedServerTP));
    CxPlatZeroMemory(&DecodedCarefulResumeState, sizeof(DecodedCarefulResumeState));
    DecodedAppData = nullptr;
    DecodedAppDataLength = 0;

    TEST_QUIC_SUCCEEDED(
        QuicCryptoEncodeServerTicket(
            nullptr,
            QUIC_VERSION_LATEST,
            sizeof(AppData),
            AppData,
            &ServerTP,
            &CarefulResumeState,
            NegotiatedAlpn[0],
            NegotiatedAlpn + 1,
            &EncodedServerTicket,
            &EncodedServerTicketLength));

    ASSERT_NE(EncodedServerTicket, nullptr);
    ASSERT_NE((uint16_t)EncodedServerTicketLength, 0);

    TEST_QUIC_SUCCEEDED(
        QuicCryptoDecodeServerTicket(
            &Connection,
            (uint16_t)EncodedServerTicketLength,
            EncodedServerTicket,
            NegotiatedAlpn,
            sizeof(NegotiatedAlpn),
            &DecodedServerTP,
            &DecodedCarefulResumeState,
            &DecodedAppData,
            &DecodedAppDataLength));

    ASSERT_EQ(DecodedAppDataLength, sizeof(AppData));
    ASSERT_NE(DecodedAppData, nullptr);
    ASSERT_TRUE(memcmp(AppData, DecodedAppData, sizeof(AppData)) == 0);
    CompareTransportParameters(&ServerTP, &DecodedServerTP);

    // Validate CarefulResumeState fields (except port)
    ASSERT_EQ(CarefulResumeState.SmoothedRtt, DecodedCarefulResumeState.SmoothedRtt);
    ASSERT_EQ(CarefulResumeState.MinRtt, DecodedCarefulResumeState.MinRtt);
    ASSERT_EQ(CarefulResumeState.Expiration, DecodedCarefulResumeState.Expiration);
    ASSERT_EQ(CarefulResumeState.Algorithm, DecodedCarefulResumeState.Algorithm);
    ASSERT_EQ(CarefulResumeState.CongestionWindow, DecodedCarefulResumeState.CongestionWindow);
    ASSERT_EQ(QuicAddrGetFamily(&CarefulResumeState.RemoteEndpoint),
                QuicAddrGetFamily(&DecodedCarefulResumeState.RemoteEndpoint));
    ASSERT_TRUE(QuicAddrCompareIp(&CarefulResumeState.RemoteEndpoint,
                                    &DecodedCarefulResumeState.RemoteEndpoint));

    CXPLAT_FREE(EncodedServerTicket, QUIC_POOL_SERVER_CRYPTO_TICKET);
}
TEST(ResumptionTicketTest, ServerTicketDecodeFailureCases)
{
    const uint8_t TicketBufferFixedV1HeaderLength = 8;
    const uint8_t TicketBufferFixedV2HeaderLength = TicketBufferFixedV1HeaderLength + 1; // for CR lengths < 0x3F
    const uint8_t TransportParametersLength = 21; // Update if TP size changes
    const uint8_t AppData[] = {1,2,3,4,5};
    const uint8_t Alpn[] = {'t', 'e', 's', 't'};
    const uint8_t AlpnList[] = {4, 't', 'e', 's', 't'};
    QUIC_TRANSPORT_PARAMETERS HandshakeTP;
    QUIC_TRANSPORT_PARAMETERS DecodedTP;
    const uint8_t* EncodedHandshakeTP = nullptr;
    uint32_t EncodedTPLength = 0;
    const uint8_t* DecodedAppData = nullptr;
    uint32_t DecodedAppDataLength = 0;

    uint32_t Versions[] = {QUIC_VERSION_1, QUIC_VERSION_2};
    QUIC_VERSION_SETTINGS VersionSettings = {
        Versions, Versions,Versions,
        ARRAYSIZE(Versions), ARRAYSIZE(Versions),ARRAYSIZE(Versions)
    };

    QUIC_CONNECTION Connection;
    CxPlatZeroMemory(&Connection, sizeof(Connection));
    Connection.Stats.QuicVersion = QUIC_VERSION_1;

    uint8_t InputTicketBuffer[TicketBufferFixedV2HeaderLength + TransportParametersLength +
                                sizeof(Alpn) + sizeof(AppData)] = {
        CXPLAT_TLS_RESUMPTION_TICKET_MAX_VERSION,
        0,0,0,1,                    // QUIC version
        4,                          // ALPN length
        0,                          // TP length, update after encoding
        0,                          // CR length
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
            &Connection,
            TRUE,
            &HandshakeTP,
            nullptr,
            &EncodedTPLength);
    TransportParamsScope TPScope(EncodedHandshakeTP);
    ASSERT_NE(EncodedHandshakeTP, nullptr);
    ASSERT_LE(EncodedTPLength - CxPlatTlsTPHeaderSize, TransportParametersLength);
    ASSERT_GT(sizeof(InputTicketBuffer), EncodedTPLength);

    CxPlatCopyMemory(
        &InputTicketBuffer[TicketBufferFixedV2HeaderLength],
        Alpn,
        sizeof(Alpn));

    CxPlatCopyMemory(
        &InputTicketBuffer[TicketBufferFixedV2HeaderLength + sizeof(Alpn)],
        EncodedHandshakeTP + CxPlatTlsTPHeaderSize,
        EncodedTPLength - CxPlatTlsTPHeaderSize);
    InputTicketBuffer[6] = (uint8_t)(EncodedTPLength - CxPlatTlsTPHeaderSize);

    ASSERT_GT(sizeof(InputTicketBuffer),(EncodedTPLength + sizeof(AppData)));

    CxPlatCopyMemory(
        &InputTicketBuffer[(TicketBufferFixedV2HeaderLength + sizeof(Alpn) + (EncodedTPLength - CxPlatTlsTPHeaderSize))],
        AppData,
        sizeof(AppData));

    //
    // Validate that the hand-crafted ticket is correct
    //
    TEST_QUIC_SUCCEEDED(
        QuicCryptoDecodeServerTicket(
            &Connection,
            (TicketBufferFixedV2HeaderLength + (uint16_t)sizeof(Alpn) + (uint16_t)(EncodedTPLength - CxPlatTlsTPHeaderSize) +
             (uint16_t)sizeof(AppData)),
            InputTicketBuffer,
            AlpnList,
            sizeof(AlpnList),
            &DecodedTP,
            NULL,
            &DecodedAppData,
            &DecodedAppDataLength));
    ASSERT_EQ(DecodedAppDataLength, sizeof(AppData));
    CompareTransportParameters(&HandshakeTP, &DecodedTP);

    //
    // Validate decoding of hand-crafted v1 ticket
    //
    InputTicketBuffer[0] = CXPLAT_TLS_RESUMPTION_TICKET_VERSION;

    //
    // Without modifying the buffer size, simply move the AppData length, Alpn, EncodedTP and AppData up the buffer and
    // pass in a smaller input buffer length here to match V1 tickets
    //
    CxPlatMoveMemory(
        &InputTicketBuffer[TicketBufferFixedV1HeaderLength - 1],
        &InputTicketBuffer[TicketBufferFixedV1HeaderLength],
        sizeof(InputTicketBuffer) - TicketBufferFixedV1HeaderLength);

    TEST_QUIC_SUCCEEDED(
        QuicCryptoDecodeServerTicket(
            &Connection,
            TicketBufferFixedV1HeaderLength + (uint16_t)sizeof(Alpn) + (uint16_t)(EncodedTPLength - CxPlatTlsTPHeaderSize) + (uint16_t)sizeof(AppData),
            InputTicketBuffer,
            AlpnList,
            sizeof(AlpnList),
            &DecodedTP,
            NULL,
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
            &Connection,
            0,
            InputTicketBuffer,
            AlpnList,
            sizeof(AlpnList),
            &DecodedTP,
            NULL,
            &DecodedAppData,
            &DecodedAppDataLength));

    // Not enough room for QUIC version
    ASSERT_EQ(
        QUIC_STATUS_INVALID_PARAMETER,
        QuicCryptoDecodeServerTicket(
            &Connection,
            4,
            InputTicketBuffer,
            AlpnList,
            sizeof(AlpnList),
            &DecodedTP,
            NULL,
            &DecodedAppData,
            &DecodedAppDataLength));

    // Not enough room for negotiated ALPN length
    ASSERT_EQ(
        QUIC_STATUS_INVALID_PARAMETER,
        QuicCryptoDecodeServerTicket(
            &Connection,
            5,
            InputTicketBuffer,
            AlpnList,
            sizeof(AlpnList),
            &DecodedTP,
            NULL,
            &DecodedAppData,
            &DecodedAppDataLength));

    // Not enough room for TP length
    ASSERT_EQ(
        QUIC_STATUS_INVALID_PARAMETER,
        QuicCryptoDecodeServerTicket(
            &Connection,
            6,
            InputTicketBuffer,
            AlpnList,
            sizeof(AlpnList),
            &DecodedTP,
            NULL,
            &DecodedAppData,
            &DecodedAppDataLength));

    // Not enough room for App Data length
    ASSERT_EQ(
        QUIC_STATUS_INVALID_PARAMETER,
        QuicCryptoDecodeServerTicket(
            &Connection,
            7,
            InputTicketBuffer,
            AlpnList,
            sizeof(AlpnList),
            &DecodedTP,
            NULL,
            &DecodedAppData,
            &DecodedAppDataLength));

    // Not enough room for negotiated ALPN length
    ASSERT_EQ(
        QUIC_STATUS_INVALID_PARAMETER,
        QuicCryptoDecodeServerTicket(
            &Connection,
            8,
            InputTicketBuffer,
            AlpnList,
            sizeof(AlpnList),
            &DecodedTP,
            NULL,
            &DecodedAppData,
            &DecodedAppDataLength));
    ASSERT_EQ(
        QUIC_STATUS_INVALID_PARAMETER,
        QuicCryptoDecodeServerTicket(
            &Connection,
            TicketBufferFixedV1HeaderLength + (uint16_t)(sizeof(Alpn) / 2),
            InputTicketBuffer,
            AlpnList,
            sizeof(AlpnList),
            &DecodedTP,
            NULL,
            &DecodedAppData,
            &DecodedAppDataLength));

    // Not enough room for handshake TP
    ASSERT_EQ(
        QUIC_STATUS_INVALID_PARAMETER,
        QuicCryptoDecodeServerTicket(
            &Connection,
            TicketBufferFixedV1HeaderLength + (uint16_t)sizeof(Alpn),
            InputTicketBuffer,
            AlpnList,
            sizeof(AlpnList),
            &DecodedTP,
            NULL,
            &DecodedAppData,
            &DecodedAppDataLength));
    ASSERT_EQ(
        QUIC_STATUS_INVALID_PARAMETER,
        QuicCryptoDecodeServerTicket(
            &Connection,
            TicketBufferFixedV1HeaderLength + (uint16_t)sizeof(Alpn) + (uint16_t)((EncodedTPLength - CxPlatTlsTPHeaderSize) / 2),
            InputTicketBuffer,
            AlpnList,
            sizeof(AlpnList),
            &DecodedTP,
            NULL,
            &DecodedAppData,
            &DecodedAppDataLength));
    ASSERT_EQ(
        QUIC_STATUS_INVALID_PARAMETER,
        QuicCryptoDecodeServerTicket(
            &Connection,
            TicketBufferFixedV1HeaderLength + (uint16_t)sizeof(Alpn) + (uint16_t)(EncodedTPLength - CxPlatTlsTPHeaderSize) - 1,
            InputTicketBuffer,
            AlpnList,
            sizeof(AlpnList),
            &DecodedTP,
            NULL,
            &DecodedAppData,
            &DecodedAppDataLength));

    // Not enough room for V2 extension
    ASSERT_EQ(
        QUIC_STATUS_INVALID_PARAMETER,
        QuicCryptoDecodeServerTicket(
            &Connection,
            TicketBufferFixedV1HeaderLength + (uint16_t)sizeof(Alpn) + (uint16_t)(EncodedTPLength - CxPlatTlsTPHeaderSize),
            InputTicketBuffer,
            AlpnList,
            sizeof(AlpnList),
            &DecodedTP,
            NULL,
            &DecodedAppData,
            &DecodedAppDataLength));
    ASSERT_EQ(
        QUIC_STATUS_INVALID_PARAMETER,
        QuicCryptoDecodeServerTicket(
            &Connection,
            (TicketBufferFixedV1HeaderLength + (uint16_t)sizeof(Alpn) + (uint16_t)(EncodedTPLength - CxPlatTlsTPHeaderSize -1)),
            InputTicketBuffer,
            AlpnList,
            sizeof(AlpnList),
            &DecodedTP,
            NULL,
            &DecodedAppData,
            &DecodedAppDataLength));

    // Not enough room for App Data
    ASSERT_EQ(
        QUIC_STATUS_INVALID_PARAMETER,
        QuicCryptoDecodeServerTicket(
            &Connection,
            (TicketBufferFixedV1HeaderLength + (uint16_t)sizeof(Alpn) + (uint16_t)(EncodedTPLength - CxPlatTlsTPHeaderSize)),
            InputTicketBuffer,
            AlpnList,
            sizeof(AlpnList),
            &DecodedTP,
            NULL,
            &DecodedAppData,
            &DecodedAppDataLength));
    ASSERT_EQ(
        QUIC_STATUS_INVALID_PARAMETER,
        QuicCryptoDecodeServerTicket(
            &Connection,
            (TicketBufferFixedV1HeaderLength + (uint16_t)sizeof(Alpn) + (uint16_t)(EncodedTPLength - CxPlatTlsTPHeaderSize) +
                (uint16_t)(sizeof(AppData) - 1)),
            InputTicketBuffer,
            AlpnList,
            sizeof(AlpnList),
            &DecodedTP,
            NULL,
            &DecodedAppData,
            &DecodedAppDataLength));

    //
    // Invalidate some of the fields of the ticket to ensure
    // decoding fails
    //

    const uint16_t ActualEncodedTicketLength =
        TicketBufferFixedV1HeaderLength + (uint16_t)sizeof(Alpn) + (uint16_t)(EncodedTPLength - CxPlatTlsTPHeaderSize) + (uint16_t)sizeof(AppData);

    const uint16_t ActualEncodedV2TicketLength = ActualEncodedTicketLength + (TicketBufferFixedV2HeaderLength - TicketBufferFixedV1HeaderLength);

    // Incorrect ticket version
    InputTicketBuffer[0] = CXPLAT_TLS_RESUMPTION_TICKET_MAX_VERSION + 1;
    ASSERT_EQ(
        QUIC_STATUS_INVALID_PARAMETER,
        QuicCryptoDecodeServerTicket(
            &Connection,
            ActualEncodedV2TicketLength,
            InputTicketBuffer,
            AlpnList,
            sizeof(AlpnList),
            &DecodedTP,
            NULL,
            &DecodedAppData,
            &DecodedAppDataLength));

    // Revert back to V1 ticket and test other error conditions
    InputTicketBuffer[0] = CXPLAT_TLS_RESUMPTION_TICKET_VERSION;

    // Unsupported QUIC version
    InputTicketBuffer[1] = 1;
    InputTicketBuffer[2] = 1;
    InputTicketBuffer[3] = 1;
    InputTicketBuffer[4] = 1;
    ASSERT_EQ(
        QUIC_STATUS_INVALID_PARAMETER,
        QuicCryptoDecodeServerTicket(
            &Connection,
            ActualEncodedTicketLength,
            InputTicketBuffer,
            AlpnList,
            sizeof(AlpnList),
            &DecodedTP,
            NULL,
            &DecodedAppData,
            &DecodedAppDataLength));

    // Unsupported QUIC version on connection
    Connection.Settings.VersionSettings = &VersionSettings;
    Connection.Settings.IsSet.VersionSettings = true;
    ASSERT_EQ(
        QUIC_STATUS_INVALID_PARAMETER,
        QuicCryptoDecodeServerTicket(
            &Connection,
            ActualEncodedTicketLength,
            InputTicketBuffer,
            AlpnList,
            sizeof(AlpnList),
            &DecodedTP,
            NULL,
            &DecodedAppData,
            &DecodedAppDataLength));
    InputTicketBuffer[1] = 0;
    InputTicketBuffer[2] = 0;
    InputTicketBuffer[3] = 0;
    InputTicketBuffer[4] = 1;
    Connection.Settings.VersionSettings = nullptr;
    Connection.Settings.IsSet.VersionSettings = false;

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
                &Connection,
                ActualEncodedTicketLength,
                InputTicketBuffer,
                AlpnList,
                sizeof(AlpnList),
                &DecodedTP,
                NULL,
                &DecodedAppData,
                &DecodedAppDataLength));
    }

    // Negotiated ALPN length longer than actual
    InputTicketBuffer[5] = (uint8_t)sizeof(Alpn) + 1;
    ASSERT_EQ(
        QUIC_STATUS_INVALID_PARAMETER,
        QuicCryptoDecodeServerTicket(
            &Connection,
            ActualEncodedTicketLength,
            InputTicketBuffer,
            AlpnList,
            sizeof(AlpnList),
            &DecodedTP,
            NULL,
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
                &Connection,
                ActualEncodedTicketLength,
                InputTicketBuffer,
                AlpnList,
                sizeof(AlpnList),
                &DecodedTP,
                NULL,
                &DecodedAppData,
                &DecodedAppDataLength));
    }
    InputTicketBuffer[5] = (uint8_t)sizeof(Alpn);

    // Handshake TP length shorter than actual
    for (uint8_t s = 0; s < (uint8_t)(EncodedTPLength - CxPlatTlsTPHeaderSize); ++s) {
        QuicTraceLogInfo(
            ServerResumptionTicketDecodeFailTpLengthShort,
            "[test] Attempting to decode Handshake TP with length %u (Actual: %u)",
            s,
            EncodedTPLength - CxPlatTlsTPHeaderSize);

        InputTicketBuffer[6] = s;
        ASSERT_EQ(
            QUIC_STATUS_INVALID_PARAMETER,
            QuicCryptoDecodeServerTicket(
                &Connection,
                ActualEncodedTicketLength,
                InputTicketBuffer,
                AlpnList,
                sizeof(AlpnList),
                &DecodedTP,
                NULL,
                &DecodedAppData,
                &DecodedAppDataLength));
    }

    // Handshake TP length longer than actual
    InputTicketBuffer[6] = (uint8_t)(EncodedTPLength - CxPlatTlsTPHeaderSize) + 1;
    ASSERT_EQ(
        QUIC_STATUS_INVALID_PARAMETER,
        QuicCryptoDecodeServerTicket(
            &Connection,
            ActualEncodedTicketLength,
            InputTicketBuffer,
            AlpnList,
            sizeof(AlpnList),
            &DecodedTP,
            NULL,
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
                &Connection,
                ActualEncodedTicketLength,
                InputTicketBuffer,
                AlpnList,
                sizeof(AlpnList),
                &DecodedTP,
                NULL,
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
                &Connection,
                ActualEncodedTicketLength,
                InputTicketBuffer,
                AlpnList,
                sizeof(AlpnList),
                &DecodedTP,
                NULL,
                &DecodedAppData,
                &DecodedAppDataLength));
    }

    // App Data length longer than actual
    InputTicketBuffer[7] = (uint8_t)sizeof(AppData) + 1;
        ASSERT_EQ(
            QUIC_STATUS_INVALID_PARAMETER,
            QuicCryptoDecodeServerTicket(
                &Connection,
                ActualEncodedTicketLength,
                InputTicketBuffer,
                AlpnList,
                sizeof(AlpnList),
                &DecodedTP,
                NULL,
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
                &Connection,
                ActualEncodedTicketLength,
                InputTicketBuffer,
                AlpnList,
                sizeof(AlpnList),
                &DecodedTP,
                NULL,
                &DecodedAppData,
                &DecodedAppDataLength));
    }
}

TEST(ResumptionTicketTest, ServerTicketDecodeFailureCasesWithCR)
{
    const uint8_t TransportParametersLength = 21; // Update if TP size changes
    const uint8_t AppData[] = {1,2,3,4,5};
    const uint8_t Alpn[] = {'t', 'e', 's', 't'};
    const uint8_t AlpnList[] = {4, 't', 'e', 's', 't'};
    QUIC_TRANSPORT_PARAMETERS HandshakeTP;
    QUIC_TRANSPORT_PARAMETERS DecodedTP;
    const uint8_t* DecodedAppData = nullptr;
    uint32_t DecodedAppDataLength = 0;

    QUIC_CONN_CAREFUL_RESUME_STATE CarefulResumeState = {};
    QUIC_CONN_CAREFUL_RESUME_STATE DecodedCarefulResumeState = {};

    // Populate CarefulResumeState with IPv4 address 172.16.0.1 (Class B)
    CxPlatZeroMemory(&CarefulResumeState.RemoteEndpoint, sizeof(CarefulResumeState.RemoteEndpoint));
    QuicAddrFromString("172.16.0.1", 0, &CarefulResumeState.RemoteEndpoint);
    CarefulResumeState.SmoothedRtt = 12345;
    CarefulResumeState.MinRtt = 2345;
    CarefulResumeState.Expiration = 0x1122334455667788;
    CarefulResumeState.Algorithm = QUIC_CONGESTION_CONTROL_ALGORITHM_CUBIC;
    CarefulResumeState.CongestionWindow = 65536;

    QUIC_CONNECTION Connection;
    CxPlatZeroMemory(&Connection, sizeof(Connection));
    Connection.Stats.QuicVersion = QUIC_VERSION_1;

    uint8_t* EncodedServerTicket = nullptr;
    uint32_t EncodedServerTicketLength = 0;

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

    // Encode a ticket with CarefulResumeState
    TEST_QUIC_SUCCEEDED(
        QuicCryptoEncodeServerTicket(
            &Connection,
            QUIC_VERSION_LATEST,
            sizeof(AppData),
            AppData,
            &HandshakeTP,
            &CarefulResumeState,
            sizeof(Alpn),
            Alpn,
            &EncodedServerTicket,
            &EncodedServerTicketLength));

    ASSERT_NE(EncodedServerTicket, nullptr);
    ASSERT_NE((uint16_t)EncodedServerTicketLength, 0);

    // Validate decode works with correct input
    TEST_QUIC_SUCCEEDED(
        QuicCryptoDecodeServerTicket(
            &Connection,
            (uint16_t)EncodedServerTicketLength,
            EncodedServerTicket,
            AlpnList,
            sizeof(AlpnList),
            &DecodedTP,
            &DecodedCarefulResumeState,
            &DecodedAppData,
            &DecodedAppDataLength));
    ASSERT_EQ(DecodedAppDataLength, sizeof(AppData));
    ASSERT_NE(DecodedAppData, nullptr);
    ASSERT_TRUE(memcmp(AppData, DecodedAppData, sizeof(AppData)) == 0);
    CompareTransportParameters(&HandshakeTP, &DecodedTP);
    // Validate CarefulResumeState fields (except port)
    ASSERT_EQ(CarefulResumeState.SmoothedRtt, DecodedCarefulResumeState.SmoothedRtt);
    ASSERT_EQ(CarefulResumeState.MinRtt, DecodedCarefulResumeState.MinRtt);
    ASSERT_EQ(CarefulResumeState.Expiration, DecodedCarefulResumeState.Expiration);
    ASSERT_EQ(CarefulResumeState.Algorithm, DecodedCarefulResumeState.Algorithm);
    ASSERT_EQ(CarefulResumeState.CongestionWindow, DecodedCarefulResumeState.CongestionWindow);
    ASSERT_EQ(QuicAddrGetFamily(&CarefulResumeState.RemoteEndpoint),
                QuicAddrGetFamily(&DecodedCarefulResumeState.RemoteEndpoint));
    ASSERT_TRUE(QuicAddrCompareIp(&CarefulResumeState.RemoteEndpoint,
                                    &DecodedCarefulResumeState.RemoteEndpoint));

    // Now test decode failure cases by corrupting the encoded ticket
    // 1. Corrupt the version
    EncodedServerTicket[0] = EncodedServerTicket[0] + 1;
    ASSERT_EQ(
        QUIC_STATUS_INVALID_PARAMETER,
        QuicCryptoDecodeServerTicket(
            &Connection,
            (uint16_t)EncodedServerTicketLength,
            EncodedServerTicket,
            AlpnList,
            sizeof(AlpnList),
            &DecodedTP,
            &DecodedCarefulResumeState,
            &DecodedAppData,
            &DecodedAppDataLength));
    EncodedServerTicket[0] = EncodedServerTicket[0] - 1;

    // 2. Corrupt the ALPN length (set to too large)
    uint8_t savedAlpnLen = EncodedServerTicket[5];
    EncodedServerTicket[5] = (uint8_t)(sizeof(Alpn) + 1);
    ASSERT_EQ(
        QUIC_STATUS_INVALID_PARAMETER,
        QuicCryptoDecodeServerTicket(
            &Connection,
            (uint16_t)EncodedServerTicketLength,
            EncodedServerTicket,
            AlpnList,
            sizeof(AlpnList),
            &DecodedTP,
            &DecodedCarefulResumeState,
            &DecodedAppData,
            &DecodedAppDataLength));
    EncodedServerTicket[5] = savedAlpnLen;

    // 3. Corrupt the TP length (set to too large)
    uint8_t savedTpLen = EncodedServerTicket[6];
    EncodedServerTicket[6] = (uint8_t)(TransportParametersLength + 1);
    ASSERT_EQ(
        QUIC_STATUS_INVALID_PARAMETER,
        QuicCryptoDecodeServerTicket(
            &Connection,
            (uint16_t)EncodedServerTicketLength,
            EncodedServerTicket,
            AlpnList,
            sizeof(AlpnList),
            &DecodedTP,
            &DecodedCarefulResumeState,
            &DecodedAppData,
            &DecodedAppDataLength));
    EncodedServerTicket[6] = savedTpLen;

    // 4. Corrupt the CR length (set to too large)
    uint8_t savedCrLen = EncodedServerTicket[7];
    EncodedServerTicket[7] = 0xFF;
    ASSERT_EQ(
        QUIC_STATUS_INVALID_PARAMETER,
        QuicCryptoDecodeServerTicket(
            &Connection,
            (uint16_t)EncodedServerTicketLength,
            EncodedServerTicket,
            AlpnList,
            sizeof(AlpnList),
            &DecodedTP,
            &DecodedCarefulResumeState,
            &DecodedAppData,
            &DecodedAppDataLength));
    EncodedServerTicket[7] = savedCrLen;

    // 5. Corrupt the AppData length (set to too large)
    uint8_t savedAppDataLen = EncodedServerTicket[8];
    EncodedServerTicket[8] = (uint8_t)(sizeof(AppData) + 1);
    ASSERT_EQ(
        QUIC_STATUS_INVALID_PARAMETER,
        QuicCryptoDecodeServerTicket(
            &Connection,
            (uint16_t)EncodedServerTicketLength,
            EncodedServerTicket,
            AlpnList,
            sizeof(AlpnList),
            &DecodedTP,
            &DecodedCarefulResumeState,
            &DecodedAppData,
            &DecodedAppDataLength));
    EncodedServerTicket[8] = savedAppDataLen;

    CXPLAT_FREE(EncodedServerTicket, QUIC_POOL_SERVER_CRYPTO_TICKET);
}

TEST(ResumptionTicketTest, ClientServerEndToEnd)
{
    uint8_t AppData[] = {10, 9, 8, 7, 6, 5, 4, 3, 2, 1};
    QUIC_TRANSPORT_PARAMETERS ServerTP, ClientTP, DecodedClientTP, DecodedServerTP;
    uint8_t NegotiatedAlpn[] = {4, 't', 'e', 's', 't'};
    uint8_t* EncodedServerTicket = nullptr, *DecodedServerTicket = nullptr;
    uint32_t EncodedServerTicketLength = 0, EncodedClientTicketLength = 0, DecodedServerTicketLength = 0, DecodedAppDataLength = 0, DecodedQuicVersion = 0;
    const uint8_t* EncodedClientTicket = nullptr, *DecodedAppData = nullptr;

    QUIC_CONNECTION Connection;
    CxPlatZeroMemory(&Connection, sizeof(Connection));
    Connection.Stats.QuicVersion = QUIC_VERSION_1;

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
            NULL,
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
            &Connection,
            (uint16_t)EncodedServerTicketLength,
            EncodedServerTicket,
            NegotiatedAlpn,
            sizeof(NegotiatedAlpn),
            &DecodedServerTP,
            NULL,
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

//
// Declarations for test purposes
//

extern "C" {

BOOLEAN
IsQuicIncomingResumptionTicketSupported(
    _In_ QUIC_VAR_INT TicketVersion
);

_IRQL_requires_max_(DISPATCH_LEVEL)
void
QuicCryptoEncodeAddr(
    _Out_writes_bytes_(_Inexpressible_("Too Dynamic")) uint8_t* Buffer,
    _Out_range_(<= , QUIC_CR_STATE_MAX_ADDR_LENGTH) uint16_t* AddrLength,
    _In_ const QUIC_ADDR* Addr
);

_IRQL_requires_max_(DISPATCH_LEVEL)
BOOLEAN
QuicCryptoDecodeAddr(
    _In_reads_bytes_(BufferLength) const uint8_t* Buffer,
    _In_ uint16_t BufferLength,
    _In_opt_ QUIC_CONNECTION* Connection,
    _Out_ QUIC_ADDR* Addr
);

_IRQL_requires_max_(DISPATCH_LEVEL)
uint32_t
QuicCryptoGetEncodeCRStateSize(
    _In_  const QUIC_CONN_CAREFUL_RESUME_STATE* CarefulResumeState
);

void
QuicCryptoEncodeCRState(
    _In_ uint32_t BufferLength,
    _In_ const QUIC_CONN_CAREFUL_RESUME_STATE* CarefulResumeState,
    _In_opt_ QUIC_CONNECTION* Connection,
    _Out_ uint32_t* CRLength,
    _Out_writes_bytes_to_(BufferLength, *CRLength) uint8_t* Buffer
);

_IRQL_requires_max_(DISPATCH_LEVEL)
_Success_(return != FALSE)
BOOLEAN
QuicCryptoDecodeCRState(
    _Out_  QUIC_CONN_CAREFUL_RESUME_STATE * CarefulResumeState,
    _In_reads_(CRBufLength) const uint8_t * Buffer,
    _In_ uint16_t CRBufLength,
    _In_opt_ QUIC_CONNECTION * Connection
);

_IRQL_requires_max_(DISPATCH_LEVEL)
size_t
QUIC_CR_STATE_ENCODED_MIN_LENGTH();

}

#define QUIC_CR_STATE_MIN_ADDR_LENGTH \
    (QuicVarIntSize(QUIC_ADDRESS_FAMILY_INET) + sizeof(IN_ADDR))

#define QUIC_CR_STATE_MAX_ADDR_LENGTH \
    (QuicVarIntSize(QUIC_ADDRESS_FAMILY_INET6) + sizeof(IN6_ADDR))

TEST(ResumptionTicketTest, IsQuicIncomingResumptionTicketSupported)
{
    //
    // Supported range: [CXPLAT_TLS_RESUMPTION_TICKET_VERSION, CXPLAT_TLS_RESUMPTION_TICKET_MAX_VERSION]
    //
    EXPECT_TRUE(IsQuicIncomingResumptionTicketSupported(CXPLAT_TLS_RESUMPTION_TICKET_VERSION));
    EXPECT_TRUE(IsQuicIncomingResumptionTicketSupported(CXPLAT_TLS_RESUMPTION_TICKET_MAX_VERSION));

    //
    // Below supported range
    //
    EXPECT_FALSE(IsQuicIncomingResumptionTicketSupported(
        CXPLAT_TLS_RESUMPTION_TICKET_VERSION - 1));

    //
    // Above supported range
    //
    EXPECT_FALSE(IsQuicIncomingResumptionTicketSupported(
        CXPLAT_TLS_RESUMPTION_TICKET_MAX_VERSION + 1));
}

TEST(ResumptionTicketTest, QuicCryptoEncodeAddr)
{
    //
    // IPv4 test
    //
    QUIC_ADDR addr4;
    CxPlatZeroMemory(&addr4, sizeof(addr4));
    QuicAddrFromString("192.0.2.123", 0, &addr4);

    uint8_t buffer4[32] = {0};
    uint16_t addrLen4 = 0;
    QuicCryptoEncodeAddr(buffer4, &addrLen4, &addr4);

    //
    // Should encode to at least the minimum length
    //
    ASSERT_GE(addrLen4, QUIC_CR_STATE_MIN_ADDR_LENGTH);

    QUIC_ADDR decoded4;
    ASSERT_TRUE(QuicCryptoDecodeAddr(buffer4, addrLen4, nullptr, &decoded4));
    ASSERT_TRUE(QuicAddrCompareIp(&addr4, &decoded4));
    ASSERT_EQ(addr4.Ipv4.sin_family, decoded4.Ipv4.sin_family);
    ASSERT_EQ(addr4.Ipv4.sin_addr.s_addr, decoded4.Ipv4.sin_addr.s_addr);

    //
    // IPv6 test
    //
    QUIC_ADDR addr6;
    CxPlatZeroMemory(&addr6, sizeof(addr6));
    QuicAddrFromString("2001:db8::abcd", 0, &addr6);

    uint8_t buffer6[64] = {0};
    uint16_t addrLen6 = 0;
    QuicCryptoEncodeAddr(buffer6, &addrLen6, &addr6);

    //
    // Should encode to at least the maximum length for IPv6
    //
    ASSERT_GE(addrLen6, QUIC_CR_STATE_MAX_ADDR_LENGTH - 8); // allow for varint size

    QUIC_ADDR decoded6;
    ASSERT_TRUE(QuicCryptoDecodeAddr(buffer6, addrLen6, nullptr, &decoded6));
    ASSERT_TRUE(QuicAddrCompareIp(&addr6, &decoded6));
    ASSERT_EQ(addr6.Ipv6.sin6_family, decoded6.Ipv6.sin6_family);
    ASSERT_EQ(0, memcmp(&addr6.Ipv6.sin6_addr, &decoded6.Ipv6.sin6_addr, sizeof(addr6.Ipv6.sin6_addr)));
}

TEST(ResumptionTicketTest, QuicCryptoDecodeAddrFailureCases)
{
    uint8_t buffer[64] = { 0 };
    uint16_t addrLen = 0;
    QUIC_ADDR decodedAddr;

    //
    // Test with null address
    //
    ASSERT_FALSE(QuicCryptoDecodeAddr(buffer, addrLen, nullptr, &decodedAddr));

    //
    // Test with zero length
    //
    ASSERT_FALSE(QuicCryptoDecodeAddr(buffer, 0, nullptr, &decodedAddr));

    //
    // Test with insufficient buffer length (IPv4/IPv6)
    //
    ASSERT_FALSE(QuicCryptoDecodeAddr(buffer, 1, nullptr, &decodedAddr));

    //
    // Test with invalid IPv4 data
    //
    buffer[0] = 0x01; // Invalid family
    addrLen = 4; // Length for IPv4
    ASSERT_FALSE(QuicCryptoDecodeAddr(buffer, addrLen, nullptr, &decodedAddr));

    //
    // Test with invalid IPv6 data
    //
    buffer[0] = AF_INET6; // Valid family
    addrLen = 16; // Length for IPv6
    memset(buffer + 1, 0xFF, 15); // Invalid address
    ASSERT_FALSE(QuicCryptoDecodeAddr(buffer, addrLen, nullptr, &decodedAddr));

    //
    // Test with IPv6 data but IPv4 length
    //
    buffer[0] = AF_INET6; // Valid family
    addrLen = QUIC_CR_STATE_MIN_ADDR_LENGTH; // Correct length for IPv4, but not IPv6
    memset(buffer + 1, 0, sizeof(IN6_ADDR));
    ASSERT_FALSE(QuicCryptoDecodeAddr(buffer, addrLen, nullptr, &decodedAddr));
}

TEST(ResumptionTicketTest, QuicCryptoDecodeCRStateFailureCases)
{
    QUIC_CONN_CAREFUL_RESUME_STATE crState = {};
    uint8_t buffer[0x11] = {};
    QUIC_ADDR addr;
    CxPlatZeroMemory(&addr, sizeof(addr));
    QuicAddrFromString("192.0.2.1", 0, &addr);

    //
    // Prepare a valid encoded CRState for reference
    //
    QUIC_CONN_CAREFUL_RESUME_STATE validState = {};
    validState.RemoteEndpoint = addr;
    validState.SmoothedRtt = 1000;
    validState.MinRtt = 500;
    validState.Expiration = 123456789;
    validState.Algorithm = QUIC_CONGESTION_CONTROL_ALGORITHM_CUBIC;
    validState.CongestionWindow = 10000;
    uint32_t requiredSize = QuicCryptoGetEncodeCRStateSize(&validState);
    uint32_t crLength = requiredSize;

    QuicCryptoEncodeCRState(
        requiredSize,
        &validState,
        nullptr,
        &crLength,
        buffer);
    ASSERT_EQ(crLength, requiredSize);
    ASSERT_EQ(crLength, sizeof(buffer));

    //
    // 1. Buffer too small (less than minimum length)
    //
    ASSERT_FALSE(QuicCryptoDecodeCRState(&crState, buffer, 0, nullptr));
    ASSERT_FALSE(QuicCryptoDecodeCRState(&crState, buffer, (uint16_t)(QUIC_CR_STATE_ENCODED_MIN_LENGTH() - 1), nullptr));

    //
    // 2. Invalid address length (set AddrLen to 0)
    //
    uint8_t corruptBuf[0x12];
    ASSERT_EQ(sizeof(corruptBuf), sizeof(buffer) + 1);

    memcpy(corruptBuf, buffer, crLength);
    corruptBuf[0] = 0; // AddrLen varint = 0
    ASSERT_FALSE(QuicCryptoDecodeCRState(&crState, corruptBuf, (uint16_t)crLength, nullptr));

    //
    // 3. AddrLen too large
    //
    memcpy(corruptBuf, buffer, crLength);
    corruptBuf[0] = (uint8_t)(QUIC_CR_STATE_MAX_ADDR_LENGTH + 1);
    ASSERT_FALSE(QuicCryptoDecodeCRState(&crState, corruptBuf, (uint16_t)crLength, nullptr));

    //
    // 4. Corrupt RTT values (make SmoothedRtt varint incomplete)
    // Set AddrLen to valid, but truncate buffer so SmoothedRtt can't be decoded
    //
    memcpy(corruptBuf, buffer, crLength);
    ASSERT_FALSE(QuicCryptoDecodeCRState(&crState, corruptBuf, 1, nullptr));

    //
    // 5. Corrupt address (invalid family)
    //
    memcpy(corruptBuf, buffer, crLength);
    uint16_t offset = 0;
    QUIC_VAR_INT addrLen = 0;
    QUIC_VAR_INT temp = 0;
    ASSERT_TRUE(QuicVarIntDecode((uint16_t)crLength, corruptBuf, &offset, &addrLen)); // Offset of address length
    ASSERT_TRUE(QuicVarIntDecode((uint16_t)crLength, corruptBuf, &offset, &temp)); // Offset of smoothedRTT
    ASSERT_TRUE(QuicVarIntDecode((uint16_t)crLength, corruptBuf, &offset, &temp)); // Offset of minRtt
    corruptBuf[offset] = 0xFF; // Invalid family
    ASSERT_FALSE(QuicCryptoDecodeCRState(&crState, corruptBuf, (uint16_t)crLength, nullptr));

    //
    // 6. Corrupt Expiration (truncate buffer so Expiration can't be decoded)
    //
    memcpy(corruptBuf, buffer, crLength);
    ASSERT_FALSE(QuicCryptoDecodeCRState(&crState, corruptBuf, (uint16_t)(crLength - 2), nullptr));

    //
    // 7. Corrupt Algorithm (set to invalid value)
    //
    memcpy(corruptBuf, buffer, crLength);
    offset = 0;
    ASSERT_TRUE(QuicVarIntDecode((uint16_t)crLength, corruptBuf, &offset, &addrLen)); // AddrLen
    ASSERT_TRUE(QuicVarIntDecode((uint16_t)crLength, corruptBuf, &offset, &temp)); // SmoothedRtt
    ASSERT_TRUE(QuicVarIntDecode((uint16_t)crLength, corruptBuf, &offset, &temp)); // MinRtt
    offset += (uint16_t)addrLen; // skip address
    ASSERT_TRUE(QuicVarIntDecode((uint16_t)crLength, corruptBuf, &offset, &temp)); // Expiration
    corruptBuf[offset] = (uint8_t)QUIC_CONGESTION_CONTROL_ALGORITHM_MAX; // Set algorithm to invalid
    ASSERT_FALSE(QuicCryptoDecodeCRState(&crState, corruptBuf, (uint16_t)crLength, nullptr));

    //
    // 8. Corrupt CongestionWindow (truncate buffer so CongestionWindow can't be decoded)
    //
    memcpy(corruptBuf, buffer, crLength);
    ASSERT_FALSE(QuicCryptoDecodeCRState(&crState, corruptBuf, (uint16_t)(crLength - 1), nullptr));

    //
    // 9. Buffer length mismatch (extra bytes at end)
    //
    memcpy(corruptBuf, buffer, crLength);
    corruptBuf[crLength] = 0xAA;
    ASSERT_FALSE(QuicCryptoDecodeCRState(&crState, corruptBuf, (uint16_t)(crLength + 1), nullptr));

    //
    // 10. Invalid address length for IPv4
    //
    memcpy(corruptBuf, buffer, crLength);
    corruptBuf[0] = (uint8_t)(QUIC_CR_STATE_MAX_ADDR_LENGTH); // Use the IPv6 length for IPv4
    ASSERT_FALSE(QuicCryptoDecodeCRState(&crState, corruptBuf, (uint16_t)crLength, nullptr));

    //
    // 11. Ensure correct decoding of a valid state
    //

    QUIC_CONN_CAREFUL_RESUME_STATE decodedState = {};
    ASSERT_TRUE(QuicCryptoDecodeCRState(&decodedState, buffer, (uint16_t)crLength, nullptr));

    //
    // Compare the decoded values to original values
    //
    ASSERT_EQ(decodedState.SmoothedRtt, validState.SmoothedRtt);
    ASSERT_EQ(decodedState.MinRtt, validState.MinRtt);
    ASSERT_EQ(decodedState.Expiration, validState.Expiration);
    ASSERT_TRUE(QuicAddrCompareIp(&decodedState.RemoteEndpoint, &validState.RemoteEndpoint));
    ASSERT_EQ(decodedState.Algorithm, validState.Algorithm);
    ASSERT_EQ(decodedState.CongestionWindow, validState.CongestionWindow);

    //
    // 12. Invalid address length for IPv6
    //
    QUIC_ADDR addr6;
    QuicAddrFromString("2001:db8::1", 0, &addr6);
    validState.RemoteEndpoint = addr6;
    uint32_t requiredSize2 = QuicCryptoGetEncodeCRStateSize(&validState);
    uint8_t buffer2[0x1D] = {};
    uint8_t corruptBuf2[0x1D] = {};
    uint32_t crLength2 = requiredSize2;

    ASSERT_EQ(sizeof(buffer2), crLength2);
    ASSERT_EQ(sizeof(corruptBuf2), crLength2);

    //
    // Encode a valid state with IPv6 address
    //
    QuicCryptoEncodeCRState(
        requiredSize2,
        &validState,
        nullptr,
        &crLength2,
        buffer2);
    ASSERT_EQ(crLength2, requiredSize2);

    ASSERT_TRUE(QuicCryptoDecodeCRState(&decodedState, buffer2, (uint16_t)crLength2, nullptr));

    memcpy(corruptBuf2, buffer2, crLength2);
    corruptBuf2[0] = (uint8_t)(QUIC_CR_STATE_MIN_ADDR_LENGTH); // Use the IPv4 length for IPv6
    ASSERT_FALSE(QuicCryptoDecodeCRState(&crState, corruptBuf2, (uint16_t)crLength2, nullptr));
}
