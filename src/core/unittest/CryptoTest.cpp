/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.

Abstract:

    Unit tests for CRYPTO frame receive handling.

--*/

#include "main.h"
#ifdef QUIC_CLOG
#include "CryptoTest.cpp.clog.h"
#endif

#define INITIAL_FLIGHT_LENGTH 64u

class CryptoTest : public ::testing::Test {
protected:
    QUIC_CONNECTION Connection{};
    QUIC_PACKET_KEY DummyKey{};
    uint8_t Data[INITIAL_FLIGHT_LENGTH]{};

    void SetUp() override
    {
        QUIC_CRYPTO* Crypto = &Connection.Crypto;
        TEST_QUIC_SUCCEEDED(
            QuicRecvBufferInitialize(
                &Crypto->RecvBuffer,
                QUIC_DEFAULT_STREAM_FC_WINDOW_SIZE / 2,
                QUIC_DEFAULT_STREAM_FC_WINDOW_SIZE / 2,
                QUIC_RECV_BUF_MODE_SINGLE,
                NULL));
        Crypto->Initialized = TRUE;

        //
        // Simulate the peer's Initial flight being received and fully
        // consumed by TLS, which then moved the read key to Handshake.
        //
        uint64_t Quota = 0;
        BOOLEAN Ready = FALSE;
        uint64_t SizeNeeded = 0;
        TEST_QUIC_SUCCEEDED(
            QuicRecvBufferWrite(
                &Crypto->RecvBuffer, 0, INITIAL_FLIGHT_LENGTH, Data, UINT16_MAX,
                &Quota, &Ready, &SizeNeeded));
        ASSERT_TRUE(Ready);

        uint64_t ReadOffset = 0;
        QUIC_BUFFER Buffer;
        uint32_t BufferCount = 1;
        QuicRecvBufferRead(&Crypto->RecvBuffer, &ReadOffset, &BufferCount, &Buffer);
        ASSERT_EQ(INITIAL_FLIGHT_LENGTH, Buffer.Length);
        QuicRecvBufferDrain(&Crypto->RecvBuffer, INITIAL_FLIGHT_LENGTH);

        Crypto->RecvTotalConsumed = INITIAL_FLIGHT_LENGTH;
        Crypto->RecvEncryptLevelStartOffset = INITIAL_FLIGHT_LENGTH;
        Crypto->TlsState.ReadKey = QUIC_PACKET_KEY_HANDSHAKE;
        Crypto->TlsState.ReadKeys[QUIC_PACKET_KEY_INITIAL] = &DummyKey;
        Crypto->TlsState.ReadKeys[QUIC_PACKET_KEY_HANDSHAKE] = &DummyKey;
    }

    void TearDown() override
    {
        QuicRecvBufferUninitialize(&Connection.Crypto.RecvBuffer);
    }
};

TEST_F(CryptoTest, OldLevelRetransmissionAccepted)
{
    QUIC_CRYPTO_EX Frame{0, INITIAL_FLIGHT_LENGTH, Data};
    TEST_QUIC_SUCCEEDED(
        QuicCryptoProcessFrame(
            &Connection.Crypto, QUIC_PACKET_KEY_INITIAL, &Frame));
    ASSERT_EQ(
        (uint64_t)INITIAL_FLIGHT_LENGTH,
        QuicRecvBufferGetTotalLength(&Connection.Crypto.RecvBuffer));
}

TEST_F(CryptoTest, OldLevelDataPastLevelEndIgnored)
{
    //
    // Initial-level data starting beyond the end of the Initial flight must
    // not land in the Handshake level's part of the receive buffer.
    //
    QUIC_CRYPTO_EX Frame{INITIAL_FLIGHT_LENGTH + 16, 8, Data};
    TEST_QUIC_SUCCEEDED(
        QuicCryptoProcessFrame(
            &Connection.Crypto, QUIC_PACKET_KEY_INITIAL, &Frame));
    ASSERT_EQ(
        (uint64_t)INITIAL_FLIGHT_LENGTH,
        QuicRecvBufferGetTotalLength(&Connection.Crypto.RecvBuffer));
}
