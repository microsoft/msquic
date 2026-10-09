/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.

--*/

#include "main.h"
#include "../tls_openssl_record.h"

//
// Verifies that incomplete TLS handshake headers are not returned, consumed,
// or marked outstanding.
//
TEST(TlsOpenSslCallbackTest, RejectsIncompleteHeaders)
{
    const uint8_t Header[] = {1, 0, 0, 4};
    for (size_t HeaderLength = 0; HeaderLength < sizeof(Header); ++HeaderLength) {
        QUIC_TLS_RECORD_STATE State = {
            HeaderLength == 0 ? nullptr : Header,
            HeaderLength,
            0,
            0
        };
        const unsigned char* Record = Header;
        size_t RecordLength = sizeof(Header);

        QuicTlsReceiveRecordInner(&State, &Record, &RecordLength);
        EXPECT_EQ(nullptr, Record);
        EXPECT_EQ(0u, RecordLength);
        EXPECT_EQ(HeaderLength == 0 ? nullptr : Header, State.InputBuffer);
        EXPECT_EQ(HeaderLength, State.InputLength);
        EXPECT_EQ(0u, State.InputOffset);
        EXPECT_EQ(0u, State.OutstandingLength);
    }
}

//
// Verifies that a TLS handshake message with an incomplete payload is not
// returned, consumed, or marked outstanding.
//
TEST(TlsOpenSslCallbackTest, RejectsIncompletePayload)
{
    const uint8_t IncompletePayload[] = {1, 0, 0, 4, 1, 2, 3};
    QUIC_TLS_RECORD_STATE State = {
        IncompletePayload,
        sizeof(IncompletePayload),
        0,
        0
    };
    const unsigned char* Record = IncompletePayload;
    size_t RecordLength = sizeof(IncompletePayload);

    QuicTlsReceiveRecordInner(&State, &Record, &RecordLength);
    EXPECT_EQ(nullptr, Record);
    EXPECT_EQ(0u, RecordLength);
    EXPECT_EQ(IncompletePayload, State.InputBuffer);
    EXPECT_EQ(sizeof(IncompletePayload), State.InputLength);
    EXPECT_EQ(0u, State.InputOffset);
    EXPECT_EQ(0u, State.OutstandingLength);
}

//
// Verifies that the maximum uint24 payload length is parsed without overflow
// and rejected when its payload is incomplete.
//
TEST(TlsOpenSslCallbackTest, RejectsIncompleteMaximumLengthPayload)
{
    const uint8_t MaximumLengthHeader[] = {1, 0xff, 0xff, 0xff};
    QUIC_TLS_RECORD_STATE State = {
        MaximumLengthHeader,
        sizeof(MaximumLengthHeader),
        0,
        0
    };
    const unsigned char* Record = MaximumLengthHeader;
    size_t RecordLength = sizeof(MaximumLengthHeader);

    QuicTlsReceiveRecordInner(&State, &Record, &RecordLength);
    EXPECT_EQ(nullptr, Record);
    EXPECT_EQ(0u, RecordLength);
    EXPECT_EQ(MaximumLengthHeader, State.InputBuffer);
    EXPECT_EQ(sizeof(MaximumLengthHeader), State.InputLength);
    EXPECT_EQ(0u, State.InputOffset);
    EXPECT_EQ(0u, State.OutstandingLength);
}

//
// Verifies that the 24-bit TLS handshake payload length is parsed in big-endian
// order and that the complete message is borrowed without being consumed.
//
TEST(TlsOpenSslCallbackTest, ParsesUint24MessageLength)
{
    uint8_t Input[260] = {0};
    Input[0] = 1;
    Input[2] = 1;
    QUIC_TLS_RECORD_STATE State = {
        Input,
        sizeof(Input),
        0,
        0
    };
    const unsigned char* Record = nullptr;
    size_t RecordLength = 0;

    QuicTlsReceiveRecordInner(&State, &Record, &RecordLength);
    EXPECT_EQ(Input, Record);
    EXPECT_EQ(sizeof(Input), RecordLength);
    EXPECT_EQ(Input, State.InputBuffer);
    EXPECT_EQ(sizeof(Input), State.InputLength);
    EXPECT_EQ(0u, State.InputOffset);
    EXPECT_EQ(sizeof(Input), State.OutstandingLength);
}

//
// Verifies that consecutive TLS handshake messages are borrowed and released
// one at a time while an incomplete trailing message remains unconsumed.
//
TEST(TlsOpenSslCallbackTest, ProcessesMultipleMessages)
{
    const uint8_t Input[] = {
        1, 0, 0, 4, 10, 11, 12, 13,
        2, 0, 0, 1, 20,
        3, 0, 0
    };
    QUIC_TLS_RECORD_STATE State = {
        Input,
        sizeof(Input),
        0,
        0
    };
    const unsigned char* Record = nullptr;
    size_t RecordLength = 0;

    QuicTlsReceiveRecordInner(&State, &Record, &RecordLength);
    EXPECT_EQ(Input, Record);
    EXPECT_EQ(8u, RecordLength);
    EXPECT_EQ(0u, State.InputOffset);
    EXPECT_EQ(8u, State.OutstandingLength);

    ASSERT_EQ(1, QuicTlsReleaseRecordInner(&State, RecordLength));
    EXPECT_EQ(8u, State.InputOffset);
    EXPECT_EQ(0u, State.OutstandingLength);

    QuicTlsReceiveRecordInner(&State, &Record, &RecordLength);
    EXPECT_EQ(Input + 8, Record);
    EXPECT_EQ(5u, RecordLength);
    EXPECT_EQ(5u, State.OutstandingLength);
    ASSERT_EQ(1, QuicTlsReleaseRecordInner(&State, RecordLength));
    EXPECT_EQ(13u, State.InputOffset);
    EXPECT_EQ(0u, State.OutstandingLength);

    QuicTlsReceiveRecordInner(&State, &Record, &RecordLength);
    EXPECT_EQ(nullptr, Record);
    EXPECT_EQ(0u, RecordLength);
    EXPECT_EQ(13u, State.InputOffset);
    EXPECT_EQ(0u, State.OutstandingLength);
}

//
// Verifies that releasing more bytes than are currently borrowed fails without
// changing the receive offset or outstanding-length accounting.
//
TEST(TlsOpenSslCallbackTest, RejectsOverRelease)
{
    const uint8_t Input[] = {1, 0, 0, 0};
    QUIC_TLS_RECORD_STATE State = {
        Input,
        sizeof(Input),
        0,
        0
    };
    const unsigned char* Record = nullptr;
    size_t RecordLength = 0;

    QuicTlsReceiveRecordInner(&State, &Record, &RecordLength);
    ASSERT_EQ(0, QuicTlsReleaseRecordInner(&State, RecordLength + 1));
    EXPECT_EQ(0u, State.InputOffset);
    EXPECT_EQ(sizeof(Input), State.OutstandingLength);

    ASSERT_EQ(1, QuicTlsReleaseRecordInner(&State, RecordLength));
    EXPECT_EQ(sizeof(Input), State.InputOffset);
    EXPECT_EQ(0u, State.OutstandingLength);
}
