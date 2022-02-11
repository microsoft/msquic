/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.

--*/

#pragma once

#include "precomp.h"

#undef min // gtest headers conflict with previous definitions of min/max.
#undef max
#include "gtest/gtest.h"

#define TEST_QUIC_SUCCEEDED(__condition) ASSERT_FALSE(QUIC_FAILED(__condition))

#define COMPARE_TP_FIELD(TpName, Field) \
    if (A->Flags & QUIC_TP_FLAG_##TpName) { ASSERT_EQ(A->Field, B->Field); }

inline
std::ostream& operator << (std::ostream& o, const QUIC_FRAME_TYPE& type) {
    switch (type) {
        case QUIC_FRAME_PADDING:
            return o << "QUIC_FRAME_PADDING";
        case QUIC_FRAME_PING:
            return o << "QUIC_FRAME_PING";
        case QUIC_FRAME_ACK:
            return o << "QUIC_FRAME_ACK";
        case QUIC_FRAME_ACK_1:
            return o << "QUIC_FRAME_ACK_1";
        case QUIC_FRAME_RESET_STREAM:
            return o << "QUIC_FRAME_RESET_STREAM";
        case QUIC_FRAME_STOP_SENDING:
            return o << "QUIC_FRAME_STOP_SENDING";
        case QUIC_FRAME_CRYPTO:
            return o << "QUIC_FRAME_CRYPTO";
        case QUIC_FRAME_NEW_TOKEN:
            return o << "QUIC_FRAME_NEW_TOKEN";
        case QUIC_FRAME_STREAM:
            return o << "QUIC_FRAME_STREAM";
        case QUIC_FRAME_STREAM_1:
            return o << "QUIC_FRAME_STREAM_1";
        case QUIC_FRAME_STREAM_2:
            return o << "QUIC_FRAME_STREAM_2";
        case QUIC_FRAME_STREAM_3:
            return o << "QUIC_FRAME_STREAM_3";
        case QUIC_FRAME_STREAM_4:
            return o << "QUIC_FRAME_STREAM_4";
        case QUIC_FRAME_STREAM_5:
            return o << "QUIC_FRAME_STREAM_5";
        case QUIC_FRAME_STREAM_6:
            return o << "QUIC_FRAME_STREAM_6";
        case QUIC_FRAME_STREAM_7:
            return o << "QUIC_FRAME_STREAM_7";
        case QUIC_FRAME_MAX_DATA:
            return o << "QUIC_FRAME_MAX_DATA";
        case QUIC_FRAME_MAX_STREAM_DATA:
            return o << "QUIC_FRAME_MAX_STREAM_DATA";
        case QUIC_FRAME_MAX_STREAMS:
            return o << "QUIC_FRAME_MAX_STREAMS";
        case QUIC_FRAME_MAX_STREAMS_1:
            return o << "QUIC_FRAME_MAX_STREAMS_1";
        case QUIC_FRAME_DATA_BLOCKED:
            return o << "QUIC_FRAME_DATA_BLOCKED";
        case QUIC_FRAME_STREAM_DATA_BLOCKED:
            return o << "QUIC_FRAME_STREAM_DATA_BLOCKED";
        case QUIC_FRAME_NEW_CONNECTION_ID:
            return o << "QUIC_FRAME_NEW_CONNECTION_ID";
        case QUIC_FRAME_RETIRE_CONNECTION_ID:
            return o << "QUIC_FRAME_RETIRE_CONNECTION_ID";
        case QUIC_FRAME_PATH_CHALLENGE:
            return o << "QUIC_FRAME_PATH_CHALLENGE";
        case QUIC_FRAME_PATH_RESPONSE:
            return o << "QUIC_FRAME_PATH_RESPONSE";
        case QUIC_FRAME_CONNECTION_CLOSE:
            return o << "QUIC_FRAME_CONNECTION_CLOSE";
        case QUIC_FRAME_CONNECTION_CLOSE_1:
            return o << "QUIC_FRAME_CONNECTION_CLOSE_1";
        case QUIC_FRAME_HANDSHAKE_DONE:
            return o << "QUIC_FRAME_HANDSHAKE_DONE";
        case QUIC_FRAME_DATAGRAM:
            return o << "QUIC_FRAME_DATAGRAM";
        case QUIC_FRAME_DATAGRAM_1:
            return o << "QUIC_FRAME_DATAGRAM_1";
        case QUIC_FRAME_ACK_FREQUENCY:
            return o << "QUIC_FRAME_ACK_FREQUENCY";
        case QUIC_FRAME_IMMEDIATE_ACK:
            return o << "QUIC_FRAME_IMMEDIATE_ACK";
        default:
            return o << "UNRECOGNIZED_FRAME_TYPE(" << (uint32_t) type << ")";
    }
}
