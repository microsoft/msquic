/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.

--*/

#pragma once

#include "main.h"

static QUIC_ACK_EVENT MakeBbrAckEvent(
    uint64_t TimeNow,
    uint64_t LargestAck,
    uint64_t LargestSentPacketNumber,
    uint32_t BytesAcked,
    uint64_t SmoothedRtt = 50000,
    uint64_t MinRtt = 45000,
    BOOLEAN MinRttValid = TRUE)
{
    QUIC_ACK_EVENT Ack{};
    Ack.TimeNow = TimeNow;
    Ack.LargestAck = LargestAck;
    Ack.LargestSentPacketNumber = LargestSentPacketNumber;
    Ack.NumRetransmittableBytes = BytesAcked;
    Ack.NumTotalAckedRetransmittableBytes = BytesAcked;
    Ack.SmoothedRtt = SmoothedRtt;
    Ack.MinRtt = MinRtt;
    Ack.MinRttValid = MinRttValid;
    Ack.AdjustedAckTime = TimeNow;
    return Ack;
}

static QUIC_LOSS_EVENT MakeBbrLossEvent(
    uint32_t LostBytes,
    uint64_t LargestPacketNumberLost,
    uint64_t LargestSentPacketNumber,
    BOOLEAN PersistentCongestion = FALSE)
{
    QUIC_LOSS_EVENT Loss{};
    Loss.NumRetransmittableBytes = LostBytes;
    Loss.LargestPacketNumberLost = LargestPacketNumberLost;
    Loss.LargestSentPacketNumber = LargestSentPacketNumber;
    Loss.PersistentCongestion = PersistentCongestion;
    return Loss;
}

static QUIC_MAX_SENT_PACKET_METADATA MakeBbrPacket(
    uint16_t PacketLength,
    BOOLEAN HasLastAckedPacketInfo,
    BOOLEAN IsAppLimited,
    uint64_t TotalBytesSent,
    uint64_t SentTime,
    uint64_t LastTotalBytesSent = 0,
    uint64_t LastSentTime = 0,
    uint64_t LastTotalBytesAcked = 0,
    uint64_t LastAdjustedAckTime = 0,
    uint64_t LastAckTime = 0)
{
    QUIC_MAX_SENT_PACKET_METADATA PacketBuf{};
    auto& Pkt = PacketBuf.Metadata;
    Pkt.PacketLength = PacketLength;
    Pkt.Flags.HasLastAckedPacketInfo = HasLastAckedPacketInfo;
    Pkt.Flags.IsAppLimited = IsAppLimited;
    Pkt.TotalBytesSent = TotalBytesSent;
    Pkt.SentTime = SentTime;
    Pkt.LastAckedPacketInfo.TotalBytesSent = LastTotalBytesSent;
    Pkt.LastAckedPacketInfo.SentTime = LastSentTime;
    Pkt.LastAckedPacketInfo.TotalBytesAcked = LastTotalBytesAcked;
    Pkt.LastAckedPacketInfo.AdjustedAckTime = LastAdjustedAckTime;
    Pkt.LastAckedPacketInfo.AckTime = LastAckTime;
    Pkt.Next = NULL;
    return PacketBuf;
}
