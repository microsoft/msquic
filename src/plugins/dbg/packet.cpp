/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.

Abstract:

    QUIC Debugger Extension Command 'packet'. This command displays the state
    for a single send packet.

--*/

#include "quictypes.h"

EXT_COMMAND(
    quicpacket,
    "Shows all information about a send packet",
    "{;e,r;addr;The address of the sent packet}"
    )
{
    SentPacketMetadata Packet(GetUnnamedArgU64(0));

    auto Flags = Packet.Flags();

    Dml("\n<b>PACKET</b> (<link cmd=\"dt msquic!QUIC_SENT_PACKET_METADATA 0x%I64X\">raw</link>)\n"
        "\n"
        "\tKey Type             %s\n"
        "\tPacket Number        %I64u\n"
        "\tSent Time (us)       %u\n"
        "\tLength               %hu\n"
        "\tFlags                ",
        Packet.Addr,
        Flags.KeyTypeStr(),
        Packet.PacketNumber(),
        Packet.SentTime(),
        Packet.PacketLength());

    if (Flags.IsAckEliciting) {
        Dml("Ack Eliciting\n"
            "\t                     ");
    }
    if (Flags.IsMtuProbe) {
        Dml("DPLPMTUD\n"
            "\t                     ");
    }

    //
    // Frames
    //

    Dml("\n<u>Frames</u>\n"
        "\n");

    for (UINT32 i = 0; i < Packet.FrameCount(); i++) {
        auto Frame = Packet.GetFrame(i);
        Dml("\t<link cmd=\"dt msquic!QUIC_SENT_FRAME_METADATA 0x%I64X\">0x%I64X</link>\t%s\n",
            Frame.Addr, Frame.Addr, Frame.TypeStr());
    }

    Dml("\n");
}
