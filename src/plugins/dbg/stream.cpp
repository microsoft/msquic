/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.

Abstract:

    QUIC Debugger Extension Command 'stream'. This command handles state
    specific to a single QUIC Stream.

--*/

#include "quictypes.h"

EXT_COMMAND(
    quicstream,
    "Shows all information about a Stream",
    "{;e,r;addr;The address of the Stream handle}"
    )
{
    Stream Strm(GetUnnamedArgU64(0));

    Dml("\n<b>STREAM</b> (<link cmd=\"!quicanalyze 0x%I64X\">analyze</link>) (<link cmd=\"dt msquic!QUIC_STREAM 0x%I64X\">raw</link>)\n"
        "\n"
        "\tID                   %I64u\n"
        "\tState                %s\n"
        "\tConnection           <link cmd=\"!quicconnection 0x%I64X\">0x%I64X</link>\n"
        "\tRef Count            %d\n",
        Strm.Addr,
        Strm.Addr,
        Strm.ID(),
        Strm.StateStr(),
        Strm.GetConnection(),
        Strm.GetConnection(),
        Strm.RefCount());

    //
    // Send State
    //

    Dml("\n<u>SEND STATE</u>\n"
        "\n"
        "\tState                %s\n"
        "\tMax Offset (FC)      %I64u\n"
        "\tQueue Length         %I64u\n"
        "\tBytes Sent           %I64u\n"
        "\tNext Send Offset     %I64u\n"
        "\tBytes Acked (UNA)    %I64u\n"
        "\n"
        "\tIn Recovery          %s\n"
        "\tRecov Window Open    %s\n"
        "\tRecov Next           %I64u\n"
        "\tRecov End            %I64u\n",
        Strm.SendStateStr(),
        Strm.MaxAllowedSendOffset(),
        Strm.QueuedSendOffset(),
        Strm.MaxSentLength(),
        Strm.NextSendOffset(),
        Strm.UnAckedOffset(),
        Strm.InRecovery() ? "YES" : "NO",
        Strm.RecoveryWindowOpen() ? "YES" : "NO",
        Strm.RecoveryNextOffset(),
        Strm.RecoveryEndOffset());

    Dml("\n"
        "\tQueued For Send      %s\n"
        "\tSend Flags           ",
        Strm.SendLink().Flink() == NULL ? "NO" : "YES");

    auto SendFlags = Strm.SendFlags();

    if (SendFlags == 0) {
        Dml("NONE\n");
    } else {
        if (SendFlags & QUIC_STREAM_SEND_FLAG_DATA_BLOCKED) {
            Dml("DATA_BLOCKED\n"
                "\t                     ");
        }
        if (SendFlags & QUIC_STREAM_SEND_FLAG_DATA) {
            Dml("DATA\n"
                "\t                     ");
        }
        if (SendFlags & QUIC_STREAM_SEND_FLAG_SEND_ABORT) {
            Dml("SEND_ABORT\n"
                "\t                     ");
        }
        if (SendFlags & QUIC_STREAM_SEND_FLAG_RECV_ABORT) {
            Dml("RECV_ABORT\n"
                "\t                     ");
        }
        if (SendFlags & QUIC_STREAM_SEND_FLAG_MAX_DATA) {
            Dml("MAX_DATA\n"
                "\t                     ");
        }
        if (SendFlags & QUIC_STREAM_SEND_FLAG_OPEN) {
            Dml("OPEN\n"
                "\t                     ");
        }
        if (SendFlags & QUIC_STREAM_SEND_FLAG_FIN) {
            Dml("FIN\n"
                "\t                     ");
        }
    }

    Dml("\n<u>SEND REQUESTS</u>\n"
        "\n");

    ULONG64 SendRequestsPtr = Strm.SendRequests();
    while (SendRequestsPtr != 0 && !CheckControlC()) {
        SendRequest Request(SendRequestsPtr);
        Dml("\t<link cmd=\"dt msquic!QUIC_SEND_REQUEST 0x%I64X\">0x%I64X</link>  Length:%I64u\n",
            SendRequestsPtr,
            SendRequestsPtr,
            Request.TotalLength());
        SendRequestsPtr = Request.Next();
    }

    //
    // Receive State
    //

    RecvBuffer RecvBuf = Strm.GetRecvBuffer();
    Dml("\n<u>RECEIVE STATE</u>\n"
        "\n"
        "\tState                %s\n"
        "\tMax Offset (FC)      %I64u\n"
        "\t0-RTT Length         %I64u\n"
        "\n"
        "\tRecv Win Size        %I64u (Alloc %I64u)\n"
        "\tRecv Win Start       %I64u\n",
        Strm.RecvStateStr(),
        Strm.MaxAllowedRecvOffset(),
        Strm.RecvMax0RttLength(),
        RecvBuf.VirtualBufferLength(),
        RecvBuf.AllocBufferLength(),
        RecvBuf.BaseOffset());

    Dml("\n");
}
