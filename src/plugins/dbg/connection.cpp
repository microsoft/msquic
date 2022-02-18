/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.

Abstract:

    QUIC Debugger Extension Command 'connection'. This command handles state
    specific to a single QUIC Connection.

--*/

#include "quictypes.h"

EXT_COMMAND(
    quicconnection,
    "Shows all information about a Connection",
    "{;e,r;addr;The address of the Connection handle}"
    )
{
    Connection Conn(GetUnnamedArgU64(0));
    Registration Reg(Conn.RegistrationPtr());
    Worker Wrker(Conn.WorkerPtr());

    Dml("\n<b>CONNECTION</b> (<link cmd=\"!quicanalyze 0x%I64X\">analyze</link>) (<link cmd=\"dt msquic!QUIC_CONNECTION 0x%I64X\">raw</link>)\n"
        "\n"
        "\tRegistration         < link cmd = \"!quicregistration 0x%I64X\">%I64u</link>\n"
        "\tWorker               < link cmd = \"!quicworker 0x%I64X\">%I64u</link>\t%s\n"
        "\n"
        "\tLocal Address        %s\n"
        "\tRemote Address       %s\n"
        "\tVersion              0x%X\n"
        "\tRef Count            %d\n",
        Conn.Addr,
        Conn.Addr,
        Reg.Addr,
        Reg.Addr,
        Wrker.Addr,
        Wrker.Addr,
        Wrker.StateStr(),
        Conn.GetLocalAddress().IpString,
        Conn.GetRemoteAddress().IpString,
        Conn.Version(),
        Conn.RefCount());

    //
    // TODO - Enumerate Source and Destination Connection IDs.
    //

    auto Send = Conn.GetSend();

    Dml("\n"
        "\tType                 %s\n"
        "\tState                %s\n"
        "\tSendPktNum           %I64u\n",
        Conn.TypeStr(),
        Conn.StateStr(),
        Send.NextPacketNumber());

    //
    // CIDs
    //

    Dml("\n\tSource CIDs          ");

    auto SourceCids = Conn.GetSourceCids().Next();
    if (!SourceCids) {
        Dml("None\n");
    } else {
        while (!CheckControlC() && SourceCids) {
            auto CidEntry = CidHashEntry::FromLink(SourceCids);
            auto Cid = CidEntry.GetCid();
            Dml("%s (%llu)\n\t                     ",
                Cid.Str().Data,
                Cid.SequenceNumber());
            SourceCids = SingleListEntry(SourceCids).Next();
        }
    }

    Dml("\n\tDestination CIDs     "); // TODO
    Dml("TODO\n");

    //
    // Streams
    //

    Dml("\n<u>STREAMS</u>\n"
        "\n");

    bool HasAtLeastOneStream = false;
    ULONG64 HashPtr = Conn.GetStreams().GetStreamTable();
    if (HashPtr != 0) {
        HashTable Streams(HashPtr);
        ULONG64 EntryPtr;
        while (!CheckControlC() && Streams.GetNextEntry(&EntryPtr)) {
            auto Strm = Stream::FromHashTableEntry(EntryPtr);
            Dml("\t<link cmd=\"!quicstream 0x%I64X\">Stream %I64u</link>\n",
                Strm.Addr,
                Strm.ID());
            HasAtLeastOneStream = true;
        }
    }

    if (!HasAtLeastOneStream) {
        Dml("\tNo Open Streams\n");
    }

    //
    // Operations
    //

    Dml("\n<u>OPERATIONS</u>\n"
        "\n");

    bool HasAtLeastOneOperation = false;
    auto Operations = Conn.GetOperQueue().GetOperations();
    while (!CheckControlC()) {
        auto OperLinkAddr = Operations.Next();
        if (OperLinkAddr == 0) {
            break;
        }

        auto Operation = Operation::FromLink(OperLinkAddr);
        Dml("\t%s\n", Operation.TypeStr());
        HasAtLeastOneOperation = true;
    }

    if (!HasAtLeastOneOperation) {
        Dml("\tNo Operations Queued\n");
    }

    //
    // Send State
    //

    Dml("\n<u>SEND STATE</u>\n"
        "\n"
        "\tSend Flags           ");

    auto SendFlags = Send.SendFlags();

    if (SendFlags == 0) {
        Dml("NONE");
    } else {
        if (SendFlags & QUIC_CONN_SEND_FLAG_ACK) {
            Dml("ACK\n"
                "\t                     ");
        }
        if (SendFlags & QUIC_CONN_SEND_FLAG_CRYPTO) {
            Dml("CRYPTO\n"
                "\t                     ");
        }
        if (SendFlags & QUIC_CONN_SEND_FLAG_CONNECTION_CLOSE) {
            Dml("CONNECTION_CLOSE\n"
                "\t                     ");
        }
        if (SendFlags & QUIC_CONN_SEND_FLAG_APPLICATION_CLOSE) {
            Dml("APPLICATION_CLOSE\n"
                "\t                     ");
        }
        if (SendFlags & QUIC_CONN_SEND_FLAG_DATA_BLOCKED) {
            Dml("DATA_BLOCKED\n"
                "\t                     ");
        }
        if (SendFlags & QUIC_CONN_SEND_FLAG_MAX_DATA) {
            Dml("MAX_DATA\n"
                "\t                     ");
        }
        if (SendFlags & QUIC_CONN_SEND_FLAG_MAX_STREAMS_BIDI) {
            Dml("MAX_STREAMS_BIDI\n"
                "\t                     ");
        }
        if (SendFlags & QUIC_CONN_SEND_FLAG_MAX_STREAMS_UNI) {
            Dml("MAX_STREAMS_UNI\n"
                "\t                     ");
        }
        if (SendFlags & QUIC_CONN_SEND_FLAG_NEW_CONNECTION_ID) {
            Dml("NEW_CONNECTION_ID\n"
                "\t                     ");
        }
        if (SendFlags & QUIC_CONN_SEND_FLAG_PATH_CHALLENGE) {
            Dml("PATH_CHALLENGE\n"
                "\t                     ");
        }
        if (SendFlags & QUIC_CONN_SEND_FLAG_PATH_RESPONSE) {
            Dml("PATH_RESPONSE\n"
                "\t                     ");
        }
        if (SendFlags & QUIC_CONN_SEND_FLAG_PING) {
            Dml("PING\n"
                "\t                     ");
        }
        if (SendFlags & QUIC_CONN_SEND_FLAG_HANDSHAKE_DONE) {
            Dml("HANDSHAKE_DONE\n"
                "\t                     ");
        }
        if (SendFlags & QUIC_CONN_SEND_FLAG_DATAGRAM) {
            Dml("DATAGRAM\n"
                "\t                     ");
        }
        if (SendFlags & QUIC_CONN_SEND_FLAG_DPLPMTUD) {
            Dml("DPLPMTUD\n"
                "\t                     ");
        }
    }

    Dml("\n"
        "\tQueued Streams       ");

    HasAtLeastOneStream = false;
    auto SendStreams = Send.GetSendStreams();
    while (!CheckControlC()) {
        auto StreamSendLinkAddr = SendStreams.Next();
        if (StreamSendLinkAddr == 0) {
            break;
        }

        auto Strm = Stream::FromSendLink(StreamSendLinkAddr);
        Dml("<link cmd=\"!quicstream 0x%I64X\">Stream %I64u</link>\n"
            "\t                     ",
            Strm.Addr,
            Strm.ID());
        HasAtLeastOneStream = true;
    }

    if (!HasAtLeastOneStream) {
        Dml("NONE\n");
    } else {
        Dml("\n");
    }

    Dml("\tOutstanding Packets  ");

    auto Loss = Conn.GetLossDetection();
    auto SendPackets = Loss.GetSendPackets();

    if (SendPackets == 0) {
        Dml("NONE\n");
    } else {
        while (SendPackets && !CheckControlC()) {
            auto Packet = SentPacketMetadata(SendPackets);
            Dml("<link cmd=\"!quicpacket 0x%I64X\">%I64u</link>\n"
                "\t                     ",
                Packet.Addr,
                Packet.PacketNumber());
            SendPackets = Packet.Next();
        }
        Dml("\n");
    }

    Dml("\n");
}

EXT_COMMAND(
    quicconn,
    "Shows all information about a Connection",
    "{;e,r;addr;The address of the Connection handle}"
    )
{
    EXT_CLASS::quicconnection();
}
