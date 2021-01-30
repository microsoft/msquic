/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.

Abstract:

    QUIC Debugger Extension Command 'binding'. This command is for querying the
    state of a single binding.

--*/

#include "quictypes.h"

EXT_COMMAND(
    quicbinding,
    "Shows all information about a Binding",
    "{;e,r;addr;The address of the Binding}"
    )
{
    Binding Binding(GetUnnamedArgU64(0));
    auto Lookup = Binding.GetLookup();
    auto Socket = Binding.GetSocket();

    Dml("\n<b>BINDING</b> (<link cmd=\"dt msquic!QUIC_BINDING 0x%I64X\">raw</link>)\n"
        "\n"
        "\tExclusive            %s\n"
        "\tConnected            %s\n"
        "\tRefCount             %u\n"
        "\tCidCount             %u\n"
        "\tPartitionCount       %u\n"
        "\tLocalAddress         %s\n"
        "\tRemoteAddress        %s\n"
        "\n",
        Binding.Addr,
        Binding.Exclusive() ? "true" : "false",
        Binding.Connected() ? "true" : "false",
        Binding.RefCount(),
        Lookup.CidCount(),
        Lookup.PartitionCount(),
        Socket.GetLocalAddress().IpString,
        Socket.GetRemoteAddress().IpString);

    bool HasAtLeastOne = false;
    auto Listeners = Binding.GetListeners();
    while (!CheckControlC()) {
        ULONG64 LinkAddr = Listeners.Next();
        if (LinkAddr == 0) {
            break;
        }

        ULONG64 ListenerAddr = LinkEntryToType(LinkAddr, "msquic!QUIC_LISTENER", "Link");
        Dml("\t<link cmd=\"!quiclistener 0x%I64X\">Listener 0x%I64X</link>\n",
            ListenerAddr,
            ListenerAddr);
        HasAtLeastOne = true;
    }

    if (!HasAtLeastOne) {
        Dml("\tNo Listeners\n");
    }

    Dml("\n");

    UCHAR PartitionCount = Lookup.PartitionCount();
    if (PartitionCount == 0) {
        Connection Conn(Lookup.GetLookupPtr());
        Dml("\t<link cmd=\"!quicconnection 0x%I64X\">Connection 0x%I64X</link> [%s]\n",
            Conn.Addr,
            Conn.Addr,
            Conn.TypeStr());
    } else {
        for (UCHAR i = 0; i < PartitionCount; i++) {
            HashTable Hash(Lookup.GetLookupTable(i).GetTablePtr());
            Dml("\t<link cmd=\"dt msquic!CXPLAT_HASHTABLE 0x%I64X\">Hash Table %d</link> (%u entries)\n",
                Hash.Addr,
                i,
                Hash.NumEntries());
            ULONG64 EntryPtr;
            while (!CheckControlC() && Hash.GetNextEntry(&EntryPtr)) {
                CidHashEntry Entry = CidHashEntry::FromEntry(EntryPtr);
                Cid Cid(Entry.GetCid());
                Connection Conn(Entry.GetConnection());
                Dml("\t  <link cmd=\"!quicconnection 0x%I64X\">Connection 0x%I64X</link> [%s] [%s]\n",
                    Conn.Addr,
                    Conn.Addr,
                    Conn.TypeStr(),
                    Cid.Str().Data);
            }
        }
    }

    Dml("\n");
}
