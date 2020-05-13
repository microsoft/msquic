/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.

Abstract:

    QUIC Debugger Extension Command 'session'. This command handles state
    specific to a single QUIC Session.

--*/

#include "quictypes.h"

EXT_COMMAND(
    quicsession,
    "Shows all information about a Session",
    "{;e,r;addr;The address of the Session}"
    )
{
    Session Session(GetUnnamedArgU64(0));

    Dml("\n<b>SESSION</b> (<link cmd=\"dt msquic!QUIC_SESSION 0x%I64X\">raw</link>)\n"
        "\n"
        "\tALPN                %s\n"
        "\tRegistration        <link cmd=\"!quicregistration 0x%I64X\">0x%I64X</link>\n",
        Session.Addr,
        Session.GetAlpns().Data,
        Session.GetRegistration(),
        Session.GetRegistration());

    Dml("\n<u>CONNECTIONS</u>\n"
        "\n");

    bool HasAtLeastOne = false;
    auto Connections = Session.GetConnections();
    while (true) {
        ULONG64 LinkAddr = Connections.Next();
        if (LinkAddr == 0) {
            break;
        }

        auto Connection = Connection::FromSessionLink(LinkAddr);
        Dml("\t<link cmd=\"!quicconnection 0x%I64X\">0x%I64X</link>\n",
            Connection.Addr,
            Connection.Addr);
        HasAtLeastOne = true;
    }

    if (!HasAtLeastOne) {
        Dml("\tNone\n");
    }

    Dml("\n");
}
