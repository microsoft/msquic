/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.

Abstract:

    QUIC Debugger Extension Command 'listener'. This command handles state
    specific to a single QUIC Listener.

--*/

#include "quictypes.h"

EXT_COMMAND(
    quiclistener,
    "Shows all information about a Listener",
    "{;e,r;addr;The address of the Listener}"
    )
{
    Listener Listener(GetUnnamedArgU64(0));
    Session Session(Listener.GetSession());

    Dml("\n<b>LISTENER</b> (<link cmd=\"dt msquic!QUIC_LISTENER 0x%I64X\">raw</link>)\n"
        "\n"
        "\tWildCard            %s\n"
        "\tSession             <link cmd=\"!quicsession 0x%I64X\">0x%I64X</link>\t\"%s\"\n"
        "\tBinding             <link cmd=\"!quicbinding 0x%I64X\">0x%I64X</link>\n"
        "\tLocalAddress        %s\n\n",
        Listener.Addr,
        Listener.WildCard() ? "true" : "false",
        Session.Addr,
        Session.Addr,
        Session.GetAlpn().Data,
        Listener.GetBinding(),
        Listener.GetBinding(),
        Listener.GetLocalAddress().IpString);
}
