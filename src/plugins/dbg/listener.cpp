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
    Registration Registration(Listener.GetRegistration());

    Dml("\n<b>LISTENER</b> (<link cmd=\"dt msquic!QUIC_LISTENER 0x%I64X\">raw</link>)\n"
        "\n"
        "\tWildCard            %s\n"
        "\tAlpns               %s\n"
        "\tSession             <link cmd=\"!quicregistration 0x%I64X\">0x%I64X</link>\n"
        "\tBinding             <link cmd=\"!quicbinding 0x%I64X\">0x%I64X</link>\n"
        "\tLocalAddress        %s\n\n",
        Listener.Addr,
        Listener.WildCard() ? "true" : "false",
        Listener.GetAlpns().Data,
        Registration.Addr,
        Registration.Addr,
        Listener.GetBinding(),
        Listener.GetBinding(),
        Listener.GetLocalAddress().IpString);
}
