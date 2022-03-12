/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.

Abstract:

    QUIC Debugger Extension Command 'configuration'. This command handles state
    specific to a single QUIC Configuration.

--*/

#include "quictypes.h"

EXT_COMMAND(
    quicconfiguration,
    "Shows all information about a Configuration",
    "{;e,r;addr;The address of the Configuration}"
    )
{
    Configuration Configuration(GetUnnamedArgU64(0));

    Dml("\n<b>CONFIGURATION</b> (<link cmd=\"dt msquic!QUIC_CONFIGURATION 0x%I64X\">raw</link>)\n"
        "\n"
        "\tALPN                %s\n"
        "\tRegistration        <link cmd=\"!quicregistration 0x%I64X\">0x%I64X</link>\n",
        Configuration.Addr,
        Configuration.GetAlpns().Data,
        Configuration.GetRegistration(),
        Configuration.GetRegistration());

    Dml("\n");
}
