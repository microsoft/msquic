/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.

Abstract:

    QUIC Debugger Extension Command 'handle'. This command is for querying the
    type of a handle.

--*/

#include "quictypes.h"

EXT_COMMAND(
    quichandle,
    "Shows the type of a handle",
    "{;e,r;addr;The address of the handle}"
    )
{
    QuicHandle Handle(GetUnnamedArgU64(0));

    Dml("\n<b>HANDLE</b> (<link cmd=\"dt msquic!QUIC_HANDLE 0x%I64X\">raw</link>)\n"
        "\n"
        "\tType                 <link cmd=\"!quic%s 0x%I64X\">%s</link>\n",
        Handle.Addr,
        Handle.CommandStr(),
        Handle.Addr,
        Handle.TypeStr());

    Dml("\n");
}
