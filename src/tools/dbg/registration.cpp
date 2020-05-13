/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.

Abstract:

    QUIC Debugger Extension Command 'registration'. This command is for querying the
    state of a single registration.

--*/

#include "quictypes.h"

EXT_COMMAND(
    quicregistration,
    "Shows all information about a Registration",
    "{;e,r;addr;The address of the Registration}"
    )
{
    Registration Registration(GetUnnamedArgU64(0));

    Dml("\n<b>REGISTRATION</b> (<link cmd=\"dt msquic!QUIC_REGISTRATION 0x%I64X\">raw</link>)\n"
        "\n"
        "\tAppName             %s\n"
        "\n",
        Registration.Addr,
        Registration.GetAppName().Data);

    Dml("\n<u>SESSIONS</u>\n"
        "\n");

    auto Sessions = Registration.GetSessions();
    while (!CheckControlC()) {
        ULONG64 LinkAddr = Sessions.Next();
        if (LinkAddr == 0) {
            break;
        }

        auto Session = Session::FromLink(LinkAddr);
        Dml("\t<link cmd=\"!quicsession 0x%I64X\">0x%I64X</link>\t\"%s\"\n",
            Session.Addr,
            Session.Addr,
            Session.GetAlpns().Data);
    }

    Dml("\n<u>WORKERS</u>\n"
        "\n");

    auto Workers = Registration.GetWorkerPool();
    UCHAR WorkerCount = Workers.WorkerCount();
    for (UCHAR i = 0; i < WorkerCount; i++) {
        Dml("\t<link cmd=\"!quicworker 0x%I64X\">Proc %d</link>\t%s\n",
            Workers.GetWorker(i).Addr,
            Workers.GetWorker(i).IdealProcessor(),
            Workers.GetWorker(i).StateStr());
    }

    Dml("\n");
}
