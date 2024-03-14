/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.

Abstract:

    QUIC Debugger Extension Command 'worker'. This command handles state
    specific to a single QUIC Worker.

--*/

#include "quictypes.h"

EXT_COMMAND(
    quicworker,
    "Shows all information about a Worker",
    "{;e,r;addr;The address of the Worker}"
    )
{
    Worker Work(GetUnnamedArgU64(0));

    Dml("\n<b>WORKER</b> (<link cmd=\"dt msquic!QUIC_WORKER 0x%I64X\">raw</link>)\n"
        "\n"
        "\tState               %s\n"
        "\tPartition           %u\n"
        "\tThread              0x%X (<link cmd=\"~~[0x%X]s\">UM</link>/<link cmd=\"!thread 0x%I64X\">KM</link>)\n",
        Work.Addr,
        Work.StateStr(),
        Work.PartitionIndex(),
        Work.ThreadID(),
        Work.ThreadID(),
        Work.Thread());

    Dml("\n<u>QUEUE</u>\n"
        "\n");

    bool HasAtLeastOne = false;
    LinkedList ProcessConnections = Work.GetConnections();
    while (true) {
        ULONG64 LinkAddr = ProcessConnections.Next();
        if (LinkAddr == 0) {
            break;
        }

        Connection Conn = Connection::FromWorkerLink(LinkAddr);
        Dml("\t<link cmd=\"!quicconnection 0x%I64X\">Connection 0x%I64X</link> [%s]\n",
            Conn.Addr,
            Conn.Addr,
            Conn.TypeStr());
        HasAtLeastOne = true;
    }

    LinkedList ProcessOperations = Work.GetOperations();
    while (true) {
        ULONG64 LinkAddr = ProcessOperations.Next();
        if (LinkAddr == 0) {
            break;
        }

        Operation Operation = Operation::FromLink(LinkAddr);
        Dml("\t%s\n", Operation.TypeStr());
        HasAtLeastOne = true;
    }

    if (!HasAtLeastOne) {
        Dml("\tNo Work\n");
    }

    Dml("\n");
}
