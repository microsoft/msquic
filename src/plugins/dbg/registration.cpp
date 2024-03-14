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

    Dml("\n<u>CONFIGURATIONS</u>\n"
        "\n");

    auto Configurations = Registration.GetConfigurations();
    while (!CheckControlC()) {
        ULONG64 LinkAddr = Configurations.Next();
        if (LinkAddr == 0) {
            break;
        }

        auto Configuration = Configuration::FromLink(LinkAddr);
        Dml("\t<link cmd=\"!quicconfiguration 0x%I64X\">0x%I64X</link>\t\"%s\"\n",
            Configuration.Addr,
            Configuration.Addr,
            Configuration.GetAlpns().Data);
    }

    Dml("\n<u>WORKERS</u>\n"
        "\n");

    auto Workers = Registration.GetWorkerPool();
    UCHAR WorkerCount = Workers.WorkerCount();
    for (UCHAR i = 0; i < WorkerCount; i++) {
        Dml("\t<link cmd=\"!quicworker 0x%I64X\">Partition %d</link> \t%s\n",
            Workers.GetWorker(i).Addr,
            Workers.GetWorker(i).PartitionIndex(),
            Workers.GetWorker(i).StateStr());
    }

    Dml("\n<u>CONNECTIONS</u>\n"
        "\n");

    auto Connections = Registration.GetConnections();
    while (!CheckControlC()) {
        ULONG64 LinkAddr = Connections.Next();
        if (LinkAddr == 0) {
            break;
        }

        auto Connection = Connection::FromRegistrationLink(LinkAddr);
        Dml("\t<link cmd=\"!quicconnection 0x%I64X\">0x%I64X</link>\t%s\n",
            Connection.Addr,
            Connection.Addr,
            Connection.StateStr());
    }

    Dml("\n");
}
