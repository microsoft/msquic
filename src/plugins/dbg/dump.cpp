/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.

Abstract:

    QUIC Debugger Extension Command 'dump' and 'dumpqueue'. This command is for dumping most all
    the current objects.

--*/

#include "quictypes.h"

EXT_COMMAND(
    quicdump,
    "Dumps all MsQuic objects",
    ""
    )
{
    QuicLibrary Lib;

    Dml("\n<b>DUMP</b>\n");

    auto Registrations = Lib.GetRegistrations();
    while (!CheckControlC()) {
        ULONG64 RegAddr = Registrations.Next();
        if (RegAddr == 0) {
            break;
        }

        auto Registration = Registration::FromLink(RegAddr);
        Dml("\n<link cmd=\"!quicregistration 0x%I64X\">Reg 0x%I64X</link>    \"%s\"\n",
            Registration.Addr,
            Registration.Addr,
            Registration.GetAppName().Data);

        auto Connections = Registration.GetConnections();
        while (!CheckControlC()) {
            ULONG64 ConnAddr = Connections.Next();
            if (ConnAddr == 0) {
                break;
            }

            auto Connection = Connection::FromRegistrationLink(ConnAddr);
            Dml("  <link cmd=\"!quicconnection 0x%I64X\">Conn 0x%I64X</link>    %s\n",
                Connection.Addr,
                Connection.Addr,
                Connection.TypeStr());
        }
    }

    Dml("\n");
}

EXT_COMMAND(
    quicdumpqueue,
    "Dumps the current work queue",
    ""
    )
{
    QuicLibrary Lib;

    Dml("\n<b>DUMP</b>\n");

    auto Registrations = Lib.GetRegistrations();
    while (!CheckControlC()) {
        ULONG64 RegAddr = Registrations.Next();
        if (RegAddr == 0) {
            break;
        }

        auto Registration = Registration::FromLink(RegAddr);
        auto DumpReg = false;

        auto Workers = Registration.GetWorkerPool();
        UCHAR WorkerCount = Workers.WorkerCount();
        for (UCHAR i = 0; i < WorkerCount && !CheckControlC(); i++) {
            auto Worker = Workers.GetWorker(i);
            if (Worker.IsActive() || Worker.GetConnections().Next() != 0) {
                if (!DumpReg) {
                    DumpReg = true;
                    Dml("\n<link cmd=\"!quicregistration 0x%I64X\">Reg 0x%I64X</link>    \"%s\"\n",
                        Registration.Addr,
                        Registration.Addr,
                        Registration.GetAppName().Data);
                }

                Dml("  <link cmd=\"!quicworker 0x%I64X\">Worker 0x%I64X</link>\t[Partition %d] %s\n",
                    Worker.Addr,
                    Worker.Addr,
                    Worker.PartitionIndex(),
                    Worker.StateStr());

                auto Connections = Worker.GetConnections();
                while (!CheckControlC()) {
                    ULONG64 LinkAddr = Connections.Next();
                    if (LinkAddr == 0) {
                        break;
                    }

                    auto Conn = Connection::FromWorkerLink(LinkAddr);
                    Dml("    <link cmd=\"!quicconnection 0x%I64X\">Connection 0x%I64X</link> [%s]\n",
                        Conn.Addr,
                        Conn.Addr,
                        Conn.TypeStr());

                    auto Operations = Conn.GetOperQueue().GetOperations();
                    while (!CheckControlC()) {
                        auto OperLinkAddr = Operations.Next();
                        if (OperLinkAddr == 0) {
                            break;
                        }

                        auto Operation = Operation::FromLink(OperLinkAddr);
                        Dml("      %s\n", Operation.TypeStr());
                    }
                }
            }
        }
    }

    Dml("\n");
}
