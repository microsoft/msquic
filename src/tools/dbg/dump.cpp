/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.

Abstract:

    QUIC Debugger Extension Command 'dump'. This command is for dumping most all
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

        auto Sessions = Registration.GetSessions();
        while (!CheckControlC()) {
            ULONG64 SessAddr = Sessions.Next();
            if (SessAddr == 0) {
                break;
            }

            auto Session = Session::FromLink(SessAddr);
            Dml("  <link cmd=\"!quicsession 0x%I64X\">Sess 0x%I64X</link>    \"%s\"\n",
                Session.Addr,
                Session.Addr,
                Session.GetAlpns().Data);

            auto Connections = Session.GetConnections();
            while (!CheckControlC()) {
                ULONG64 ConnAddr = Connections.Next();
                if (ConnAddr == 0) {
                    break;
                }

                auto Connection = Connection::FromSessionLink(ConnAddr);
                Dml("    <link cmd=\"!quicconnection 0x%I64X\">Conn 0x%I64X</link>    %s\n",
                    Connection.Addr,
                    Connection.Addr,
                    Connection.TypeStr());
            }
        }
    }

    Dml("\n");
}
