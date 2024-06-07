/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.

Abstract:

    QUIC Debugger Extension Command 'library'. This command is for querying the
    state of the library.

--*/

#include "quictypes.h"

EXT_COMMAND(
    quiclibrary,
    "Shows the state of the MsQuic library",
    ""
    )
{
    QuicLibrary Lib;

    Dml("\n<b>LIBRARY</b> (<link cmd=\"dt msquic!QUIC_LIBRARY 0x%I64X\">raw</link>)\n"
        "\n"
        "\tRefCount             %u\n"
        "\tHandshake Mem        %llu bytes\n"
        "\tRetry Mem Limit      %llu bytes\n"
        "\tSending Retries      %s\n"
        "\n",
        Lib.Addr,
        Lib.RefCount(),
        Lib.CurrentHandshakeMemoryUsage(),
        Lib.RetryHandshakeMemoryLimit(),
        Lib.IsSendingRetries() ? "yes" : "no");

    Dml("\n<u>REGISTRATIONS</u>\n"
        "\n");

    bool HasAtLeastOne = false;
    auto Registrations = Lib.GetRegistrations();
    while (!CheckControlC()) {
        ULONG64 LinkAddr = Registrations.Next();
        if (LinkAddr == 0) {
            break;
        }

        Registration Registration = Registration::FromLink(LinkAddr);
        Dml("\t<link cmd=\"!quicregistration 0x%I64X\">0x%I64X</link>\t%s\t\t\"%s\"\n",
            Registration.Addr,
            Registration.Addr,
            Registration.GetWorkersState(),
            Registration.GetAppName().Data);
        HasAtLeastOne = true;
    }

    if (!HasAtLeastOne) {
        Dml("\tNone\n");
    }

    Dml("\n<u>BINDINGS</u>\n"
        "\n");

    HasAtLeastOne = false;
    auto Bindings = Lib.GetBindings();
    while (!CheckControlC()) {
        ULONG64 LinkAddr = Bindings.Next();
        if (LinkAddr == 0) {
            break;
        }

        auto Binding = Binding::FromLink(LinkAddr);
        Dml("\t<link cmd=\"!quicbinding 0x%I64X\">0x%I64X</link>\n",
            Binding.Addr,
            Binding.Addr);
        HasAtLeastOne = true;
    }

    if (!HasAtLeastOne) {
        Dml("\tNone\n");
    }

    Dml("\n");
}

EXT_COMMAND(
    quiclib,
    "Shows the state of the MsQuic library",
    ""
    )
{
    EXT_CLASS::quiclibrary();
}
