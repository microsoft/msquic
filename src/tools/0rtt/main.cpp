/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.

--*/

#include <stdio.h>
#include "msquichelper.h"
#include "msquic.hpp"
#include "quic_0rtt.h"

int
QUIC_MAIN_EXPORT
main(int argc, char **argv)
{
    if (argc < 2 ||
        !strcmp(argv[1], "?") ||
        !strcmp(argv[1], "-?") ||
        !strcmp(argv[1], "--?") ||
        !strcmp(argv[1], "/?") ||
        !strcmp(argv[1], "help")) {
        printf("Usage: quic0rtt.exe -server:<thumbprint> | -client:<server>\n");
        exit(1);
    }

    Quic0RttInitialize();

    const char* Value;
    if ((Value = GetValue(argc, argv, "server")) != nullptr) {
        uint8_t Thumbprint[20];
        if (DecodeHexBuffer(Value, 20, Thumbprint) != 20) {
            printf("Bad thumbprint length\n");
            return 1;
        }

        auto Service = Quic0RttServiceStart(Thumbprint);
        if (!Service) {
            printf("Failed to start service\n");
            return 1;
        }

        printf("Press Enter to exit.\n\n");
        getchar();

        Quic0RttServiceStop(Service);

    } else {

        Value = GetValue(argc, argv, "client");
        if (!Value) {
            printf("No -client <server> specified!\n");
            return 1;
        }

        auto Client = Quic0RttClientInitialize(0, 0, Value);
        if (!Client) {
            printf("Failed to initialize client\n");
            return 1;
        }

        uint8_t Id[QUIC_0RTT_ID_LENGTH];
        Quic0RttClientGenerateIdentifier(Client, Id);

        auto Result = Quic0RttClientValidateIdentifier(Client, Id);
        printf("Validation result: %hhu\n", Result);

        Quic0RttClientUninitialize(Client);
    }

    Quic0RttUninitialize();

    return 0;
}

const MsQuicApi* MsQuic;

extern "C"
BOOLEAN
Quic0RttInitialize(void)
{
    CxPlatSystemLoad();
    CxPlatInitialize();
    return
        (MsQuic = new(std::nothrow) MsQuicApi()) != nullptr &&
        QUIC_SUCCEEDED(MsQuic->GetInitStatus());
}

extern "C"
void
Quic0RttUninitialize(void)
{
    delete MsQuic;
    MsQuic = nullptr;
    CxPlatUninitialize();
    CxPlatSystemUnload();
}
