/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.

--*/

#include <stdio.h>
#include "msquichelper.h"
#include "quic_0rtt.h"

int
QUIC_MAIN_EXPORT
main(int argc, char **argv)
{
    if (argc > 1 &&
        (
            !strcmp(argv[1], "?") ||
            !strcmp(argv[1], "-?") ||
            !strcmp(argv[1], "--?") ||
            !strcmp(argv[1], "/?") ||
            !strcmp(argv[1], "help")
        )) {
        printf("Usage: quic0rtt.exe -server | -client <server>\n");
        exit(1);
    }

    if (GetFlag(argc, argv, "-server")) {
        auto Service = Quic0RttServiceStart();
        if (!Service) {
            printf("Failed to start service\n");
            return 1;
        }

        printf("Press Enter to exit.\n\n");
        getchar();

        Quic0RttServiceStop(Service);

    } else {

        if (argc < 3) {
            printf("No -client <server> specified!\n");
            return 1;
        }
        const char* ServerName = GetValue(argc, argv, "-client");
        if (!ServerName) {
            printf("No -client <server> specified!\n");
            return 1;
        }

        auto Client = Quic0RttClientInitialize(ServerName);
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

    return 0;
}
