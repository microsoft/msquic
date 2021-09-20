/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.

--*/

#include "msquic.h" // for SAL annotations

#if defined(__cplusplus)
extern "C" {
#endif

#define QUIC_0RTT_ALPN "0rtt"
#define QUIC_0RTT_PORT 4499
#define QUIC_0RTT_ID_LENGTH 16

//
// Serivce/server side part that accepts and handles requests to validate 0-RTT
// session identifiers.
//

typedef struct QUIC_0RTT_SERVICE QUIC_0RTT_SERVICE;

QUIC_0RTT_SERVICE* Quic0RttServiceStart();

void Quic0RttServiceStop(QUIC_0RTT_SERVICE* Service);

//
// Client side part that creates identifiers and calls into the service to
// validate them.
//
// TODO - Make this async.
//

typedef struct QUIC_0RTT_CLIENT QUIC_0RTT_CLIENT;

QUIC_0RTT_CLIENT* Quic0RttClientInitialize(const char* ServerName);

void Quic0RttClientUninitialize(QUIC_0RTT_CLIENT* Client);

void
Quic0RttClientGenerateIdentifier(
    _In_ QUIC_0RTT_CLIENT* Client,
    _Out_writes_(QUIC_0RTT_ID_LENGTH)
        uint8_t* Identifier
    );

bool
Quic0RttClientValidateIdentifier(
    _In_ QUIC_0RTT_CLIENT* Client,
    _In_reads_(QUIC_0RTT_ID_LENGTH)
        uint8_t* Identifier
    );

#if defined(__cplusplus)
} // extern "C"
#endif
