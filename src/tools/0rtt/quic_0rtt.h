/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.

--*/

#include "msquic.h" // for SAL annotations

#if defined(__cplusplus)
extern "C" {
#endif

typedef struct QUIC_0RTT_IDENTIFIER {
    uint64_t DataCenter;
    uint64_t Server;
    uint64_t Index;
} QUIC_0RTT_IDENTIFIER;

#define QUIC_0RTT_ALPN "0rtt"
#define QUIC_0RTT_PORT 4499
#define QUIC_0RTT_ID_LENGTH sizeof(QUIC_0RTT_IDENTIFIER)

//
// Library initialization.
//

BOOLEAN Quic0RttInitialize(void);

void Quic0RttUninitialize(void);

//
// Serivce/server side part that accepts and handles requests to validate 0-RTT
// session identifiers.
//

typedef struct QUIC_0RTT_SERVICE QUIC_0RTT_SERVICE;

QUIC_0RTT_SERVICE*
Quic0RttServiceStart(
    _In_reads_(20)
        const uint8_t* CertificateThumbprint
    );

void
Quic0RttServiceStop(
    _In_ QUIC_0RTT_SERVICE* Service
    );

//
// Client side part that creates identifiers and calls into the service to
// validate them.
//

typedef struct QUIC_0RTT_CLIENT QUIC_0RTT_CLIENT;

QUIC_0RTT_CLIENT*
Quic0RttClientInitialize(
    _In_ uint64_t DataCenterId,
    _In_ uint64_t ServerId,
    _In_z_ const char* ServerName
    );

void
Quic0RttClientUninitialize(
    _In_ QUIC_0RTT_CLIENT* Client
    );

void
Quic0RttClientGenerateIdentifier(
    _In_ QUIC_0RTT_CLIENT* Client,
    _Out_writes_(QUIC_0RTT_ID_LENGTH)
        uint8_t* Identifier
    );

BOOLEAN
Quic0RttClientValidateIdentifier( // TODO - Make this async.
    _In_ QUIC_0RTT_CLIENT* Client,
    _In_reads_(QUIC_0RTT_ID_LENGTH)
        uint8_t* Identifier
    );

#if defined(__cplusplus)
} // extern "C"
#endif
