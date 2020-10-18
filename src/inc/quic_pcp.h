/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.

Abstract:

    This file contains the definitions for the port control protocol used by the
    core QUIC library.

--*/

#pragma once

#include "quic_datapath.h"

#if defined(__cplusplus)
extern "C" {
#endif

typedef struct QUIC_PCP QUIC_PCP;

#define QUIC_PCP_NONCE_LENGTH 12

//
// PCP event / callback interface
//

typedef enum QUIC_PCP_EVENT_TYPE {
    QUIC_PCP_EVENT_FAILURE = 0,
    QUIC_PCP_EVENT_MAP     = 1,
    QUIC_PCP_EVENT_PEER    = 2
} QUIC_PCP_EVENT_TYPE;

typedef struct QUIC_PCP_EVENT {
    QUIC_PCP_EVENT_TYPE Type;
    union {
        struct {
            uint8_t Nonce[QUIC_PCP_NONCE_LENGTH];
            const QUIC_ADDR* InternalAddress;
            uint8_t ErrorCode;
        } FAILURE;

        struct {
            uint8_t Nonce[QUIC_PCP_NONCE_LENGTH];
            uint32_t LifetimeSeconds;
            const QUIC_ADDR* InternalAddress;
            const QUIC_ADDR* ExternalAddress;
        } MAP;

        struct {
            uint8_t Nonce[QUIC_PCP_NONCE_LENGTH];
            uint32_t LifetimeSeconds;
            const QUIC_ADDR* InternalAddress;
            const QUIC_ADDR* ExternalAddress;
            const QUIC_ADDR* RemotePeerAddress;
        } PEER;
    };
} QUIC_PCP_EVENT;

//
// Function pointer type for PCP callbacks.
//
typedef
_IRQL_requires_max_(DISPATCH_LEVEL)
_Function_class_(QUIC_PCP_CALLBACK)
void
(QUIC_PCP_CALLBACK)(
    _In_ QUIC_PCP* PcpContext,
    _In_ void* Context,
    _In_ const QUIC_PCP_EVENT* Event
    );

typedef QUIC_PCP_CALLBACK *QUIC_PCP_CALLBACK_HANDLER;

//
// Initializes the port control protocol interface on the data path.
//
_IRQL_requires_max_(PASSIVE_LEVEL)
QUIC_STATUS
QuicPcpInitialize(
    _In_ QUIC_DATAPATH* Datapath,
    _In_ void* Context,
    _In_ QUIC_PCP_CALLBACK_HANDLER Handler,
    _Out_ QUIC_PCP** PcpContext
    );

//
// Uninitializes the PCP context.
//
_IRQL_requires_max_(PASSIVE_LEVEL)
void
QuicPcpUninitialize(
    _In_ QUIC_PCP* PcpContext
    );

//
// Send a MAP request for an internal UDP port.
//
_IRQL_requires_max_(DISPATCH_LEVEL)
QUIC_STATUS
QuicPcpSendMapRequest(
    _In_ QUIC_PCP* PcpContext,
    _In_reads_(QUIC_PCP_NONCE_LENGTH)
        const uint8_t* Nonce,
    _In_opt_ const QUIC_ADDR* LocalAddress,
    _In_ uint16_t InternalPort,     // Host byte order
    _In_ uint32_t Lifetime          // Zero indicates delete Nonce must match.
    );

//
// Send a PEER request for an internal UDP port to an external peer.
//
_IRQL_requires_max_(DISPATCH_LEVEL)
QUIC_STATUS
QuicPcpSendPeerRequest(
    _In_ QUIC_PCP* PcpContext,
    _In_reads_(QUIC_PCP_NONCE_LENGTH)
        const uint8_t* Nonce,
    _In_opt_ const QUIC_ADDR* LocalAddress,
    _In_ const QUIC_ADDR* RemotePeerAddress,
    _In_ uint16_t InternalPort,     // Host byte order
    _In_ uint32_t Lifetime          // Zero indicates delete. Nonce must match.
    );

#if defined(__cplusplus)
}
#endif
