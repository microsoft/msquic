/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.

Abstract:

    QUIC protocol versions.

--*/

#pragma once

//
// The QUIC version numbers, in network byte order.
//
#define QUIC_VERSION_VER_NEG    0x00000000U     // Version for 'Version Negotiation'
#define QUIC_VERSION_2          0xcf43336bU     // Second official version
#define QUIC_VERSION_1          0x01000000U     // First official version
#define QUIC_VERSION_MS_1       0x0000cdabU     // First Microsoft version (currently same as latest draft)
#define QUIC_VERSION_DRAFT_29   0x1d0000ffU     // IETF draft 29

//
// The QUIC version numbers, in host byte order.
//
#define QUIC_VERSION_VER_NEG_H  0x00000000U     // Version for 'Version Negotiation'
#define QUIC_VERSION_2_H        0x6b3343cfU     // Second official version
#define QUIC_VERSION_1_H        0x00000001U     // First official version
#define QUIC_VERSION_1_MS_H     0xabcd0000U     // First Microsoft version (-1412628480 in decimal)
#define QUIC_VERSION_DRAFT_29_H 0xff00001dU     // IETF draft 29

//
// Represents a reserved version value; used to force version negotation.
//
#define QUIC_VERSION_RESERVED       0x0a0a0a0aU
#define QUIC_VERSION_RESERVED_MASK  0x0f0f0f0fU

//
// The latest QUIC version number.
//
#define QUIC_VERSION_LATEST     QUIC_VERSION_1
#define QUIC_VERSION_LATEST_H   QUIC_VERSION_1_H

QUIC_INLINE
BOOLEAN
QuicIsVersionSupported(
    _In_ uint32_t Version // Network Byte Order
    )
{
    switch (Version) {
    case QUIC_VERSION_1:
    case QUIC_VERSION_DRAFT_29:
    case QUIC_VERSION_MS_1:
    case QUIC_VERSION_2:
        return TRUE;
    default:
        return FALSE;
    }
}

QUIC_INLINE
BOOLEAN
QuicIsVersionReserved(
    _In_ uint32_t Version // Either Byte Order
    )
{
    return (Version & QUIC_VERSION_RESERVED_MASK) == QUIC_VERSION_RESERVED;
}
