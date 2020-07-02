/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.

--*/

#pragma once

#define _CRT_SECURE_NO_WARNINGS 1
#define QUIC_TEST_APIS 1 // Needed for self signed cert API
#include <msquichelper.h>

//
// QUIC API Function Table.
//
extern const QUIC_API_TABLE* MsQuic;

//
// Registration context.
//
extern HQUIC Registration;

//
// Security configuration for server.
//
extern QUIC_SEC_CONFIG* SecurityConfig;

//
// Raw byte buffer for sending.
//
extern uint8_t* QuicPingRawIoBuffer;

//
// The protocol name used for QuicPing
//
#define DEFAULT_ALPN "ping"

//
// The default port used for connecting with QuicPing.
//
#define DEFAULT_PORT 433

//
// QuicPing defaults to using encryption.
//
#define DEFAULT_USE_ENCRYPTION 1

//
// QuicPing defaults to using send buffering.
//
#define DEFAULT_USE_SEND_BUF 1

//
// QuicPing defaults to using send pacing.
//
#define DEFAULT_USE_PACING 1

//
// QuicPing defaults not printing connection statistics.
//
#define DEFAULT_PRINT_STATISTICS 0

//
// QuicPing defaults to the low latency profile.
//
#define DEFAULT_EXECUTION_PROFILE QUIC_EXECUTION_PROFILE_LOW_LATENCY

//
// The default connection count count.
//
#define DEFAULT_CLIENT_CONNECTION_COUNT 1

//
// The default size of a single send IO, and how many to keep outstanding,
// when buffered sends are disabled.
//
#define DEFAULT_SEND_IO_SIZE_NONBUFFERED 0x100000
#define DEFAULT_SEND_COUNT_NONBUFFERED 8

//
// The default size of a single send IO, and how many to keep outstanding,
// when buffered sends are enabled.
//
#define DEFAULT_SEND_IO_SIZE_BUFFERED 0x10000
#define DEFAULT_SEND_COUNT_BUFFERED 1

//
// The default payload length of datagrams.
//
#define DEFAULT_DATAGRAM_MAX_LENGTH UINT16_MAX // Use connection max

//
// The disconnect timeout (in milliseconds) used.
//
#define DEFAULT_DISCONNECT_TIMEOUT (10 * 1000)

//
// The idle timeout (in milliseconds) used.
//
#define DEFAULT_IDLE_TIMEOUT 1000

//
// The amount of time (in milliseconds) the app will wait for completion.
//
#define DEFAULT_WAIT_TIMEOUT (60 * 60 * 1000)

typedef struct QUIC_PING_CONFIG {

    bool ServerMode    : 1;
    bool UseEncryption : 1;
    bool UseSendBuffer : 1;
    bool UsePacing     : 1;
    bool PrintStats    : 1;

    QUIC_BUFFER ALPN;
    QUIC_ADDR LocalIpAddr;

    uint32_t DisconnectTimeout; // Milliseconds
    uint64_t IdleTimeout;       // Milliseconds

    uint64_t LocalUnidirStreamCount;    // Total
    uint64_t LocalBidirStreamCount;     // Total
    uint64_t LocalDatagramCount;        // Total
    uint16_t PeerUnidirStreamCount;     // Max simultaneous
    uint16_t PeerBidirStreamCount;      // Max simultaneous

    uint64_t MaxBytesPerKey;            // Max bytes per key

    uint64_t StreamPayloadLength;
    uint16_t DatagramMaxLength;

    uint32_t IoSize;
    uint32_t IoCount;

    uint32_t ConnectionCount;

    struct {
        bool UseExplicitRemoteAddr : 1;
        const char* Target;         // SNI
        QUIC_ADDR RemoteIpAddr;
        uint32_t Version;           // QUIC protocol version
        const char* ResumeToken;
        uint32_t WaitTimeout;       // Milliseconds
    } Client;

} QUIC_PING_CONFIG;

extern QUIC_PING_CONFIG PingConfig;

struct QuicSession
{
    HQUIC Handle;
    QuicSession() : Handle(nullptr) {}
    ~QuicSession() { if (Handle != nullptr) { MsQuic->SessionClose(Handle); } }
    void Cancel() {
        MsQuic->SessionShutdown(Handle, QUIC_CONNECTION_SHUTDOWN_FLAG_SILENT, 0);
    }
};

struct PingSendRequest {

    QUIC_SEND_FLAGS Flags;
    QUIC_BUFFER QuicBuffer;
    bool DeleteBufferOnDestruction;

    PingSendRequest(
        ) {
        DeleteBufferOnDestruction = false;
        Flags = QUIC_SEND_FLAG_ALLOW_0_RTT;
        QuicBuffer.Buffer = QuicPingRawIoBuffer;
        QuicBuffer.Length = 0;
    }

    PingSendRequest(
        const uint8_t * buffer,
        uint32_t bufferSize
        ) {
        DeleteBufferOnDestruction = true;
        Flags = QUIC_SEND_FLAG_NONE;
        QuicBuffer.Buffer = new uint8_t[bufferSize];
        QuicBuffer.Length = bufferSize;
        if (buffer) {
            memcpy((uint8_t*)QuicBuffer.Buffer, buffer, bufferSize);
        }
    }

    void SetLength(uint64_t BytesLeftToSend) {
        if (BytesLeftToSend > PingConfig.IoSize) {
            QuicBuffer.Length = PingConfig.IoSize;
        } else {
            Flags |= QUIC_SEND_FLAG_FIN;
            QuicBuffer.Length = (uint32_t)BytesLeftToSend;
        }
    }

    ~PingSendRequest(
        ) {
        if (DeleteBufferOnDestruction) {
            delete[] QuicBuffer.Buffer;
        }
    }
};

//
// Starts the server at the local address and waits for clients until a key is pressed.
//
void QuicPingServerRun();

//
// Connects the client to the remote host.
//
void QuicPingClientRun();

#include "PingStream.h"
#include "PingConnection.h"
