/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.

--*/

#pragma once

#define _CRT_SECURE_NO_WARNINGS 1

#include <msquichelper.h>

#include "PingStream.h"
#include "PingConnection.h"

//
// QUIC API Function Table.
//
extern QUIC_API_V1* MsQuic;

//
// Registration context.
//
extern HQUIC Registration;

//
// Security configuration for server.
//
extern QUIC_SEC_CONFIG* SecurityConfig;

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

    char RawALPN[256];
    QUIC_BUFFER ALPN;
    QUIC_ADDR LocalIpAddr;

    uint32_t DisconnectTimeout; // Milliseconds
    uint64_t IdleTimeout;       // Milliseconds

    uint64_t LocalUnidirStreamCount;    // Total
    uint64_t LocalBidirStreamCount;     // Total
    uint16_t PeerUnidirStreamCount;     // Max simultaneous
    uint16_t PeerBidirStreamCount;      // Max simultaneous

    uint64_t MaxBytesPerKey;            // Max bytes per key

    uint64_t StreamPayloadLength;

    uint32_t IoSize;
    uint32_t IoCount;

    struct {
        bool UseExplicitRemoteAddr : 1;
        char Target[256];           // SNI
        QUIC_ADDR RemoteIpAddr;
        uint32_t Version;           // QUIC protocol version
        char ResumeToken[256];
        uint32_t ConnectionCount;
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

//
// Starts the server at the local address and waits for clients until a key is pressed.
//
void QuicPingServerRun();

//
// Connects the client to the remote host.
//
void QuicPingClientRun();

