/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.

Abstract:

    QUIC PING Client Implementation. Supports connecting to a remote QUIC
    endpoint and sending a variable length payload of semi-random data. It
    then waits for the remote to acknowledge the data via closing the stream.
    The remote may or may not echo the payload.

--*/

#include "QuicPing.h"

struct QuicConfigurationPtr {
    HQUIC Handle {nullptr};
    ~QuicConfigurationPtr() { MsQuic->ConfigurationClose(Handle); }
};

void QuicPingClientRun()
{
    PingTracker Tracker;
    bool Timeout = true;
    {
        QUIC_SETTINGS Settings{0};
        Settings.IdleTimeoutMs = PingConfig.IdleTimeout;
        Settings.IsSet.IdleTimeoutMs = TRUE;
        Settings.DisconnectTimeoutMs = PingConfig.DisconnectTimeout;
        Settings.IsSet.DisconnectTimeoutMs = TRUE;
        Settings.DatagramReceiveEnabled = TRUE;
        Settings.IsSet.DatagramReceiveEnabled = TRUE;
        if (!PingConfig.UseSendBuffer) {
            Settings.SendBufferingEnabled = FALSE;
            Settings.IsSet.SendBufferingEnabled = TRUE;
        }
        if (!PingConfig.UsePacing) {
            Settings.PacingEnabled = FALSE;
            Settings.IsSet.PacingEnabled = TRUE;
        }
        if (PingConfig.MaxBytesPerKey != UINT64_MAX) {
            Settings.MaxBytesPerKey = PingConfig.MaxBytesPerKey;
            Settings.IsSet.MaxBytesPerKey = TRUE;
        }
        if (PingConfig.PeerBidirStreamCount != 0) {
            Settings.PeerBidiStreamCount = PingConfig.PeerBidirStreamCount;
            Settings.IsSet.PeerBidiStreamCount = TRUE;
        }
        if (PingConfig.PeerUnidirStreamCount != 0) {
            Settings.PeerUnidiStreamCount = PingConfig.PeerUnidirStreamCount;
            Settings.IsSet.PeerUnidiStreamCount = TRUE;
        }

        QuicConfigurationPtr ClientConfiguration;
        if (QUIC_FAILED(
            MsQuic->ConfigurationOpen(
                Registration,
                &PingConfig.ALPN,
                1,
                &Settings,
                sizeof(Settings),
                nullptr,
                &ClientConfiguration.Handle))) {
            printf("MsQuic->ConfigurationOpen failed!\n");
            return;
        }

        QUIC_CREDENTIAL_CONFIG CredConfig;
        QuicZeroMemory(&CredConfig, sizeof(CredConfig));
        CredConfig.Type = QUIC_CREDENTIAL_TYPE_NONE;
        CredConfig.Flags = QUIC_CREDENTIAL_FLAG_CLIENT | QUIC_CREDENTIAL_FLAG_NO_CERTIFICATE_VALIDATION;
        if (QUIC_FAILED(
            MsQuic->ConfigurationLoadCredential(
                ClientConfiguration.Handle,
                &CredConfig))) {
            printf("MsQuic->ConfigurationLoadCredential failed!\n");
            return;
        }

        auto Connections = new PingConnection*[PingConfig.ConnectionCount];
        for (uint32_t i = 0; i < PingConfig.ConnectionCount; i++) {
            Connections[i] =
                new PingConnection(
                    &Tracker,
                    PingConfig.ConnectionCount == 1);
            if (!Connections[i]) {
                printf("Failed to open a connection!\n");
                return;
            }

            if (!Connections[i]->Initialize(false)) {
                return;
            }
        }

        Tracker.Start();

        //
        // Start connecting to the remote server.
        //
        for (uint32_t i = 0; i < PingConfig.ConnectionCount; i++) {
            Connections[i]->Connect(ClientConfiguration.Handle);
        }

        delete[] Connections;

        if (Tracker.Wait(PingConfig.Client.WaitTimeout)) {
            printf("Cancelling remaining connections.\n");
            MsQuic->RegistrationShutdown(Registration, QUIC_CONNECTION_SHUTDOWN_FLAG_NONE, 0);
            Timeout = false; // Connections didn't hit idle timeout. They were cancelled.
        }
    }

    if (PingConfig.ConnectionCount > 1 &&
        (Tracker.BytesSent != 0 || Tracker.BytesReceived != 0)) {
        uint64_t ElapsedMicroseconds = Tracker.CompleteTime - Tracker.StartTime;
        if (Timeout) {
            ElapsedMicroseconds -= DEFAULT_IDLE_TIMEOUT * 1000;
        }

        uint32_t SendRate = (uint32_t)((Tracker.BytesSent * 1000 * 1000 * 8) / (1000 * ElapsedMicroseconds));
        uint32_t RecvRate = (uint32_t)((Tracker.BytesReceived * 1000 * 1000 * 8) / (1000 * ElapsedMicroseconds));

        printf("Total rate after %u.%u ms. (TX %llu bytes @ %u kbps | RX %llu bytes @ %u kbps).\n",
            (uint32_t)(ElapsedMicroseconds / 1000),
            (uint32_t)(ElapsedMicroseconds % 1000),
            (unsigned long long)Tracker.BytesSent, SendRate,
            (unsigned long long)Tracker.BytesReceived, RecvRate);
    }
}
