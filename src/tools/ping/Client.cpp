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

void QuicPingClientRun()
{
    PingTracker Tracker;
    bool Timeout = true;
    {
        QuicSession Session;
        if (QUIC_FAILED(
            MsQuic->SessionOpen(
                Registration,
                &PingConfig.ALPN,
                1,
                NULL,
                &Session.Handle))) {
            printf("MsQuic->SessionOpen failed!\n");
            return;
        }
        if (PingConfig.MaxBytesPerKey != UINT64_MAX &&
            QUIC_FAILED(
            MsQuic->SetParam(
                Session.Handle,
                QUIC_PARAM_LEVEL_SESSION,
                QUIC_PARAM_SESSION_MAX_BYTES_PER_KEY,
                sizeof(uint64_t),
                &PingConfig.MaxBytesPerKey))) {
            printf("MsQuic.SetParam (SESSION_MAX_BYTES_PER_KEY) failed!\n");
            return;
        }

        auto Connections = new PingConnection*[PingConfig.ConnectionCount];
        for (uint32_t i = 0; i < PingConfig.ConnectionCount; i++) {
            Connections[i] =
                new PingConnection(
                    &Tracker,
                    Session.Handle,
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
            Connections[i]->Connect();
        }

        delete[] Connections;

        if (Tracker.Wait(PingConfig.Client.WaitTimeout)) {
            printf("Cancelling remaining connections.\n");
            Session.Cancel();
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
            Tracker.BytesSent, SendRate, Tracker.BytesReceived, RecvRate);
    }
}
