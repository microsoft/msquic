/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.

Abstract:

    QUIC Debugger Extension Command 'analyze'. This command is for analyzing
    possible issues on a QUIC handle.

--*/

#include "quictypes.h"

EXT_COMMAND(
    quicanalyze,
    "Analyze issues of a handle",
    "{;e,r;addr;The address of the handle}"
    )
{
    QuicHandle Handle(GetUnnamedArgU64(0));
    auto Type = Handle.Type();

    if (Type == QUIC_HANDLE_TYPE_CONNECTION_CLIENT ||
        Type == QUIC_HANDLE_TYPE_CONNECTION_SERVER) {
        AnalyzeConnection(Handle.Addr);
    } else if (Type == QUIC_HANDLE_TYPE_STREAM) {
        AnalyzeStream(Handle.Addr);
    } else {
        Dml("Not supported for handle type: %s", Handle.TypeStr());
    }

    Dml("\n");
}

void EXT_CLASS::AnalyzeConnection(UINT64 Addr)
{
    Connection Conn(Addr);

    QUIC_CONNECTION_STATE state = Conn.State();
    if (state.Freed) {
        Dml("The connection has been freed.\n");
    } else if (state.HandleClosed) {
        Dml("The connection has been closed by the application and is in the process of being deleted.\n");
    } else if (state.ShutdownComplete) {
        Dml("The connection has completed the shutdown process.\n");
    } else if (state.ClosedLocally || state.ClosedRemotely) {
        Dml("The connection is in the process of shutting down.");
        if (state.ClosedLocally) {
            Dml(" It has been closed locally.");
        }
        if (state.ClosedRemotely) {
            Dml(" It has been closed remotely.");
        }
        Dml("\n");
    } else if (state.Connected) {
        Dml("The connection is connected.\n");
    } else if (state.Started) {
        Dml("The connection is in the process of performing the handshake.\n");
    } else if (state.Initialized) {
        Dml("The connection has been allocated and successfully initialized.\n");
    } else if (state.Allocated) {
        Dml("The connection has been allocated.\n");
    } else {
        Dml("The connection is invalid.\n");
    }

    //
    // TODO ...
    //
}

void EXT_CLASS::AnalyzeStream(UINT64 Addr)
{
    Stream Strm(Addr);

    QUIC_STREAM_FLAGS flags = Strm.Flags();
    if (flags.Freed) {
        Dml("The stream has been freed.\n");
    } else if (flags.HandleClosed) {
        Dml("The stream has been closed by the application.\n");
    } else if (flags.HandleShutdown) {
        Dml("The stream has completed the shutdown process and is ready to be closed by the application.\n");
    } else {
        auto LocallyClosed = flags.LocalCloseFin || flags.LocalCloseReset;
        auto RemotelyClosed = flags.RemoteCloseFin || flags.RemoteCloseReset;

        if (RemotelyClosed) {
            if (flags.RemoteCloseAcked) {
                Dml("The stream's receive pipe has been closed and acknowledged.\n");
            } else {
                Dml("The stream's receive pipe has been closed but not yet acknowledged.\n");
            }
        } else {
            Dml("The stream's receive pipe is open.\n");
        }

        if (LocallyClosed) {
            if (flags.LocalCloseAcked) {
                Dml("The stream's send pipe has been closed and acknowledged.\n");
            } else {
                Dml("The stream's send pipe has been closed but not yet acknowledged.\n");
            }
        } else {
            Dml("The stream's send pipe is open.\n");
        }
    }

    UINT32 SendRequestsCount = 0;
    ULONG64 SendRequestsPtr = Strm.SendRequests();
    while (SendRequestsPtr != 0) {
        SendRequest Request(SendRequestsPtr);
        SendRequestsPtr = Request.Next();
        SendRequestsCount++;
    }
    Dml("The stream has %u send requests pending.\n", SendRequestsCount);
}
