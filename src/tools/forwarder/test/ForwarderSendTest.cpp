/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.

--*/

#include "forwarder.h"

int main() {
    uint8_t First[] = {'a', 'b'};
    uint8_t Second[] = {'c', 'd', 'e'};
    QUIC_BUFFER ReceiveBuffers[] = {{sizeof(First), First}, {sizeof(Second), Second}};
    QUIC_STREAM_EVENT Event = {};
    Event.Type = QUIC_STREAM_EVENT_RECEIVE;
    Event.RECEIVE.BufferCount = 2;
    Event.RECEIVE.Buffers = ReceiveBuffers;
    Event.RECEIVE.TotalBufferLength = sizeof(First) + sizeof(Second);

    auto BufferedSend = ForwardedSend::New(&Event, true);
    const bool BufferedValid =
        BufferedSend != nullptr &&
        BufferedSend->BufferCount == 1 &&
        BufferedSend->TotalLength == Event.RECEIVE.TotalBufferLength &&
        BufferedSend->Buffers[0].Length == Event.RECEIVE.TotalBufferLength &&
        memcmp(BufferedSend->Buffers[0].Buffer, "abcde", 5) == 0;
    if (BufferedSend != nullptr) { ForwardedSend::Delete(BufferedSend); }
    if (!BufferedValid) { return 1; }

    auto UnbufferedSend = ForwardedSend::New(&Event, false);
    const bool UnbufferedValid =
        UnbufferedSend != nullptr &&
        UnbufferedSend->BufferCount == 2 &&
        UnbufferedSend->TotalLength == Event.RECEIVE.TotalBufferLength &&
        UnbufferedSend->Buffers[0].Buffer == First &&
        UnbufferedSend->Buffers[0].Length == sizeof(First) &&
        UnbufferedSend->Buffers[1].Buffer == Second &&
        UnbufferedSend->Buffers[1].Length == sizeof(Second);
    if (UnbufferedSend != nullptr) { ForwardedSend::Delete(UnbufferedSend); }
    return UnbufferedValid ? 0 : 1;
}
