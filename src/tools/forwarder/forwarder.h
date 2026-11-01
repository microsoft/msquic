/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.

--*/

#pragma once

#include "msquic.h"
#include <new>
#include <stdlib.h>
#include <string.h>

struct ForwardedSend {
    uint64_t TotalLength;
    uint32_t BufferCount;
    bool Buffered;
    QUIC_BUFFER Buffers[3];

    static ForwardedSend* New(const QUIC_STREAM_EVENT* Event, bool BufferedMode) {
        if (BufferedMode) {
            auto SendContext = (ForwardedSend*)malloc(sizeof(ForwardedSend) + (size_t)Event->RECEIVE.TotalBufferLength);
            SendContext->TotalLength = Event->RECEIVE.TotalBufferLength;
            SendContext->BufferCount = 1;
            SendContext->Buffered = true;
            SendContext->Buffers[0].Buffer = (uint8_t*)SendContext + sizeof(ForwardedSend);
            SendContext->Buffers[0].Length = 0;
            for (uint32_t i = 0; i < Event->RECEIVE.BufferCount; ++i) {
                memcpy(
                    SendContext->Buffers[0].Buffer + SendContext->Buffers[0].Length,
                    Event->RECEIVE.Buffers[i].Buffer,
                    Event->RECEIVE.Buffers[i].Length);
                SendContext->Buffers[0].Length += Event->RECEIVE.Buffers[i].Length;
            }
            return SendContext;
        }
        auto SendContext = new(std::nothrow) ForwardedSend;
        SendContext->TotalLength = Event->RECEIVE.TotalBufferLength;
        SendContext->BufferCount = Event->RECEIVE.BufferCount;
        SendContext->Buffered = false;
        for (uint32_t i = 0; i < Event->RECEIVE.BufferCount; ++i) {
            SendContext->Buffers[i].Length = Event->RECEIVE.Buffers[i].Length;
            SendContext->Buffers[i].Buffer = Event->RECEIVE.Buffers[i].Buffer;
        }
        return SendContext;
    }

    static void Delete(ForwardedSend* SendContext) {
        if (SendContext->Buffered) { free(SendContext); }
        else { delete SendContext; }
    }
};
