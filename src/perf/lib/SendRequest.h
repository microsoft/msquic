/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.

Abstract:

    QUIC Perf Send Request Wrapper.

--*/

#pragma once

#include "PerfHelpers.h"

struct SendRequest {
    QUIC_SEND_FLAGS Flags {QUIC_SEND_FLAG_NONE};
    QUIC_BUFFER QuicBuffer;
    QuicPoolBufferAllocator* BufferAllocator;
    uint32_t IoSize;
    SendRequest(
        QuicPoolBufferAllocator* BufferAllocator,
        uint32_t IoSize,
        bool FillBuffer
        ) {
        this->BufferAllocator = BufferAllocator;
        this->IoSize = IoSize;
        QuicBuffer.Buffer = BufferAllocator->Alloc();
        if (FillBuffer) {
            memset(QuicBuffer.Buffer, 0xBF, IoSize);
        }
        QuicBuffer.Length = 0;
    }

    ~SendRequest() {
        BufferAllocator->Free(QuicBuffer.Buffer);
    }

    void SetLength(
        uint64_t BytesLeftToSend
        ) {
        if (BytesLeftToSend > IoSize) {
            QuicBuffer.Length = IoSize;
        } else {
            Flags |= QUIC_SEND_FLAG_FIN;
            QuicBuffer.Length = (uint32_t)BytesLeftToSend;
        }
    }
};
