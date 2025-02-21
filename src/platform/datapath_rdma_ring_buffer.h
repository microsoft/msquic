/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.

--*/

#pragma once

#define QUIC_API_ENABLE_PREVIEW_FEATURES 1

#include "platform_internal.h"

//
// RDMA Ring Buffer
//
typedef struct _RDMA_NDSPI_SEND_RING_BUFFER
{
    void*  Buffer;
    size_t Size;
    size_t Head;
    size_t Tail;
    
} RDMA_SEND_RING_BUFFER, *PRDMA_SEND_RING_BUFFER;

typedef struct _RDMA_NDSPI_RECV_RING_BUFFER
{
    void*   Buffer;
    void *  OffsetBuffer; 
    size_t  Size;
    size_t  Head;
    size_t  Tail;
} RDMA_RECV_RING_BUFFER, *PRDMA_RECV_RING_BUFFER;