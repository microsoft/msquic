/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.

Abstract:

    Consumes an XSKMAP handle duplicated from another process. Creates XSK
    sockets, inserts them into the map, and receives packets.

    Usage:
        1. Run: xdpmapconsumer.exe -IfIndex <N> -QueueCount <N>
        2. Note the printed PID
        3. In another terminal, run: xdpmapcreator.exe -TargetPid <PID>
        4. Paste the remote handle value printed by the creator into this console
        5. The consumer creates per-queue XSKs, inserts them into the map,
           and starts receiving packets.

    The creator owns the map and the XDP program; the consumer only inserts
    its XSK sockets and drains received frames.

--*/

#define _CRT_SECURE_NO_WARNINGS 1
#define XDP_API_VERSION 3
#define XDP_INCLUDE_WINCOMMON

#pragma warning(disable:5105)
#include <xdp/wincommon.h>
#include <stdio.h>
#include <stdlib.h>

#include <xdpapi.h>
#include <afxdp.h>
#include <afxdp_helper.h>

#define LOGERR(...) \
    fprintf(stderr, "ERR: "); fprintf(stderr, __VA_ARGS__); fprintf(stderr, "\n")

#define RX_RING_SIZE 64
#define FRAME_SIZE 2048

typedef struct _QUEUE_CONTEXT {
    HANDLE Socket;
    XSK_RING RxRing;
    XSK_RING RxFillRing;
    UCHAR *Umem;
    UINT64 PacketsReceived;
    UINT64 BytesReceived;
} QUEUE_CONTEXT;

static UINT32 IfIndex;
static UINT32 QueueCount;

static void
PrintUsage(void)
{
    printf(
        "xdpmapconsumer.exe -IfIndex <N> -QueueCount <N>\n"
        "\n"
        "Receives an XSKMAP handle from xdpmapcreator, creates per-queue\n"
        "XSK sockets, inserts them into the map, and receives packets.\n"
        "\n"
        "OPTIONS:\n"
        "   -IfIndex <N>       Network interface index to bind XSKs to (required)\n"
        "   -QueueCount <N>    Number of RSS queues to cover (required, 1-128)\n"
    );
}

static BOOLEAN
ParseArgs(
    int ArgC,
    char** ArgV
    )
{
    int i = 1;
    IfIndex = MAXUINT32;
    QueueCount = 0;

    while (i < ArgC) {
        if (!_stricmp(ArgV[i], "-IfIndex")) {
            if (++i >= ArgC) {
                LOGERR("Missing IfIndex value");
                return FALSE;
            }
            IfIndex = (UINT32)atoi(ArgV[i]);
        } else if (!_stricmp(ArgV[i], "-QueueCount")) {
            if (++i >= ArgC) {
                LOGERR("Missing QueueCount value");
                return FALSE;
            }
            QueueCount = (UINT32)atoi(ArgV[i]);
            if (QueueCount == 0 || QueueCount > 128) {
                LOGERR("QueueCount must be between 1 and 128");
                return FALSE;
            }
        } else {
            LOGERR("Unexpected parameter \"%s\"", ArgV[i]);
            return FALSE;
        }
        ++i;
    }

    if (IfIndex == MAXUINT32) {
        LOGERR("-IfIndex is required");
        return FALSE;
    }
    if (QueueCount == 0) {
        LOGERR("-QueueCount is required");
        return FALSE;
    }
    return TRUE;
}

static XDP_STATUS
SetupQueueSocket(
    _In_ UINT32 QueueId,
    _Inout_ QUEUE_CONTEXT *Ctx
    )
{
    XDP_STATUS XdpStatus;
    XSK_UMEM_REG UmemReg = {0};
    UINT32 RingSize = RX_RING_SIZE;
    XSK_RING_INFO_SET RingInfo;
    UINT32 OptionLength;
    UINT32 FillIndex;

    Ctx->PacketsReceived = 0;
    Ctx->BytesReceived = 0;

    Ctx->Umem = (UCHAR *)calloc(RX_RING_SIZE, FRAME_SIZE);
    if (Ctx->Umem == NULL) {
        LOGERR("Failed to allocate UMEM for queue %u", QueueId);
        return E_OUTOFMEMORY;
    }

    XdpStatus = XskCreate(&Ctx->Socket);
    if (FAILED(XdpStatus)) {
        LOGERR("XskCreate failed for queue %u: %x", QueueId, XdpStatus);
        return XdpStatus;
    }

    UmemReg.TotalSize = (UINT32)RX_RING_SIZE * FRAME_SIZE;
    UmemReg.ChunkSize = FRAME_SIZE;
    UmemReg.Address = Ctx->Umem;

    XdpStatus = XskSetSockopt(Ctx->Socket, XSK_SOCKOPT_UMEM_REG, &UmemReg, sizeof(UmemReg));
    if (FAILED(XdpStatus)) {
        LOGERR("XSK_SOCKOPT_UMEM_REG failed for queue %u: %x", QueueId, XdpStatus);
        return XdpStatus;
    }

    XdpStatus = XskBind(Ctx->Socket, IfIndex, QueueId, XSK_BIND_FLAG_RX);
    if (FAILED(XdpStatus)) {
        LOGERR("XskBind failed for queue %u: %x", QueueId, XdpStatus);
        return XdpStatus;
    }

    XdpStatus = XskSetSockopt(Ctx->Socket, XSK_SOCKOPT_RX_RING_SIZE, &RingSize, sizeof(RingSize));
    if (FAILED(XdpStatus)) {
        LOGERR("XSK_SOCKOPT_RX_RING_SIZE failed for queue %u: %x", QueueId, XdpStatus);
        return XdpStatus;
    }

    XdpStatus = XskSetSockopt(Ctx->Socket, XSK_SOCKOPT_RX_FILL_RING_SIZE, &RingSize, sizeof(RingSize));
    if (FAILED(XdpStatus)) {
        LOGERR("XSK_SOCKOPT_RX_FILL_RING_SIZE failed for queue %u: %x", QueueId, XdpStatus);
        return XdpStatus;
    }

    XdpStatus = XskActivate(Ctx->Socket, XSK_ACTIVATE_FLAG_NONE);
    if (FAILED(XdpStatus)) {
        LOGERR("XskActivate failed for queue %u: %x", QueueId, XdpStatus);
        return XdpStatus;
    }

    OptionLength = sizeof(RingInfo);
    XdpStatus = XskGetSockopt(Ctx->Socket, XSK_SOCKOPT_RING_INFO, &RingInfo, &OptionLength);
    if (FAILED(XdpStatus)) {
        LOGERR("XSK_SOCKOPT_RING_INFO failed for queue %u: %x", QueueId, XdpStatus);
        return XdpStatus;
    }

    XskRingInitialize(&Ctx->RxRing, &RingInfo.Rx);
    XskRingInitialize(&Ctx->RxFillRing, &RingInfo.Fill);

    XskRingProducerReserve(&Ctx->RxFillRing, RX_RING_SIZE, &FillIndex);
    for (UINT32 j = 0; j < RX_RING_SIZE; j++) {
        *(UINT64 *)XskRingGetElement(&Ctx->RxFillRing, FillIndex + j) =
            (UINT64)j * FRAME_SIZE;
    }
    XskRingProducerSubmit(&Ctx->RxFillRing, RX_RING_SIZE);

    return S_OK;
}

static void
PrintStats(
    _In_ QUEUE_CONTEXT *Queues,
    _In_ UINT32 Count
    )
{
    UINT64 TotalPackets = 0;
    UINT64 TotalBytes = 0;

    printf("\n--- RX Stats ---\n");
    for (UINT32 i = 0; i < Count; i++) {
        printf("  Queue %2u: %8llu pkts  %12llu bytes\n",
            i, Queues[i].PacketsReceived, Queues[i].BytesReceived);
        TotalPackets += Queues[i].PacketsReceived;
        TotalBytes += Queues[i].BytesReceived;
    }
    printf("  Total:    %8llu pkts  %12llu bytes\n", TotalPackets, TotalBytes);
    printf("----------------\n");
}

int
__cdecl
main(
    int argc,
    char** argv
    )
{
    UINT_PTR HandleValue;
    HANDLE XskMap;
    QUEUE_CONTEXT *Queues = NULL;
    XDP_STATUS XdpStatus;
    char InputBuf[64];

    if (!ParseArgs(argc, argv)) {
        PrintUsage();
        return 1;
    }

    printf("=== XSKMAP Consumer ===\n");
    printf("My PID: %u\n", GetCurrentProcessId());
    printf("IfIndex: %u, QueueCount: %u\n", IfIndex, QueueCount);
    printf("\n");
    printf("Start xdpmapcreator.exe -TargetPid %u in another terminal,\n",
        GetCurrentProcessId());
    printf("then paste the remote handle value here.\n");
    printf("\n");
    printf("Handle value (hex): ");
    fflush(stdout);

    if (fgets(InputBuf, sizeof(InputBuf), stdin) == NULL) {
        LOGERR("Failed to read input");
        return 1;
    }

    HandleValue = (UINT_PTR)_strtoui64(InputBuf, NULL, 16);
    if (HandleValue == 0 || HandleValue == (UINT_PTR)INVALID_HANDLE_VALUE) {
        LOGERR("Invalid handle value: %s", InputBuf);
        return 1;
    }

    XskMap = (HANDLE)HandleValue;
    printf("Received XSKMAP handle: 0x%IX\n", (UINT_PTR)XskMap);

    //
    // Create per-queue XSK sockets and insert them into the map.
    //
    Queues = (QUEUE_CONTEXT *)calloc(QueueCount, sizeof(QUEUE_CONTEXT));
    if (Queues == NULL) {
        LOGERR("Failed to allocate queue context array");
        return 1;
    }

    for (UINT32 i = 0; i < QueueCount; i++) {
        XdpStatus = SetupQueueSocket(i, &Queues[i]);
        if (FAILED(XdpStatus)) {
            return 1;
        }

        XdpStatus = XdpMapInsert(XskMap, &i, &Queues[i].Socket);
        if (FAILED(XdpStatus)) {
            LOGERR("XdpMapInsert failed for queue %u: %x", i, XdpStatus);
            return 1;
        }

        printf("Queue %u: XSK created, bound, activated, inserted into map\n", i);
    }

    printf("\nReceiving packets... (Ctrl+C to stop)\n");

    //
    // Poll all queues for received packets, print stats every second.
    //
    ULONGLONG LastPrintTick = GetTickCount64();

    for (;;) {
        ULONGLONG Now = GetTickCount64();
        if (Now - LastPrintTick >= 1000) {
            PrintStats(Queues, QueueCount);
            LastPrintTick = Now;
        }

        for (UINT32 q = 0; q < QueueCount; q++) {
            QUEUE_CONTEXT *Ctx = &Queues[q];
            UINT32 RxIndex;
            UINT32 Available = XskRingConsumerReserve(&Ctx->RxRing, RX_RING_SIZE, &RxIndex);

            for (UINT32 j = 0; j < Available; j++) {
                XSK_BUFFER_DESCRIPTOR *Desc =
                    (XSK_BUFFER_DESCRIPTOR *)XskRingGetElement(&Ctx->RxRing, RxIndex + j);
                Ctx->PacketsReceived++;
                Ctx->BytesReceived += Desc->Length;
            }

            if (Available > 0) {
                XskRingConsumerRelease(&Ctx->RxRing, Available);

                UINT32 FillIndex;
                UINT32 Filled = XskRingProducerReserve(&Ctx->RxFillRing, Available, &FillIndex);
                for (UINT32 j = 0; j < Filled; j++) {
                    *(UINT64 *)XskRingGetElement(&Ctx->RxFillRing, FillIndex + j) =
                        (UINT64)((RxIndex + j) % RX_RING_SIZE) * FRAME_SIZE;
                }
                XskRingProducerSubmit(&Ctx->RxFillRing, Filled);
            }
        }
    }
}
