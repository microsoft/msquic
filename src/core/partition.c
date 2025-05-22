/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.

--*/

#include "precomp.h"
#ifdef QUIC_CLOG
#include "partition.c.clog.h"
#endif

QUIC_STATUS
QuicPartitionInitialize(
    _Inout_ QUIC_PARTITION* Partition,
    _In_ uint16_t Index,
    _In_ uint16_t Processor,
    _In_ CXPLAT_HASH_TYPE HashType,
    _In_reads_(ResetHashKeyLength)
        const uint8_t* const ResetHashKey,
    _In_ uint32_t ResetHashKeyLength
    )
{
    QUIC_STATUS Status =
        CxPlatHashCreate(
            HashType,
            ResetHashKey,
            ResetHashKeyLength,
            &Partition->ResetTokenHash);
    if (QUIC_FAILED(Status)) {
        return Status;
    }

    Partition->Index = Index;
    Partition->Processor = Processor;
    CxPlatPoolInitialize(FALSE, sizeof(QUIC_CONNECTION), QUIC_POOL_CONN, &Partition->ConnectionPool);
    CxPlatPoolInitialize(FALSE, sizeof(QUIC_TRANSPORT_PARAMETERS), QUIC_POOL_TP, &Partition->TransportParamPool);
    CxPlatPoolInitialize(FALSE, sizeof(QUIC_PACKET_SPACE), QUIC_POOL_TP, &Partition->PacketSpacePool);
    CxPlatPoolInitialize(FALSE, sizeof(QUIC_STREAM), QUIC_POOL_STREAM, &Partition->StreamPool);
    CxPlatPoolInitialize(FALSE, sizeof(QUIC_RECV_CHUNK)+QUIC_DEFAULT_STREAM_RECV_BUFFER_SIZE, QUIC_POOL_SBUF, &Partition->DefaultReceiveBufferPool);
    CxPlatPoolInitialize(FALSE, sizeof(QUIC_SEND_REQUEST), QUIC_POOL_SEND_REQUEST, &Partition->SendRequestPool);
    QuicSentPacketPoolInitialize(&Partition->SentPacketPool);
    CxPlatPoolInitialize(FALSE, sizeof(QUIC_API_CONTEXT), QUIC_POOL_API_CTX, &Partition->ApiContextPool);
    CxPlatPoolInitialize(FALSE, sizeof(QUIC_STATELESS_CONTEXT), QUIC_POOL_STATELESS_CTX, &Partition->StatelessContextPool);
    CxPlatPoolInitialize(FALSE, sizeof(QUIC_OPERATION), QUIC_POOL_OPER, &Partition->OperPool);
    CxPlatPoolInitialize(FALSE, sizeof(QUIC_RECV_CHUNK), QUIC_POOL_APP_BUFFER_CHUNK, &Partition->AppBufferChunkPool);
    CxPlatLockInitialize(&Partition->ResetTokenLock);
    CxPlatDispatchLockInitialize(&Partition->StatelessRetryKeysLock);

    return QUIC_STATUS_SUCCESS;
}

void
QuicPartitionUninitialize(
    _Inout_ QUIC_PARTITION* Partition
    )
{
    for (size_t i = 0; i < ARRAYSIZE(Partition->StatelessRetryKeys); ++i) {
        CxPlatKeyFree(Partition->StatelessRetryKeys[i].Key);
    }
    CxPlatPoolUninitialize(&Partition->ConnectionPool);
    CxPlatPoolUninitialize(&Partition->TransportParamPool);
    CxPlatPoolUninitialize(&Partition->PacketSpacePool);
    CxPlatPoolUninitialize(&Partition->StreamPool);
    CxPlatPoolUninitialize(&Partition->DefaultReceiveBufferPool);
    CxPlatPoolUninitialize(&Partition->SendRequestPool);
    QuicSentPacketPoolUninitialize(&Partition->SentPacketPool);
    CxPlatPoolUninitialize(&Partition->ApiContextPool);
    CxPlatPoolUninitialize(&Partition->StatelessContextPool);
    CxPlatPoolUninitialize(&Partition->OperPool);
    CxPlatPoolUninitialize(&Partition->AppBufferChunkPool);
    CxPlatLockUninitialize(&Partition->ResetTokenLock);
    CxPlatDispatchLockUninitialize(&Partition->StatelessRetryKeysLock);
    CxPlatHashFree(Partition->ResetTokenHash);
}

_IRQL_requires_max_(DISPATCH_LEVEL)
_Ret_maybenull_
CXPLAT_KEY*
QuicPartitionGetStatelessRetryKey(
    _In_ QUIC_PARTITION* Partition,
    _In_ int64_t KeyIndex
    )
{
    //
    // Check if the key is already generated.
    //
    if (Partition->StatelessRetryKeys[KeyIndex & 1].Index == KeyIndex) {
        return Partition->StatelessRetryKeys[KeyIndex & 1].Key;
    }

    //
    // Generate a new key from the base retry key combined with the index.
    //
    uint8_t RawKey[CXPLAT_AEAD_AES_256_GCM_SIZE];
    CxPlatCopyMemory(
        RawKey,
        MsQuicLib.BaseRetrySecret,
        CxPlatKeyLength(MsQuicLib.RetryAeadAlgorithm));
    for (size_t i = 0; i < sizeof(KeyIndex); ++i) {
        RawKey[i] ^= ((uint8_t*)&KeyIndex)[i];
    }

    CXPLAT_KEY* NewKey;
    QUIC_STATUS Status =
        CxPlatKeyCreate(
            MsQuicLib.RetryAeadAlgorithm,
            RawKey,
            &NewKey);
    if (QUIC_FAILED(Status)) {
        QuicTraceEvent(
            LibraryErrorStatus,
            "[ lib] ERROR, %u, %s.",
            Status,
            "Create stateless retry key");
        return NULL;
    }

    CxPlatKeyFree(Partition->StatelessRetryKeys[KeyIndex & 1].Key);
    Partition->StatelessRetryKeys[KeyIndex & 1].Key = NewKey;
    Partition->StatelessRetryKeys[KeyIndex & 1].Index = KeyIndex;

    return NewKey;
}

_IRQL_requires_max_(DISPATCH_LEVEL)
_Ret_maybenull_
CXPLAT_KEY*
QuicPartitionGetCurrentStatelessRetryKey(
    _In_ QUIC_PARTITION* Partition
    )
{
    const int64_t Now = CxPlatTimeEpochMs64();
    CxPlatDispatchRwLockAcquireShared(&MsQuicLib.StatelessRetryLock, PrevIrql);
    const int64_t KeyIndex = Now / MsQuicLib.RetryKeyRotationMs;
    CXPLAT_KEY* Key = QuicPartitionGetStatelessRetryKey(Partition, KeyIndex);
    CxPlatDispatchRwLockReleaseShared(&MsQuicLib.StatelessRetryLock, PrevIrql);
    return Key;
}

_IRQL_requires_max_(DISPATCH_LEVEL)
_Ret_maybenull_
CXPLAT_KEY*
QuicPartitionGetStatelessRetryKeyForTimestamp(
    _In_ QUIC_PARTITION* Partition,
    _In_ int64_t Timestamp
    )
{
    const int64_t Now = CxPlatTimeEpochMs64();
    CxPlatDispatchRwLockAcquireShared(&MsQuicLib.StatelessRetryLock, PrevIrql);
    const int64_t CurrentKeyIndex = Now / MsQuicLib.RetryKeyRotationMs;
    const int64_t KeyIndex = Timestamp / MsQuicLib.RetryKeyRotationMs;

    if (KeyIndex < CurrentKeyIndex - 1 || KeyIndex > CurrentKeyIndex) {
        //
        // This key index is too old or too new.
        //
        CxPlatDispatchRwLockReleaseShared(&MsQuicLib.StatelessRetryLock, PrevIrql);
        return NULL;
    }

    CXPLAT_KEY* Key = QuicPartitionGetStatelessRetryKey(Partition, KeyIndex);
    CxPlatDispatchRwLockReleaseShared(&MsQuicLib.StatelessRetryLock, PrevIrql);
    return Key;
}
