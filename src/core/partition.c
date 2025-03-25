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
        CxPlatKeyFree(Partition->StatelessRetryKeys[i]);
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
QuicPartitionGetCurrentStatelessRetryKey(
    _In_ QUIC_PARTITION* Partition
    )
{
    int64_t Now = CxPlatTimeEpochMs64();
    int64_t StartTime = (Now / QUIC_STATELESS_RETRY_KEY_LIFETIME_MS) * QUIC_STATELESS_RETRY_KEY_LIFETIME_MS;

    if (StartTime < Partition->StatelessRetryKeysExpiration[Partition->CurrentStatelessRetryKey]) {
        return Partition->StatelessRetryKeys[Partition->CurrentStatelessRetryKey];
    }

    //
    // If the start time for the current key interval is greater-than-or-equal
    // to the expiration time of the latest stateless retry key, generate a new
    // key, and rotate the old.
    //

    int64_t ExpirationTime = StartTime + QUIC_STATELESS_RETRY_KEY_LIFETIME_MS;

    CXPLAT_KEY* NewKey;
    uint8_t RawKey[CXPLAT_AEAD_AES_256_GCM_SIZE];
    CxPlatRandom(sizeof(RawKey), RawKey);
    QUIC_STATUS Status =
        CxPlatKeyCreate(
            CXPLAT_AEAD_AES_256_GCM,
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

    Partition->StatelessRetryKeysExpiration[!Partition->CurrentStatelessRetryKey] = ExpirationTime;
    CxPlatKeyFree(Partition->StatelessRetryKeys[!Partition->CurrentStatelessRetryKey]);
    Partition->StatelessRetryKeys[!Partition->CurrentStatelessRetryKey] = NewKey;
    Partition->CurrentStatelessRetryKey = !Partition->CurrentStatelessRetryKey;

    return NewKey;
}

_IRQL_requires_max_(DISPATCH_LEVEL)
_Ret_maybenull_
CXPLAT_KEY*
QuicPartitionGetStatelessRetryKeyForTimestamp(
    _In_ QUIC_PARTITION* Partition,
    _In_ int64_t Timestamp
    )
{
    if (Timestamp < Partition->StatelessRetryKeysExpiration[!Partition->CurrentStatelessRetryKey] - QUIC_STATELESS_RETRY_KEY_LIFETIME_MS) {
        //
        // Timestamp is before the beginning of the previous key's validity window.
        //
        return NULL;
    }

    if (Timestamp < Partition->StatelessRetryKeysExpiration[!Partition->CurrentStatelessRetryKey]) {
        if (Partition->StatelessRetryKeys[!Partition->CurrentStatelessRetryKey] == NULL) {
            return NULL;
        }
        return Partition->StatelessRetryKeys[!Partition->CurrentStatelessRetryKey];
    }

    if (Timestamp < Partition->StatelessRetryKeysExpiration[Partition->CurrentStatelessRetryKey]) {
        if (Partition->StatelessRetryKeys[Partition->CurrentStatelessRetryKey] == NULL) {
            return NULL;
        }
        return Partition->StatelessRetryKeys[Partition->CurrentStatelessRetryKey];
    }

    //
    // Timestamp is after the end of the latest key's validity window.
    //
    return NULL;
}
