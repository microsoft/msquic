/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.

Abstract:

    Functions for encoding and decoding frames.

--*/

#include "precomp.h"
#ifdef QUIC_CLOG
#include "frame.c.clog.h"
#endif

_Post_equal_to_(Buffer + sizeof(uint8_t))
uint8_t*
QuicUint8Encode(
    _In_ uint8_t Value,
    _Out_ uint8_t* Buffer
    )
{
    *Buffer = Value;
    return Buffer + sizeof(uint8_t);
}

_Success_(return != FALSE)
BOOLEAN
QuicUint8tDecode(
    _In_ uint16_t BufferLength,
    _In_reads_bytes_(BufferLength)
        const uint8_t * const Buffer,
    _Inout_
    _Deref_in_range_(0, BufferLength)
    _Deref_out_range_(0, BufferLength)
        uint16_t* Offset,
    _Out_ uint8_t* Value
    )
{
    if (BufferLength < sizeof(uint8_t) + *Offset) {
        return FALSE;
    }
    *Value = Buffer[*Offset];
    *Offset += sizeof(uint8_t);
    return TRUE;
}

_Success_(return != FALSE)
BOOLEAN
QuicAckHeaderEncode(
    _In_ const QUIC_ACK_EX * const Frame,
    _In_opt_ QUIC_ACK_ECN_EX* Ecn,
    _Inout_ uint16_t* Offset,
    _In_ uint16_t BufferLength,
    _Out_writes_to_(BufferLength, *Offset) uint8_t* Buffer
    )
{
    uint16_t RequiredLength =
        sizeof(uint8_t) +     // Type
        QuicVarIntSize(Frame->LargestAcknowledged) +
        QuicVarIntSize(Frame->AckDelay) +
        QuicVarIntSize(Frame->AdditionalAckBlockCount) +
        QuicVarIntSize(Frame->FirstAckBlock);

    if (BufferLength < *Offset + RequiredLength) {
        return FALSE;
    }

    Buffer = Buffer + *Offset;
    Buffer = QuicUint8Encode(Ecn == NULL ? QUIC_FRAME_ACK : QUIC_FRAME_ACK + 1, Buffer);
    Buffer = QuicVarIntEncode(Frame->LargestAcknowledged, Buffer);
    Buffer = QuicVarIntEncode(Frame->AckDelay, Buffer);
    Buffer = QuicVarIntEncode(Frame->AdditionalAckBlockCount, Buffer);
    QuicVarIntEncode(Frame->FirstAckBlock, Buffer);
    *Offset += RequiredLength;

    return TRUE;
}

_Success_(return != FALSE)
BOOLEAN
QuicAckHeaderDecode(
    _In_ uint16_t BufferLength,
    _In_reads_bytes_(BufferLength)
        const uint8_t * const Buffer,
    _Inout_ uint16_t* Offset,
    _Out_ QUIC_ACK_EX* Frame
    )
{
    if (!QuicVarIntDecode(BufferLength, Buffer, Offset, &Frame->LargestAcknowledged) ||
        !QuicVarIntDecode(BufferLength, Buffer, Offset, &Frame->AckDelay) ||
        !QuicVarIntDecode(BufferLength, Buffer, Offset, &Frame->AdditionalAckBlockCount) ||
        !QuicVarIntDecode(BufferLength, Buffer, Offset, &Frame->FirstAckBlock) ||
        Frame->FirstAckBlock > Frame->LargestAcknowledged) {
        return FALSE;
    }
    return TRUE;
}

_Success_(return != FALSE)
BOOLEAN
QuicAckBlockEncode(
    _In_ const QUIC_ACK_BLOCK_EX * const Block,
    _Inout_ uint16_t* Offset,
    _In_ uint16_t BufferLength,
    _Out_writes_to_(BufferLength, *Offset) uint8_t* Buffer
    )
{
    uint16_t RequiredLength =
        QuicVarIntSize(Block->Gap) +
        QuicVarIntSize(Block->AckBlock);

    if (BufferLength < *Offset + RequiredLength) {
        return FALSE;
    }

    Buffer = Buffer + *Offset;
    Buffer = QuicVarIntEncode(Block->Gap, Buffer);
    QuicVarIntEncode(Block->AckBlock, Buffer);
    *Offset += RequiredLength;

    return TRUE;
}

_Success_(return != FALSE)
BOOLEAN
QuicAckBlockDecode(
    _In_ uint16_t BufferLength,
    _In_reads_bytes_(BufferLength)
        const uint8_t * const Buffer,
    _Inout_ uint16_t* Offset,
    _Out_ QUIC_ACK_BLOCK_EX* Block
    )
{
    if (!QuicVarIntDecode(BufferLength, Buffer, Offset, &Block->Gap) ||
        !QuicVarIntDecode(BufferLength, Buffer, Offset, &Block->AckBlock)) {
        return FALSE;
    }
    return TRUE;
}

_Success_(return != FALSE)
BOOLEAN
QuicAckEcnEncode(
    _In_ const QUIC_ACK_ECN_EX * const Ecn,
    _Inout_ uint16_t* Offset,
    _In_ uint16_t BufferLength,
    _Out_writes_to_(BufferLength, *Offset) uint8_t* Buffer
    )
{
    uint16_t RequiredLength =
        QuicVarIntSize(Ecn->ECT_0_Count) +
        QuicVarIntSize(Ecn->ECT_1_Count) +
        QuicVarIntSize(Ecn->CE_Count);

    if (BufferLength < *Offset + RequiredLength) {
        return FALSE;
    }

    Buffer = Buffer + *Offset;
    Buffer = QuicVarIntEncode(Ecn->ECT_0_Count, Buffer);
    Buffer = QuicVarIntEncode(Ecn->ECT_1_Count, Buffer);
    QuicVarIntEncode(Ecn->CE_Count, Buffer);
    *Offset += RequiredLength;

    return TRUE;
}

_Success_(return != FALSE)
BOOLEAN
QuicAckEcnDecode(
    _In_ uint16_t BufferLength,
    _In_reads_bytes_(BufferLength)
        const uint8_t * const Buffer,
    _Inout_ uint16_t* Offset,
    _Out_ QUIC_ACK_ECN_EX* Ecn
    )
{
    if (!QuicVarIntDecode(BufferLength, Buffer, Offset, &Ecn->ECT_0_Count) ||
        !QuicVarIntDecode(BufferLength, Buffer, Offset, &Ecn->ECT_1_Count) ||
        !QuicVarIntDecode(BufferLength, Buffer, Offset, &Ecn->CE_Count)) {
        return FALSE;
    }
    return TRUE;
}

_Success_(return != FALSE)
BOOLEAN
QuicAckFrameEncode(
    _In_ const QUIC_RANGE * const AckBlocks,
    _In_ uint64_t AckDelay,
    _In_opt_ QUIC_ACK_ECN_EX* Ecn,
    _Inout_ uint16_t* Offset,
    _In_ uint16_t BufferLength,
    _Out_writes_to_(BufferLength, *Offset) uint8_t* Buffer
    )
{
    uint32_t i = QuicRangeSize(AckBlocks) - 1;

    QUIC_SUBRANGE* LastSub = QuicRangeGet(AckBlocks, i);
    uint64_t Largest = QuicRangeGetHigh(LastSub);
    uint64_t Count = LastSub->Count;

    //
    // Write the ACK Frame Header
    //
    QUIC_ACK_EX Frame = {
        Largest,                // LargestAcknowledged
        AckDelay,               // AckDelay
        i,                      // AdditionalAckBlockCount
        Count - 1               // FirstAckBlock
    };

    if (!QuicAckHeaderEncode(&Frame, Ecn, Offset, BufferLength, Buffer)) {
        return FALSE;
    }

    //
    // Write any additional ACK Blocks
    //
    while (i != 0) {

        CXPLAT_DBG_ASSERT(Largest >= Count);
        Largest -= Count;

        QUIC_SUBRANGE* Next = QuicRangeGet(AckBlocks, i - 1);
        uint64_t NextLargest = QuicRangeGetHigh(Next);
        Count = Next->Count;

        CXPLAT_DBG_ASSERT(Largest > NextLargest);
        CXPLAT_DBG_ASSERT(Count > 0);

        QUIC_ACK_BLOCK_EX Block = {
            (Largest - NextLargest) - 1,    // Gap
            Count - 1                       // AckBlock
        };

        if (!QuicAckBlockEncode(&Block, Offset, BufferLength, Buffer)) {
            CXPLAT_TEL_ASSERT(FALSE); // TODO - Support partial ACK array encoding by updating the 'AdditionalAckBlockCount' field.
            return FALSE;
        }

        Largest = NextLargest;
        i--;
    }

    if (Ecn != NULL) {
        if (!QuicAckEcnEncode(Ecn, Offset, BufferLength, Buffer)) {
            return FALSE;
        }
    }

    return TRUE;
}

//
// Given that the max UDP packet is 64k, this is a reasonable upper bound for
// the number of ACK blocks possible.
//
#define QUIC_MAX_NUMBER_ACK_BLOCKS 0x10000

//
// Decodes the ACK_FRAME (has packet numbers from largest to smallest) to a
// QUIC_RANGE format (smallest to largest).
//
_Success_(return != FALSE)
BOOLEAN
QuicAckFrameDecode(
    _In_ QUIC_FRAME_TYPE FrameType,
    _In_ uint16_t BufferLength,
    _In_reads_bytes_(BufferLength)
        const uint8_t * const Buffer,
    _Inout_ uint16_t* Offset,
    _Out_ BOOLEAN* InvalidFrame,
    _Inout_ QUIC_RANGE* AckRanges, // Pre-Initialized by caller
    _When_(FrameType == QUIC_FRAME_ACK_1, _Out_)
        QUIC_ACK_ECN_EX* Ecn,
    _Out_ uint64_t* AckDelay
    )
{
    *InvalidFrame = FALSE;
    CXPLAT_DBG_ASSERT(AckRanges->SubRanges); // Should be pre-initialized.

    //
    // Decode the ACK frame header.
    //
    QUIC_ACK_EX Frame;
    if (!QuicAckHeaderDecode(BufferLength, Buffer, Offset, &Frame)) {
        *InvalidFrame = TRUE;
        return FALSE;
    }

    //
    // Insert the largest/first block into the range.
    //

    uint64_t Largest = Frame.LargestAcknowledged;
    uint64_t Count = Frame.FirstAckBlock + 1;

    BOOLEAN DontCare;
    if (!QuicRangeAddRange(AckRanges, Largest + 1 - Count, Count, &DontCare)) {
        return FALSE;
    }

    if (Frame.AdditionalAckBlockCount >= QUIC_MAX_NUMBER_ACK_BLOCKS) {
        *InvalidFrame = TRUE;
        return FALSE;
    }

    //
    // Insert all the rest of the blocks (if any) into the range.
    //

    for (uint32_t i = 0; i < (uint32_t)Frame.AdditionalAckBlockCount; i++) {

        if (Count > Largest) {
            *InvalidFrame = TRUE;
            return FALSE;
        }

        Largest -= Count;

        QUIC_ACK_BLOCK_EX Block;
        if (!QuicAckBlockDecode(BufferLength, Buffer, Offset, &Block)) {
            *InvalidFrame = TRUE;
            return FALSE;
        }

        if (Block.Gap + 1 > Largest) {
            *InvalidFrame = TRUE;
            return FALSE;
        }

        Largest -= (Block.Gap + 1);
        Count = Block.AckBlock + 1;

        //
        // N.B. The efficiency here isn't great because we are always inserting
        // values less than the current minimum, which requires a complete
        // memmove of the current array. A circular buffer that allows both
        // forward and backward growth would fix this.
        //

        if (!QuicRangeAddRange(AckRanges, Largest - Count + 1, Count, &DontCare)) {
            return FALSE;
        }
    }

    *AckDelay = Frame.AckDelay;

    if (FrameType == QUIC_FRAME_ACK_1) {
        //
        // The ECN section was provided. Decode it as well.
        //
        if (!QuicAckEcnDecode(BufferLength, Buffer, Offset, Ecn)) {
            return FALSE;
        }
    }

    return TRUE;
}

_Success_(return != FALSE)
BOOLEAN
QuicResetStreamFrameEncode(
    _In_ const QUIC_RESET_STREAM_EX * const Frame,
    _Inout_ uint16_t* Offset,
    _In_ uint16_t BufferLength,
    _Out_writes_to_(BufferLength, *Offset) uint8_t* Buffer
    )
{
    uint16_t RequiredLength =
        sizeof(uint8_t) +     // Type
        QuicVarIntSize(Frame->ErrorCode) +
        QuicVarIntSize(Frame->StreamID) +
        QuicVarIntSize(Frame->FinalSize);

    if (BufferLength < *Offset + RequiredLength) {
        return FALSE;
    }

    Buffer = Buffer + *Offset;
    Buffer = QuicUint8Encode(QUIC_FRAME_RESET_STREAM, Buffer);
    Buffer = QuicVarIntEncode(Frame->StreamID, Buffer);
    Buffer = QuicVarIntEncode(Frame->ErrorCode, Buffer);
    QuicVarIntEncode(Frame->FinalSize, Buffer);
    *Offset += RequiredLength;

    return TRUE;
}

_Success_(return != FALSE)
BOOLEAN
QuicResetStreamFrameDecode(
    _In_ uint16_t BufferLength,
    _In_reads_bytes_(BufferLength)
        const uint8_t * const Buffer,
    _Inout_ uint16_t* Offset,
    _Out_ QUIC_RESET_STREAM_EX* Frame
    )
{
    if (!QuicVarIntDecode(BufferLength, Buffer, Offset, &Frame->StreamID) ||
        !QuicVarIntDecode(BufferLength, Buffer, Offset, &Frame->ErrorCode) ||
        !QuicVarIntDecode(BufferLength, Buffer, Offset, &Frame->FinalSize)) {
        return FALSE;
    }
    return TRUE;
}

_Success_(return != FALSE)
BOOLEAN
QuicStopSendingFrameEncode(
    _In_ const QUIC_STOP_SENDING_EX * const Frame,
    _Inout_ uint16_t* Offset,
    _In_ uint16_t BufferLength,
    _Out_writes_to_(BufferLength, *Offset) uint8_t* Buffer
    )
{
    uint16_t RequiredLength =
        sizeof(uint8_t) +     // Type
        QuicVarIntSize(Frame->StreamID) +
        QuicVarIntSize(Frame->ErrorCode);

    if (BufferLength < *Offset + RequiredLength) {
        return FALSE;
    }

    Buffer = Buffer + *Offset;
    Buffer = QuicUint8Encode(QUIC_FRAME_STOP_SENDING, Buffer);
    Buffer = QuicVarIntEncode(Frame->StreamID, Buffer);
    QuicVarIntEncode(Frame->ErrorCode, Buffer);
    *Offset += RequiredLength;

    return TRUE;
}

_Success_(return != FALSE)
BOOLEAN
QuicStopSendingFrameDecode(
    _In_ uint16_t BufferLength,
    _In_reads_bytes_(BufferLength)
        const uint8_t * const Buffer,
    _Inout_ uint16_t* Offset,
    _Out_ QUIC_STOP_SENDING_EX* Frame
    )
{
    if (!QuicVarIntDecode(BufferLength, Buffer, Offset, &Frame->StreamID) ||
        !QuicVarIntDecode(BufferLength, Buffer, Offset, &Frame->ErrorCode)) {
        return FALSE;
    }
    return TRUE;
}

_Success_(return != FALSE)
BOOLEAN
QuicCryptoFrameEncode(
    _In_ const QUIC_CRYPTO_EX * const Frame,
    _Inout_ uint16_t* Offset,
    _In_ uint16_t BufferLength,
    _Out_writes_to_(BufferLength, *Offset) uint8_t* Buffer
    )
{
    CXPLAT_DBG_ASSERT(Frame->Length < UINT16_MAX);

    uint16_t RequiredLength =
        sizeof(uint8_t) +     // Type
        QuicVarIntSize(Frame->Offset) +
        QuicVarIntSize(Frame->Length) +
        (uint16_t)Frame->Length;

    if (BufferLength < *Offset + RequiredLength) {
        return FALSE;
    }

    Buffer = Buffer + *Offset;
    Buffer = QuicUint8Encode(QUIC_FRAME_CRYPTO, Buffer);
    Buffer = QuicVarIntEncode(Frame->Offset, Buffer);
    Buffer = QuicVarIntEncode(Frame->Length, Buffer);
    CxPlatCopyMemory(Buffer, Frame->Data, (uint16_t)Frame->Length);
    *Offset += RequiredLength;

    return TRUE;
}

_Success_(return != FALSE)
BOOLEAN
QuicCryptoFrameDecode(
    _In_ uint16_t BufferLength,
    _In_reads_bytes_(BufferLength)
        const uint8_t * const Buffer,
    _Inout_ uint16_t* Offset,
    _Out_ QUIC_CRYPTO_EX* Frame
    )
{
    if (!QuicVarIntDecode(BufferLength, Buffer, Offset, &Frame->Offset) ||
        !QuicVarIntDecode(BufferLength, Buffer, Offset, &Frame->Length) ||
        BufferLength < Frame->Length + *Offset) {
        return FALSE;
    }
    Frame->Data = Buffer + *Offset;
    *Offset += (uint16_t)Frame->Length;
    return TRUE;
}

_Success_(return != FALSE)
BOOLEAN
QuicNewTokenFrameEncode(
    _In_ const QUIC_NEW_TOKEN_EX * const Frame,
    _Inout_ uint16_t* Offset,
    _In_ uint16_t BufferLength,
    _Out_writes_to_(BufferLength, *Offset) uint8_t* Buffer
    )
{
    uint16_t RequiredLength =
        sizeof(uint8_t) +     // Type
        QuicVarIntSize(Frame->TokenLength) +
        (uint16_t)Frame->TokenLength;

    if (BufferLength < *Offset + RequiredLength) {
        return FALSE;
    }

    Buffer = Buffer + *Offset;
    Buffer = QuicUint8Encode(QUIC_FRAME_NEW_TOKEN, Buffer);
    Buffer = QuicVarIntEncode(Frame->TokenLength, Buffer);
    CxPlatCopyMemory(Buffer, Frame->Token, (uint16_t)Frame->TokenLength);
    *Offset += RequiredLength;

    return TRUE;
}

_Success_(return != FALSE)
BOOLEAN
QuicNewTokenFrameDecode(
    _In_ uint16_t BufferLength,
    _In_reads_bytes_(BufferLength)
        const uint8_t * const Buffer,
    _Inout_ uint16_t* Offset,
    _Out_ QUIC_NEW_TOKEN_EX* Frame
    )
{
    if (!QuicVarIntDecode(BufferLength, Buffer, Offset, &Frame->TokenLength) ||
        BufferLength < Frame->TokenLength + *Offset) {
        return FALSE;
    }

    Frame->Token = Buffer + *Offset;
    *Offset += (uint16_t)Frame->TokenLength;

    return TRUE;
}

_Success_(return != FALSE)
BOOLEAN
QuicStreamFrameEncode(
    _In_ const QUIC_STREAM_EX * const Frame,
    _Inout_ uint16_t* Offset,
    _In_ uint16_t BufferLength,
    _Out_writes_to_(BufferLength, *Offset) uint8_t* Buffer
    )
{
    __analysis_assume(Frame->Length < 0x10000);
    CXPLAT_DBG_ASSERT(Frame->Length < 0x10000);

    uint16_t RequiredLength =
        QuicStreamFrameHeaderSize(Frame) +
        (uint16_t)Frame->Length;

    if (BufferLength < *Offset + RequiredLength) {
        return FALSE;
    }

    QUIC_STREAM_FRAME_TYPE Type = {{{
        Frame->Fin,
        Frame->ExplicitLength,
        Frame->Offset != 0 ? TRUE : FALSE,
        0b00001
    }}};

    Buffer = Buffer + *Offset;
    Buffer = QuicUint8Encode(Type.Type, Buffer);
    Buffer = QuicVarIntEncode(Frame->StreamID, Buffer);
    if (Type.OFF) {
        Buffer = QuicVarIntEncode(Frame->Offset, Buffer);
    }
    if (Type.LEN) {
        Buffer = QuicVarIntEncode2Bytes(Frame->Length, Buffer); // We always use two bytes for the explicit length.
    }
    CXPLAT_DBG_ASSERT(Frame->Length == 0 || Buffer == Frame->Data); // Caller already set the data.
    *Offset += RequiredLength;

    return TRUE;
}

_Success_(return != FALSE)
BOOLEAN
QuicStreamFrameDecode(
    _In_ QUIC_FRAME_TYPE FrameType,
    _In_ uint16_t BufferLength,
    _In_reads_bytes_(BufferLength)
        const uint8_t * const Buffer,
    _Inout_
    _Deref_in_range_(0, BufferLength)
    _Deref_out_range_(0, BufferLength)
        uint16_t* Offset,
    _Out_ QUIC_STREAM_EX* Frame
    )
{
    QUIC_STREAM_FRAME_TYPE Type = { .Type = FrameType };
    if (!QuicVarIntDecode(BufferLength, Buffer, Offset, &Frame->StreamID)) {
        return FALSE;
    }
    if (Type.OFF) {
        if (!QuicVarIntDecode(BufferLength, Buffer, Offset, &Frame->Offset)) {
            return FALSE;
        }
    } else {
        Frame->Offset = 0;
    }
    if (Type.LEN) {
        if (!QuicVarIntDecode(BufferLength, Buffer, Offset, &Frame->Length) ||
            BufferLength < Frame->Length + *Offset) {
            return FALSE;
        }
        Frame->ExplicitLength = TRUE;
    } else {
        CXPLAT_ANALYSIS_ASSERT(BufferLength >= *Offset);
        Frame->Length = BufferLength - *Offset;
    }
    Frame->Fin = Type.FIN;
    Frame->Data = Buffer + *Offset;
    *Offset += (uint16_t)Frame->Length;
    return TRUE;
}

_Success_(return != FALSE)
BOOLEAN
QuicMaxDataFrameEncode(
    _In_ const QUIC_MAX_DATA_EX * const Frame,
    _Inout_ uint16_t* Offset,
    _In_ uint16_t BufferLength,
    _Out_writes_to_(BufferLength, *Offset) uint8_t* Buffer
    )
{
    uint16_t RequiredLength =
        sizeof(uint8_t) +     // Type
        QuicVarIntSize(Frame->MaximumData);

    if (BufferLength < *Offset + RequiredLength) {
        return FALSE;
    }

    Buffer = Buffer + *Offset;
    Buffer = QuicUint8Encode(QUIC_FRAME_MAX_DATA, Buffer);
    QuicVarIntEncode(Frame->MaximumData, Buffer);
    *Offset += RequiredLength;

    return TRUE;
}

_Success_(return != FALSE)
BOOLEAN
QuicMaxDataFrameDecode(
    _In_ uint16_t BufferLength,
    _In_reads_bytes_(BufferLength)
        const uint8_t * const Buffer,
    _Inout_ uint16_t* Offset,
    _Out_ QUIC_MAX_DATA_EX* Frame
    )
{
    if (!QuicVarIntDecode(BufferLength, Buffer, Offset, &Frame->MaximumData)) {
        return FALSE;
    }
    return TRUE;
}

_Success_(return != FALSE)
BOOLEAN
QuicMaxStreamDataFrameEncode(
    _In_ const QUIC_MAX_STREAM_DATA_EX * const Frame,
    _Inout_ uint16_t* Offset,
    _In_ uint16_t BufferLength,
    _Out_writes_to_(BufferLength, *Offset) uint8_t* Buffer
    )
{
    uint16_t RequiredLength =
        sizeof(uint8_t) +     // Type
        QuicVarIntSize(Frame->StreamID) +
        QuicVarIntSize(Frame->MaximumData);

    if (BufferLength < *Offset + RequiredLength) {
        return FALSE;
    }

    Buffer = Buffer + *Offset;
    Buffer = QuicUint8Encode(QUIC_FRAME_MAX_STREAM_DATA, Buffer);
    Buffer = QuicVarIntEncode(Frame->StreamID, Buffer);
    QuicVarIntEncode(Frame->MaximumData, Buffer);
    *Offset += RequiredLength;

    return TRUE;
}

_Success_(return != FALSE)
BOOLEAN
QuicMaxStreamDataFrameDecode(
    _In_ uint16_t BufferLength,
    _In_reads_bytes_(BufferLength)
        const uint8_t * const Buffer,
    _Inout_ uint16_t* Offset,
    _Out_ QUIC_MAX_STREAM_DATA_EX* Frame
    )
{
    if (!QuicVarIntDecode(BufferLength, Buffer, Offset, &Frame->StreamID) ||
        !QuicVarIntDecode(BufferLength, Buffer, Offset, &Frame->MaximumData)) {
        return FALSE;
    }
    return TRUE;
}

_Success_(return != FALSE)
BOOLEAN
QuicMaxStreamsFrameEncode(
    _In_ const QUIC_MAX_STREAMS_EX * const Frame,
    _Inout_ uint16_t* Offset,
    _In_ uint16_t BufferLength,
    _Out_writes_to_(BufferLength, *Offset) uint8_t* Buffer
    )
{
    uint16_t RequiredLength =
        sizeof(uint8_t) +     // Type
        QuicVarIntSize(Frame->MaximumStreams);

    if (BufferLength < *Offset + RequiredLength) {
        return FALSE;
    }

    Buffer = Buffer + *Offset;
    Buffer =
        QuicUint8Encode(
            Frame->BidirectionalStreams ?
                QUIC_FRAME_MAX_STREAMS :
                QUIC_FRAME_MAX_STREAMS_1,
            Buffer);
    QuicVarIntEncode(Frame->MaximumStreams, Buffer);
    *Offset += RequiredLength;

    return TRUE;
}

_Success_(return != FALSE)
BOOLEAN
QuicMaxStreamsFrameDecode(
    _In_ QUIC_FRAME_TYPE FrameType,
    _In_ uint16_t BufferLength,
    _In_reads_bytes_(BufferLength)
        const uint8_t * const Buffer,
    _Inout_ uint16_t* Offset,
    _Out_ QUIC_MAX_STREAMS_EX* Frame
    )
{
    if (!QuicVarIntDecode(BufferLength, Buffer, Offset, &Frame->MaximumStreams)) {
        return FALSE;
    }
    Frame->BidirectionalStreams = FrameType == QUIC_FRAME_MAX_STREAMS;
    return TRUE;
}

_Success_(return != FALSE)
BOOLEAN
QuicDataBlockedFrameEncode(
    _In_ const QUIC_DATA_BLOCKED_EX * const Frame,
    _Inout_ uint16_t* Offset,
    _In_ uint16_t BufferLength,
    _Out_writes_to_(BufferLength, *Offset) uint8_t* Buffer
    )
{
    uint16_t RequiredLength =
        sizeof(uint8_t) +     // Type
        QuicVarIntSize(Frame->DataLimit);

    if (BufferLength < *Offset + RequiredLength) {
        return FALSE;
    }

    Buffer = Buffer + *Offset;
    Buffer = QuicUint8Encode(QUIC_FRAME_DATA_BLOCKED, Buffer);
    QuicVarIntEncode(Frame->DataLimit, Buffer);
    *Offset += RequiredLength;

    return TRUE;
}

_Success_(return != FALSE)
BOOLEAN
QuicDataBlockedFrameDecode(
    _In_ uint16_t BufferLength,
    _In_reads_bytes_(BufferLength)
        const uint8_t * const Buffer,
    _Inout_ uint16_t* Offset,
    _Out_ QUIC_DATA_BLOCKED_EX* Frame
    )
{
    if (!QuicVarIntDecode(BufferLength, Buffer, Offset, &Frame->DataLimit)) {
        return FALSE;
    }
    return TRUE;
}

_Success_(return != FALSE)
BOOLEAN
QuicStreamDataBlockedFrameEncode(
    _In_ const QUIC_STREAM_DATA_BLOCKED_EX * const Frame,
    _Inout_ uint16_t* Offset,
    _In_ uint16_t BufferLength,
    _Out_writes_to_(BufferLength, *Offset) uint8_t* Buffer
    )
{
    uint16_t RequiredLength =
        sizeof(uint8_t) +     // Type
        QuicVarIntSize(Frame->StreamID) +
        QuicVarIntSize(Frame->StreamDataLimit);

    if (BufferLength < *Offset + RequiredLength) {
        return FALSE;
    }

    Buffer = Buffer + *Offset;
    Buffer = QuicUint8Encode(QUIC_FRAME_STREAM_DATA_BLOCKED, Buffer);
    Buffer = QuicVarIntEncode(Frame->StreamID, Buffer);
    QuicVarIntEncode(Frame->StreamDataLimit, Buffer);
    *Offset += RequiredLength;

    return TRUE;
}

_Success_(return != FALSE)
BOOLEAN
QuicStreamDataBlockedFrameDecode(
    _In_ uint16_t BufferLength,
    _In_reads_bytes_(BufferLength)
        const uint8_t * const Buffer,
    _Inout_ uint16_t* Offset,
    _Out_ QUIC_STREAM_DATA_BLOCKED_EX* Frame
    )
{
    if (!QuicVarIntDecode(BufferLength, Buffer, Offset, &Frame->StreamID) ||
        !QuicVarIntDecode(BufferLength, Buffer, Offset, &Frame->StreamDataLimit)) {
        return FALSE;
    }
    return TRUE;
}

_Success_(return != FALSE)
BOOLEAN
QuicStreamsBlockedFrameEncode(
    _In_ const QUIC_STREAMS_BLOCKED_EX * const Frame,
    _Inout_ uint16_t* Offset,
    _In_ uint16_t BufferLength,
    _Out_writes_to_(BufferLength, *Offset) uint8_t* Buffer
    )
{
    uint16_t RequiredLength =
        sizeof(uint8_t) +     // Type
        QuicVarIntSize(Frame->StreamLimit);

    if (BufferLength < *Offset + RequiredLength) {
        return FALSE;
    }

    Buffer = Buffer + *Offset;
    Buffer =
        QuicUint8Encode(
            Frame->BidirectionalStreams ?
                QUIC_FRAME_STREAMS_BLOCKED :
                QUIC_FRAME_STREAMS_BLOCKED_1,
            Buffer);
    QuicVarIntEncode(Frame->StreamLimit, Buffer);
    *Offset += RequiredLength;

    return TRUE;
}

_Success_(return != FALSE)
BOOLEAN
QuicStreamsBlockedFrameDecode(
    _In_ QUIC_FRAME_TYPE FrameType,
    _In_ uint16_t BufferLength,
    _In_reads_bytes_(BufferLength)
        const uint8_t * const Buffer,
    _Inout_ uint16_t* Offset,
    _Out_ QUIC_STREAMS_BLOCKED_EX* Frame
    )
{
    if (!QuicVarIntDecode(BufferLength, Buffer, Offset, &Frame->StreamLimit)) {
        return FALSE;
    }
    Frame->BidirectionalStreams = FrameType == QUIC_FRAME_STREAMS_BLOCKED;
    return TRUE;
}

_Success_(return != FALSE)
BOOLEAN
QuicNewConnectionIDFrameEncode(
    _In_ const QUIC_NEW_CONNECTION_ID_EX * const Frame,
    _Inout_ uint16_t* Offset,
    _In_ uint16_t BufferLength,
    _Out_writes_to_(BufferLength, *Offset) uint8_t* Buffer
    )
{
    uint16_t RequiredLength =
        sizeof(uint8_t) +     // Type
        QuicVarIntSize(Frame->Sequence) +
        QuicVarIntSize(Frame->RetirePriorTo) +
        sizeof(uint8_t) +     // Length
        Frame->Length +
        QUIC_STATELESS_RESET_TOKEN_LENGTH;

    if (BufferLength < *Offset + RequiredLength) {
        return FALSE;
    }

    Buffer = Buffer + *Offset;
    Buffer = QuicUint8Encode(QUIC_FRAME_NEW_CONNECTION_ID, Buffer);
    Buffer = QuicVarIntEncode(Frame->Sequence, Buffer);
    Buffer = QuicVarIntEncode(Frame->RetirePriorTo, Buffer);
    Buffer = QuicUint8Encode(Frame->Length, Buffer);
    CxPlatCopyMemory(Buffer, Frame->Buffer, Frame->Length + QUIC_STATELESS_RESET_TOKEN_LENGTH);
    *Offset += RequiredLength;

    return TRUE;
}

_Success_(return != FALSE)
BOOLEAN
QuicNewConnectionIDFrameDecode(
    _In_ uint16_t BufferLength,
    _In_reads_bytes_(BufferLength)
        const uint8_t * const Buffer,
    _Inout_ uint16_t* Offset,
    _Out_ QUIC_NEW_CONNECTION_ID_EX* Frame
    )
{
    if (!QuicVarIntDecode(BufferLength, Buffer, Offset, &Frame->Sequence) ||
        !QuicVarIntDecode(BufferLength, Buffer, Offset, &Frame->RetirePriorTo) ||
        Frame->RetirePriorTo > Frame->Sequence ||
        BufferLength < *Offset + 1) {
        return FALSE;
    }

    Frame->Length = Buffer[(*Offset)++];

    if (Frame->Length < 1 || Frame->Length > QUIC_MAX_CONNECTION_ID_LENGTH_V1 ||
        BufferLength < *Offset + Frame->Length + QUIC_STATELESS_RESET_TOKEN_LENGTH) {
        return FALSE;
    }

    CxPlatCopyMemory(Frame->Buffer, Buffer + *Offset, Frame->Length + QUIC_STATELESS_RESET_TOKEN_LENGTH);
    *Offset += Frame->Length + QUIC_STATELESS_RESET_TOKEN_LENGTH;

    return TRUE;
}

_Success_(return != FALSE)
BOOLEAN
QuicRetireConnectionIDFrameEncode(
    _In_ const QUIC_RETIRE_CONNECTION_ID_EX * const Frame,
    _Inout_ uint16_t* Offset,
    _In_ uint16_t BufferLength,
    _Out_writes_to_(BufferLength, *Offset) uint8_t* Buffer
    )
{
    uint16_t RequiredLength =
        sizeof(uint8_t) +     // Type
        QuicVarIntSize(Frame->Sequence);

    if (BufferLength < *Offset + RequiredLength) {
        return FALSE;
    }

    Buffer = Buffer + *Offset;
    Buffer = QuicUint8Encode(QUIC_FRAME_RETIRE_CONNECTION_ID, Buffer);
    QuicVarIntEncode(Frame->Sequence, Buffer);
    *Offset += RequiredLength;

    return TRUE;
}

_Success_(return != FALSE)
BOOLEAN
QuicRetireConnectionIDFrameDecode(
    _In_ uint16_t BufferLength,
    _In_reads_bytes_(BufferLength)
        const uint8_t * const Buffer,
    _Inout_ uint16_t* Offset,
    _Out_ QUIC_RETIRE_CONNECTION_ID_EX* Frame
    )
{
    if (!QuicVarIntDecode(BufferLength, Buffer, Offset, &Frame->Sequence)) {
        return FALSE;
    }

    return TRUE;
}

_Success_(return != FALSE)
BOOLEAN
QuicPathChallengeFrameEncode(
    _In_ QUIC_FRAME_TYPE FrameType,
    _In_ const QUIC_PATH_CHALLENGE_EX * const Frame,
    _Inout_ uint16_t* Offset,
    _In_ uint16_t BufferLength,
    _Out_writes_to_(BufferLength, *Offset) uint8_t* Buffer
    )
{
    uint16_t RequiredLength =
        sizeof(uint8_t) +     // Type
        sizeof(Frame->Data);

    if (BufferLength < *Offset + RequiredLength) {
        return FALSE;
    }

    Buffer = Buffer + *Offset;
    Buffer = QuicUint8Encode(FrameType, Buffer);
    CxPlatCopyMemory(Buffer, Frame->Data, sizeof(Frame->Data));
    *Offset += RequiredLength;

    return TRUE;
}

_Success_(return != FALSE)
BOOLEAN
QuicPathChallengeFrameDecode(
    _In_ uint16_t BufferLength,
    _In_reads_bytes_(BufferLength)
        const uint8_t * const Buffer,
    _Inout_ uint16_t* Offset,
    _Out_ QUIC_PATH_CHALLENGE_EX* Frame
    )
{
    if (BufferLength < *Offset + sizeof(Frame->Data)) {
        return FALSE;
    }
    CxPlatCopyMemory(Frame->Data, Buffer + *Offset, sizeof(Frame->Data));
    *Offset += sizeof(Frame->Data);
    return TRUE;
}

_Success_(return != FALSE)
BOOLEAN
QuicConnCloseFrameEncode(
    _In_ const QUIC_CONNECTION_CLOSE_EX * const Frame,
    _Inout_ uint16_t* Offset,
    _In_ uint16_t BufferLength,
    _Out_writes_to_(BufferLength, *Offset) uint8_t* Buffer
    )
{
    uint16_t RequiredLength =
        sizeof(uint8_t) +     // Type
        QuicVarIntSize(Frame->ErrorCode) +
        (Frame->ApplicationClosed ? 0 : QuicVarIntSize(Frame->FrameType)) +
        QuicVarIntSize(Frame->ReasonPhraseLength) +
        (uint16_t)Frame->ReasonPhraseLength;

    if (BufferLength < *Offset + RequiredLength) {
        return FALSE;
    }

    Buffer = Buffer + *Offset;
    Buffer =
        QuicUint8Encode(
            Frame->ApplicationClosed ?
                QUIC_FRAME_CONNECTION_CLOSE_1 :
                QUIC_FRAME_CONNECTION_CLOSE,
            Buffer);
    Buffer = QuicVarIntEncode(Frame->ErrorCode, Buffer);
    if (!Frame->ApplicationClosed) {
        Buffer = QuicVarIntEncode(Frame->FrameType, Buffer);
    }
    Buffer = QuicVarIntEncode(Frame->ReasonPhraseLength, Buffer);
    if (Frame->ReasonPhraseLength != 0) {
        CxPlatCopyMemory(Buffer, Frame->ReasonPhrase, (size_t)Frame->ReasonPhraseLength);
    }
    *Offset += RequiredLength;

    return TRUE;
}

_Success_(return != FALSE)
BOOLEAN
QuicConnCloseFrameDecode(
    _In_ QUIC_FRAME_TYPE FrameType,
    _In_ uint16_t BufferLength,
    _In_reads_bytes_(BufferLength)
        const uint8_t * const Buffer,
    _Inout_ uint16_t* Offset,
    _Out_ QUIC_CONNECTION_CLOSE_EX* Frame
    )
{
    Frame->ApplicationClosed = FrameType == QUIC_FRAME_CONNECTION_CLOSE_1;
    Frame->FrameType = 0; // Default to make OACR happy.
    if (!QuicVarIntDecode(BufferLength, Buffer, Offset, &Frame->ErrorCode) ||
        (!Frame->ApplicationClosed &&
         !QuicVarIntDecode(BufferLength, Buffer, Offset, &Frame->FrameType)) ||
        !QuicVarIntDecode(BufferLength, Buffer, Offset, &Frame->ReasonPhraseLength) ||
        (uint64_t)BufferLength < *Offset + Frame->ReasonPhraseLength) {
        return FALSE;
    }
    Frame->ReasonPhrase = (char*)(Buffer + *Offset);
    *Offset += (uint16_t)Frame->ReasonPhraseLength;
    return TRUE;
}

_Success_(return != FALSE)
BOOLEAN
QuicDatagramFrameEncodeEx(
    _In_reads_(BufferCount)
        const QUIC_BUFFER* const Buffers,
    _In_ uint32_t BufferCount,
    _In_ uint64_t TotalLength,
    _Inout_ uint16_t* Offset,
    _In_ uint16_t BufferLength,
    _Out_writes_to_(BufferLength, *Offset)
        uint8_t* Buffer
    )
{
    QUIC_DATAGRAM_FRAME_TYPE Type = {{{
        TRUE,
        0b0011000
    }}};

    uint16_t RequiredLength =
        sizeof(uint8_t) +     // Type
        (Type.LEN ? QuicVarIntSize(TotalLength) : 0) +
        (uint16_t)TotalLength;

    if (BufferLength < *Offset + RequiredLength) {
        return FALSE;
    }

    Buffer = Buffer + *Offset;
    Buffer = QuicUint8Encode(Type.Type, Buffer);
    if (Type.LEN) {
        Buffer = QuicVarIntEncode(TotalLength, Buffer);
    }
    for (uint32_t i = 0; i < BufferCount; ++i) {
        if (Buffers[i].Length != 0) {
            CxPlatCopyMemory(Buffer, Buffers[i].Buffer, Buffers[i].Length);
            Buffer += Buffers[i].Length;
        }
    }

    *Offset += RequiredLength;

    return TRUE;
}

_Success_(return != FALSE)
BOOLEAN
QuicDatagramFrameDecode(
    _In_ QUIC_FRAME_TYPE FrameType,
    _In_ uint16_t BufferLength,
    _In_reads_bytes_(BufferLength)
        const uint8_t * const Buffer,
    _Deref_in_range_(0, BufferLength)
    _Inout_ uint16_t* Offset,
    _Out_ QUIC_DATAGRAM_EX* Frame
    )
{
    QUIC_DATAGRAM_FRAME_TYPE Type = { .Type = FrameType };
    if (Type.LEN) {
        if (!QuicVarIntDecode(BufferLength, Buffer, Offset, &Frame->Length) ||
            BufferLength < Frame->Length + *Offset) {
            return FALSE;
        }
    } else {
        CXPLAT_ANALYSIS_ASSERT(BufferLength >= *Offset);
        Frame->Length = BufferLength - *Offset;
    }
    Frame->Data = Buffer + *Offset;
    *Offset += (uint16_t)Frame->Length;
    return TRUE;
}

typedef struct QUIC_ACK_FREQUENCY_EXTRAS {

    union {
        struct {
            uint8_t IgnoreOrder : 1;
            uint8_t IgnoreCE    : 1;
            uint8_t Reserved    : 6;
        };
        uint8_t Value;
    };

} QUIC_ACK_FREQUENCY_EXTRAS;

_Success_(return != FALSE)
BOOLEAN
QuicAckFrequencyFrameEncode(
    _In_ const QUIC_ACK_FREQUENCY_EX * const Frame,
    _Inout_ uint16_t* Offset,
    _In_ uint16_t BufferLength,
    _Out_writes_to_(BufferLength, *Offset) uint8_t* Buffer
    )
{
    uint16_t RequiredLength =
        QuicVarIntSize(QUIC_FRAME_ACK_FREQUENCY) +
        QuicVarIntSize(Frame->SequenceNumber) +
        QuicVarIntSize(Frame->PacketTolerance) +
        QuicVarIntSize(Frame->UpdateMaxAckDelay) +
        sizeof(QUIC_ACK_FREQUENCY_EXTRAS);

    if (BufferLength < *Offset + RequiredLength) {
        return FALSE;
    }

    CXPLAT_DBG_ASSERT(Frame->IgnoreOrder <= 1); // IgnoreOrder should only be 0 or 1.
    CXPLAT_DBG_ASSERT(Frame->IgnoreCE <= 1);    // IgnoreCE should only be 0 or 1.

    QUIC_ACK_FREQUENCY_EXTRAS Extras = { .Value = 0 };
    Extras.IgnoreOrder = Frame->IgnoreOrder;
    Extras.IgnoreCE = Frame->IgnoreCE;

    Buffer = Buffer + *Offset;
    Buffer = QuicVarIntEncode(QUIC_FRAME_ACK_FREQUENCY, Buffer);
    Buffer = QuicVarIntEncode(Frame->SequenceNumber, Buffer);
    Buffer = QuicVarIntEncode(Frame->PacketTolerance, Buffer);
    Buffer = QuicVarIntEncode(Frame->UpdateMaxAckDelay, Buffer);
    QuicUint8Encode(Extras.Value, Buffer);
    *Offset += RequiredLength;

    return TRUE;
}

_Success_(return != FALSE)
BOOLEAN
QuicAckFrequencyFrameDecode(
    _In_ uint16_t BufferLength,
    _In_reads_bytes_(BufferLength)
        const uint8_t * const Buffer,
    _Inout_ uint16_t* Offset,
    _Out_ QUIC_ACK_FREQUENCY_EX* Frame
    )
{
    QUIC_ACK_FREQUENCY_EXTRAS Extras;
    if (!QuicVarIntDecode(BufferLength, Buffer, Offset, &Frame->SequenceNumber) ||
        !QuicVarIntDecode(BufferLength, Buffer, Offset, &Frame->PacketTolerance) ||
        !QuicVarIntDecode(BufferLength, Buffer, Offset, &Frame->UpdateMaxAckDelay) ||
        !QuicUint8tDecode(BufferLength, Buffer, Offset, &Extras.Value)) {
        return FALSE;
    }
    Frame->IgnoreOrder = Extras.IgnoreOrder;
    Frame->IgnoreCE = Extras.IgnoreCE;
    return TRUE;
}

_IRQL_requires_max_(DISPATCH_LEVEL)
BOOLEAN
QuicFrameLog(
    _In_opt_ QUIC_CONNECTION* Connection,
    _In_ BOOLEAN Rx,
    _In_ uint64_t PacketNumber,
    _In_ uint16_t PacketLength,
    _In_reads_bytes_(PacketLength)
        const uint8_t * const Packet,
    _Inout_ uint16_t* Offset
    )
{
    QUIC_VAR_INT FrameType INIT_NO_SAL(0);
    if (!QuicVarIntDecode(PacketLength, Packet, Offset, &FrameType)) {
        QuicTraceEvent(
            ConnError,
            "[conn][%p] ERROR, %s.",
            Connection,
            "Frame type decode failure");
        QuicConnTransportError(Connection, QUIC_ERROR_FRAME_ENCODING_ERROR);
        return FALSE;
    }

    if (!QUIC_FRAME_IS_KNOWN(FrameType)) {
        QuicTraceLogVerbose(
            FrameLogUnknownType,
            "[%c][%cX][%llu]   unknown frame (%llu)",
            PtkConnPre(Connection),
            PktRxPre(Rx),
            PacketNumber,
            FrameType);
        return FALSE;
    }

    switch (FrameType) {

    case QUIC_FRAME_PADDING: {
        uint16_t Start = *Offset;
        while (*Offset < PacketLength &&
            Packet[*Offset] == QUIC_FRAME_PADDING) {
            (*Offset) += sizeof(uint8_t);
        }
        QuicTraceLogVerbose(
            FrameLogPadding,
            "[%c][%cX][%llu]   PADDING Len:%hu",
            PtkConnPre(Connection),
            PktRxPre(Rx),
            PacketNumber,
            (uint16_t)((*Offset - Start) + 1));
        break;
    }

    case QUIC_FRAME_PING: {
        QuicTraceLogVerbose(
            FrameLogPing,
            "[%c][%cX][%llu]   PING",
            PtkConnPre(Connection),
            PktRxPre(Rx),
            PacketNumber);
        break;
    }

    case QUIC_FRAME_ACK:
    case QUIC_FRAME_ACK_1: {
        QUIC_ACK_EX Frame;
        if (!QuicAckHeaderDecode(PacketLength, Packet, Offset, &Frame)) {
            QuicTraceLogVerbose(
                FrameLogAckInvalid,
                "[%c][%cX][%llu]   ACK [Invalid]",
                PtkConnPre(Connection),
                PktRxPre(Rx),
                PacketNumber);
            return FALSE;
        }

        QuicTraceLogVerbose(
            FrameLogAck,
            "[%c][%cX][%llu]   ACK Largest:%llu Delay:%llu",
            PtkConnPre(Connection),
            PktRxPre(Rx),
            PacketNumber,
            Frame.LargestAcknowledged,
            Frame.AckDelay);

        if (Frame.FirstAckBlock == 0) {
            QuicTraceLogVerbose(
                FrameLogAckSingleBlock,
                "[%c][%cX][%llu]     %llu",
                PtkConnPre(Connection),
                PktRxPre(Rx),
                PacketNumber,
                Frame.LargestAcknowledged);
        } else {
            QuicTraceLogVerbose(
                FrameLogAckMultiBlock,
                "[%c][%cX][%llu]     %llu - %llu",
                PtkConnPre(Connection),
                PktRxPre(Rx),
                PacketNumber,
                Frame.LargestAcknowledged - Frame.FirstAckBlock,
                Frame.LargestAcknowledged);
        }

        Frame.LargestAcknowledged -= (Frame.FirstAckBlock + 1);

        for (uint64_t i = 0; i < Frame.AdditionalAckBlockCount; i++) {
            QUIC_ACK_BLOCK_EX Block;
            if (!QuicAckBlockDecode(PacketLength, Packet, Offset, &Block)) {
                QuicTraceLogVerbose(
                    FrameLogAckInvalidBlock,
                    "[%c][%cX][%llu]     [Invalid Block]",
                    PtkConnPre(Connection),
                    PktRxPre(Rx),
                    PacketNumber);
                return FALSE;
            }

            Frame.LargestAcknowledged -= (Block.Gap + 1);

            if (Block.AckBlock == 0) {
                QuicTraceLogVerbose(
                    FrameLogAckSingleBlock,
                    "[%c][%cX][%llu]     %llu",
                    PtkConnPre(Connection),
                    PktRxPre(Rx),
                    PacketNumber,
                    Frame.LargestAcknowledged);
            } else {
                QuicTraceLogVerbose(
                    FrameLogAckMultiBlock,
                    "[%c][%cX][%llu]     %llu - %llu",
                    PtkConnPre(Connection),
                    PktRxPre(Rx),
                    PacketNumber,
                    Frame.LargestAcknowledged - Block.AckBlock,
                    Frame.LargestAcknowledged);
            }

            Frame.LargestAcknowledged -= (Block.AckBlock + 1);
        }

        if (FrameType == QUIC_FRAME_ACK_1) {
            QUIC_ACK_ECN_EX Ecn;
            if (!QuicVarIntDecode(PacketLength, Packet, Offset, &Ecn.ECT_0_Count) ||
                !QuicVarIntDecode(PacketLength, Packet, Offset, &Ecn.ECT_1_Count) ||
                !QuicVarIntDecode(PacketLength, Packet, Offset, &Ecn.CE_Count)) {
                QuicTraceLogVerbose(
                    FrameLogAckEcnInvalid,
                    "[%c][%cX][%llu]     ECN [Invalid]",
                    PtkConnPre(Connection),
                    PktRxPre(Rx),
                    PacketNumber);
                return FALSE;
            }
            QuicTraceLogVerbose(
                FrameLogAckEcn,
                "[%c][%cX][%llu]     ECN [ECT0=%llu,ECT1=%llu,CE=%llu]",
                PtkConnPre(Connection),
                PktRxPre(Rx),
                PacketNumber,
                Ecn.ECT_0_Count,
                Ecn.ECT_1_Count,
                Ecn.CE_Count);
        }

        break;
    }

    case QUIC_FRAME_RESET_STREAM: {
        QUIC_RESET_STREAM_EX Frame;
        if (!QuicResetStreamFrameDecode(PacketLength, Packet, Offset, &Frame)) {
            QuicTraceLogVerbose(
                FrameLogResetStreamInvalid,
                "[%c][%cX][%llu]   RESET_STREAM [Invalid]",
                PtkConnPre(Connection),
                PktRxPre(Rx),
                PacketNumber);
            return FALSE;
        }

        QuicTraceLogVerbose(
            FrameLogResetStream,
            "[%c][%cX][%llu]   RESET_STREAM ID:%llu ErrorCode:0x%llX FinalSize:%llu",
            PtkConnPre(Connection),
            PktRxPre(Rx),
            PacketNumber,
            Frame.StreamID,
            Frame.ErrorCode,
            Frame.FinalSize);
        break;
    }

    case QUIC_FRAME_STOP_SENDING: {
        QUIC_STOP_SENDING_EX Frame;
        if (!QuicStopSendingFrameDecode(PacketLength, Packet, Offset, &Frame)) {
            QuicTraceLogVerbose(
                FrameLogStopSendingInvalid,
                "[%c][%cX][%llu]   STOP_SENDING [Invalid]",
                PtkConnPre(Connection),
                PktRxPre(Rx),
                PacketNumber);
            return FALSE;
        }

        QuicTraceLogVerbose(
            FrameLogStopSending,
            "[%c][%cX][%llu]   STOP_SENDING ID:%llu Error:0x%llX",
            PtkConnPre(Connection),
            PktRxPre(Rx),
            PacketNumber,
            Frame.StreamID,
            Frame.ErrorCode);
        break;
    }

    case QUIC_FRAME_CRYPTO: {
        QUIC_CRYPTO_EX Frame;
        if (!QuicCryptoFrameDecode(PacketLength, Packet, Offset, &Frame)) {
            QuicTraceLogVerbose(
                FrameLogCryptoInvalid,
                "[%c][%cX][%llu]   CRYPTO [Invalid]",
                PtkConnPre(Connection),
                PktRxPre(Rx),
                PacketNumber);
            return FALSE;
        }

        QuicTraceLogVerbose(
            FrameLogCrypto,
            "[%c][%cX][%llu]   CRYPTO Offset:%llu Len:%hu",
            PtkConnPre(Connection),
            PktRxPre(Rx),
            PacketNumber,
            Frame.Offset,
            (uint16_t)Frame.Length);

        break;
    }

    case QUIC_FRAME_NEW_TOKEN: {
        QUIC_NEW_TOKEN_EX Frame;
        if (!QuicNewTokenFrameDecode(PacketLength, Packet, Offset, &Frame)) {
            QuicTraceLogVerbose(
                FrameLogNewTokenInvalid,
                "[%c][%cX][%llu]   NEW_TOKEN [Invalid]",
                PtkConnPre(Connection),
                PktRxPre(Rx),
                PacketNumber);
            return FALSE;
        }

        QuicTraceLogVerbose(
            FrameLogNewToken,
            "[%c][%cX][%llu]   NEW_TOKEN Length:%llu",
            PtkConnPre(Connection),
            PktRxPre(Rx),
            PacketNumber,
            Frame.TokenLength);

        break;
    }

    case QUIC_FRAME_STREAM:
    case QUIC_FRAME_STREAM_1:
    case QUIC_FRAME_STREAM_2:
    case QUIC_FRAME_STREAM_3:
    case QUIC_FRAME_STREAM_4:
    case QUIC_FRAME_STREAM_5:
    case QUIC_FRAME_STREAM_6:
    case QUIC_FRAME_STREAM_7: {
        QUIC_STREAM_EX Frame;
        if (!QuicStreamFrameDecode(FrameType, PacketLength, Packet, Offset, &Frame)) {
            QuicTraceLogVerbose(
                FrameLogStreamInvalid,
                "[%c][%cX][%llu]   STREAM [Invalid]",
                PtkConnPre(Connection),
                PktRxPre(Rx),
                PacketNumber);
            return FALSE;
        }

        if (Frame.Fin) {
            QuicTraceLogVerbose(
                FrameLogStreamFin,
                "[%c][%cX][%llu]   STREAM ID:%llu Offset:%llu Len:%hu Fin",
                PtkConnPre(Connection),
                PktRxPre(Rx),
                PacketNumber,
                Frame.StreamID,
                Frame.Offset,
                (uint16_t)Frame.Length);
        } else {
            QuicTraceLogVerbose(
                FrameLogStream,
                "[%c][%cX][%llu]   STREAM ID:%llu Offset:%llu Len:%hu",
                PtkConnPre(Connection),
                PktRxPre(Rx),
                PacketNumber,
                Frame.StreamID,
                Frame.Offset,
                (uint16_t)Frame.Length);
        }

        break;
    }

    case QUIC_FRAME_MAX_DATA: {
        QUIC_MAX_DATA_EX Frame;
        if (!QuicMaxDataFrameDecode(PacketLength, Packet, Offset, &Frame)) {
            QuicTraceLogVerbose(
                FrameLogMaxDataInvalid,
                "[%c][%cX][%llu]   MAX_DATA [Invalid]",
                PtkConnPre(Connection),
                PktRxPre(Rx),
                PacketNumber);
            return FALSE;
        }

        QuicTraceLogVerbose(
            FrameLogMaxData,
            "[%c][%cX][%llu]   MAX_DATA Max:%llu",
            PtkConnPre(Connection),
            PktRxPre(Rx),
            PacketNumber,
            Frame.MaximumData);
        break;
    }

    case QUIC_FRAME_MAX_STREAM_DATA: {
        QUIC_MAX_STREAM_DATA_EX Frame;
        if (!QuicMaxStreamDataFrameDecode(PacketLength, Packet, Offset, &Frame)) {
            QuicTraceLogVerbose(
                FrameLogMaxStreamDataInvalid,
                "[%c][%cX][%llu]   MAX_STREAM_DATA [Invalid]",
                PtkConnPre(Connection),
                PktRxPre(Rx),
                PacketNumber);
            return FALSE;
        }

        QuicTraceLogVerbose(
            FrameLogMaxStreamData,
            "[%c][%cX][%llu]   MAX_STREAM_DATA ID:%llu Max:%llu",
            PtkConnPre(Connection),
            PktRxPre(Rx),
            PacketNumber,
            Frame.StreamID,
            Frame.MaximumData);
        break;
    }

    case QUIC_FRAME_MAX_STREAMS:
    case QUIC_FRAME_MAX_STREAMS_1: {
        QUIC_MAX_STREAMS_EX Frame;
        if (!QuicMaxStreamsFrameDecode(FrameType, PacketLength, Packet, Offset, &Frame)) {
            QuicTraceLogVerbose(
                FrameLogMaxStreamsInvalid,
                "[%c][%cX][%llu]   MAX_STREAMS [Invalid]",
                PtkConnPre(Connection),
                PktRxPre(Rx),
                PacketNumber);
            return FALSE;
        }

        QuicTraceLogVerbose(
            FrameLogMaxStreams,
            "[%c][%cX][%llu]   MAX_STREAMS[%hu] Count:%llu",
            PtkConnPre(Connection),
            PktRxPre(Rx),
            PacketNumber,
            Frame.BidirectionalStreams,
            Frame.MaximumStreams);
        break;
    }

    case QUIC_FRAME_DATA_BLOCKED: {
        QUIC_DATA_BLOCKED_EX Frame;
        if (!QuicDataBlockedFrameDecode(PacketLength, Packet, Offset, &Frame)) {
            QuicTraceLogVerbose(
                FrameLogDataBlockedInvalid,
                "[%c][%cX][%llu]   DATA_BLOCKED [Invalid]",
                PtkConnPre(Connection),
                PktRxPre(Rx),
                PacketNumber);
            return FALSE;
        }
        QuicTraceLogVerbose(
            FrameLogDataBlocked,
            "[%c][%cX][%llu]   DATA_BLOCKED Limit:%llu",
            PtkConnPre(Connection),
            PktRxPre(Rx),
            PacketNumber,
            Frame.DataLimit);
        break;
    }

    case QUIC_FRAME_STREAM_DATA_BLOCKED: {
        QUIC_STREAM_DATA_BLOCKED_EX Frame;
        if (!QuicStreamDataBlockedFrameDecode(PacketLength, Packet, Offset, &Frame)) {
            QuicTraceLogVerbose(
                FrameLogStreamDataBlockedInvalid,
                "[%c][%cX][%llu]   STREAM_DATA_BLOCKED [Invalid]",
                PtkConnPre(Connection),
                PktRxPre(Rx),
                PacketNumber);
            return FALSE;
        }

        QuicTraceLogVerbose(
            FrameLogStreamDataBlocked,
            "[%c][%cX][%llu]   STREAM_DATA_BLOCKED ID:%llu Limit:%llu",
            PtkConnPre(Connection),
            PktRxPre(Rx),
            PacketNumber,
            Frame.StreamID,
            Frame.StreamDataLimit);
        break;
    }

    case QUIC_FRAME_STREAMS_BLOCKED:
    case QUIC_FRAME_STREAMS_BLOCKED_1: {
        QUIC_STREAMS_BLOCKED_EX Frame;
        if (!QuicStreamsBlockedFrameDecode(FrameType, PacketLength, Packet, Offset, &Frame)) {
            QuicTraceLogVerbose(
                FrameLogStreamsBlockedInvalid,
                "[%c][%cX][%llu]   STREAMS_BLOCKED [Invalid]",
                PtkConnPre(Connection),
                PktRxPre(Rx),
                PacketNumber);
            return FALSE;
        }

        QuicTraceLogVerbose(
            FrameLogStreamsBlocked,
            "[%c][%cX][%llu]   STREAMS_BLOCKED[%hu] ID:%llu",
            PtkConnPre(Connection),
            PktRxPre(Rx),
            PacketNumber,
            Frame.BidirectionalStreams,
            Frame.StreamLimit);
        break;
    }

    case QUIC_FRAME_NEW_CONNECTION_ID: {
        QUIC_NEW_CONNECTION_ID_EX Frame;
        if (!QuicNewConnectionIDFrameDecode(PacketLength, Packet, Offset, &Frame)) {
            QuicTraceLogVerbose(
                FrameLogNewConnectionIDInvalid,
                "[%c][%cX][%llu]   NEW_CONN_ID [Invalid]",
                PtkConnPre(Connection),
                PktRxPre(Rx),
                PacketNumber);
            return FALSE;
        }

        QuicTraceLogVerbose(
            FrameLogNewConnectionID,
            "[%c][%cX][%llu]   NEW_CONN_ID Seq:%llu RPT:%llu CID:%s Token:%s",
            PtkConnPre(Connection),
            PktRxPre(Rx),
            PacketNumber,
            Frame.Sequence,
            Frame.RetirePriorTo,
            QuicCidBufToStr(Frame.Buffer, Frame.Length).Buffer,
            QuicCidBufToStr(Frame.Buffer + Frame.Length, QUIC_STATELESS_RESET_TOKEN_LENGTH).Buffer);
        break;
    }

    case QUIC_FRAME_RETIRE_CONNECTION_ID: {
        QUIC_RETIRE_CONNECTION_ID_EX Frame;
        if (!QuicRetireConnectionIDFrameDecode(PacketLength, Packet, Offset, &Frame)) {
            QuicTraceLogVerbose(
                FrameLogRetireConnectionIDInvalid,
                "[%c][%cX][%llu]   RETIRE_CONN_ID [Invalid]",
                PtkConnPre(Connection),
                PktRxPre(Rx),
                PacketNumber);
            return FALSE;
        }

        QuicTraceLogVerbose(
            FrameLogRetireConnectionID,
            "[%c][%cX][%llu]   RETIRE_CONN_ID Seq:%llu",
            PtkConnPre(Connection),
            PktRxPre(Rx),
            PacketNumber,
            Frame.Sequence);
        break;
    }

    case QUIC_FRAME_PATH_CHALLENGE: {
        QUIC_PATH_CHALLENGE_EX Frame;
        if (!QuicPathChallengeFrameDecode(PacketLength, Packet, Offset, &Frame)) {
            QuicTraceLogVerbose(
                FrameLogPathChallengeInvalid,
                "[%c][%cX][%llu]   PATH_CHALLENGE [Invalid]",
                PtkConnPre(Connection),
                PktRxPre(Rx),
                PacketNumber);
            return FALSE;
        }

        QuicTraceLogVerbose(
            FrameLogPathChallenge,
            "[%c][%cX][%llu]   PATH_CHALLENGE [%llu]",
            PtkConnPre(Connection),
            PktRxPre(Rx),
            PacketNumber,
            CxPlatByteSwapUint64(*(uint64_t*)Frame.Data));
        break;
    }

    case QUIC_FRAME_PATH_RESPONSE: {
        QUIC_PATH_RESPONSE_EX Frame;
        if (!QuicPathChallengeFrameDecode(PacketLength, Packet, Offset, &Frame)) {
            QuicTraceLogVerbose(
                FrameLogPathResponseInvalid,
                "[%c][%cX][%llu]   PATH_RESPONSE [Invalid]",
                PtkConnPre(Connection),
                PktRxPre(Rx),
                PacketNumber);
            return FALSE;
        }

        QuicTraceLogVerbose(
            FrameLogPathResponse,
            "[%c][%cX][%llu]   PATH_RESPONSE [%llu]",
            PtkConnPre(Connection),
            PktRxPre(Rx),
            PacketNumber,
            CxPlatByteSwapUint64(*(uint64_t*)Frame.Data));
        break;
    }

    case QUIC_FRAME_CONNECTION_CLOSE:
    case QUIC_FRAME_CONNECTION_CLOSE_1: {
        QUIC_CONNECTION_CLOSE_EX Frame;
        if (!QuicConnCloseFrameDecode(FrameType, PacketLength, Packet, Offset, &Frame)) {
            QuicTraceLogVerbose(
                FrameLogConnectionCloseInvalid,
                "[%c][%cX][%llu]   CONN_CLOSE [Invalid]",
                PtkConnPre(Connection),
                PktRxPre(Rx),
                PacketNumber);
            return FALSE;
        }

        if (Frame.ApplicationClosed) {
            QuicTraceLogVerbose(
                FrameLogConnectionCloseApp,
                "[%c][%cX][%llu]   CONN_CLOSE (App) ErrorCode:0x%llX",
                PtkConnPre(Connection),
                PktRxPre(Rx),
                PacketNumber,
                Frame.ErrorCode);
        } else {
            QuicTraceLogVerbose(
                FrameLogConnectionClose,
                "[%c][%cX][%llu]   CONN_CLOSE ErrorCode:0x%llX FrameType:%llu",
                PtkConnPre(Connection),
                PktRxPre(Rx),
                PacketNumber,
                Frame.ErrorCode,
                Frame.FrameType);
        }
        break;
    }

    case QUIC_FRAME_HANDSHAKE_DONE: {
        QuicTraceLogVerbose(
            FrameLogHandshakeDone,
            "[%c][%cX][%llu]   HANDSHAKE_DONE",
            PtkConnPre(Connection),
            PktRxPre(Rx),
            PacketNumber);
        break;
    }

    case QUIC_FRAME_DATAGRAM:
    case QUIC_FRAME_DATAGRAM_1: {
        QUIC_DATAGRAM_EX Frame;
        if (!QuicDatagramFrameDecode(FrameType, PacketLength, Packet, Offset, &Frame)) {
            QuicTraceLogVerbose(
                FrameLogDatagramInvalid,
                "[%c][%cX][%llu]   DATAGRAM [Invalid]",
                PtkConnPre(Connection),
                PktRxPre(Rx),
                PacketNumber);
            return FALSE;
        }
        QuicTraceLogVerbose(
            FrameLogDatagram,
            "[%c][%cX][%llu]   DATAGRAM Len:%hu",
            PtkConnPre(Connection),
            PktRxPre(Rx),
            PacketNumber,
            (uint16_t)Frame.Length);
        break;
    }

    case QUIC_FRAME_ACK_FREQUENCY: {
        QUIC_ACK_FREQUENCY_EX Frame;
        if (!QuicAckFrequencyFrameDecode(PacketLength, Packet, Offset, &Frame)) {
            QuicTraceLogVerbose(
                FrameLogAckFrequencyInvalid,
                "[%c][%cX][%llu]   ACK_FREQUENCY [Invalid]",
                PtkConnPre(Connection),
                PktRxPre(Rx),
                PacketNumber);
            return FALSE;
        }

        QuicTraceLogVerbose(
            FrameLogAckFrequency,
            "[%c][%cX][%llu]   ACK_FREQUENCY SeqNum:%llu PktTolerance:%llu MaxAckDelay:%llu IgnoreOrder:%hhu IgnoreCE:%hhu",
            PtkConnPre(Connection),
            PktRxPre(Rx),
            PacketNumber,
            Frame.SequenceNumber,
            Frame.PacketTolerance,
            Frame.UpdateMaxAckDelay,
            Frame.IgnoreOrder,
            Frame.IgnoreCE);
        break;
    }

    case QUIC_FRAME_IMMEDIATE_ACK: {
        QuicTraceLogVerbose(
            FrameLogImmediateAck,
            "[%c][%cX][%llu]   IMMEDIATE_ACK",
            PtkConnPre(Connection),
            PktRxPre(Rx),
            PacketNumber);
        break;
    }

    default:
        CXPLAT_FRE_ASSERT(FALSE);
        break;
    }

    return TRUE;
}

_IRQL_requires_max_(DISPATCH_LEVEL)
void
QuicFrameLogAll(
    _In_opt_ QUIC_CONNECTION* Connection,
    _In_ BOOLEAN Rx,
    _In_ uint64_t PacketNumber,
    _In_ uint16_t PacketLength,
    _In_reads_bytes_(PacketLength)
        const uint8_t * const Packet,
    _In_ uint16_t Offset
    )
{
    BOOLEAN ProcessFrames = TRUE;
    while (ProcessFrames && Offset < PacketLength) {
        ProcessFrames =
            QuicFrameLog(
                Connection,
                Rx,
                PacketNumber,
                PacketLength,
                Packet,
                &Offset);
    }
}
