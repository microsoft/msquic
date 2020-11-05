using System;

namespace MsQuicTracing.DataModel
{
    internal class QuicWorkerCreatedEtwPayload : QuicWorkerCreatedPayload
    {
        internal QuicWorkerCreatedEtwPayload(ReadOnlySpan<byte> data, int pointerSize)
        {
            IdealProcessor = data.ReadValue<ushort>();
            OwnerPointer = data.ReadPointer(pointerSize);
        }
    }

    internal class QuicWorkerActivityStateUpdatedEtwPayload : QuicWorkerActivityStateUpdatedPayload
    {
        internal QuicWorkerActivityStateUpdatedEtwPayload(ReadOnlySpan<byte> data)
        {
            IsActive = data.ReadValue<byte>();
            Arg = data.ReadValue<uint>();
        }
    }

    internal class QuicWorkerQueueDelayUpdatedEtwPayload : QuicWorkerQueueDelayUpdatedPayload
    {
        internal QuicWorkerQueueDelayUpdatedEtwPayload(ReadOnlySpan<byte> data)
        {
            QueueDelay = data.ReadValue<uint>();
        }
    }
}
