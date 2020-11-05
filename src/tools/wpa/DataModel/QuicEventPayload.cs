//
// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
//

using System;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;

namespace MsQuicTracing.DataModel
{
    internal static class SpanHelpers
    {
        internal static T ReadValue<T>(this ref ReadOnlySpan<byte> data) where T : unmanaged
        {
            T val = MemoryMarshal.Cast<byte, T>(data)[0];
            data = data.Slice(Unsafe.SizeOf<T>());
            return val;
        }
        internal static ulong ReadPointer(this ref ReadOnlySpan<byte> data, int pointerSize)
        {
            return pointerSize == 8 ? data.ReadValue<ulong>() : data.ReadValue<uint>();
        }
    }

    public class QuicWorkerCreatedPayload
    {
        public ushort IdealProcessor { get; protected set; }

        public ulong OwnerPointer { get; protected set; }
    }

    public class QuicWorkerActivityStateUpdatedPayload
    {
        public byte IsActive { get; protected set; }

        public uint Arg { get; protected set; }
    }

    public class QuicWorkerQueueDelayUpdatedPayload
    {
        public uint QueueDelay { get; protected set; }
    }
}
