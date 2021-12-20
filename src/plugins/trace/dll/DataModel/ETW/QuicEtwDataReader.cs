//
// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
//

using System;
using System.Collections.Generic;
using System.Net;
using System.Runtime.InteropServices;

namespace QuicTrace.DataModel.ETW
{
    internal unsafe ref struct QuicEtwDataReader
    {
        private ReadOnlySpan<byte> Data;

        private readonly int PointerSize;

        internal QuicEtwDataReader(void* pointer, int length, int pointerSize)
        {
            Data = new ReadOnlySpan<byte>(pointer, length);
            PointerSize = pointerSize;
        }

        internal unsafe T ReadValue<T>() where T : unmanaged
        {
            T val = MemoryMarshal.Cast<byte, T>(Data)[0];
            Data = Data.Slice(sizeof(T));
            return val;
        }

        internal byte ReadByte() => ReadValue<byte>();

        internal ushort ReadUShort() => ReadValue<ushort>();

        internal uint ReadUInt() => ReadValue<uint>();

        internal ulong ReadULong() => ReadValue<ulong>();

        internal ulong ReadPointer()
        {
            return PointerSize == 8 ? ReadValue<ulong>() : ReadValue<uint>();
        }

        internal ReadOnlySpan<byte> ReadBytes()
        {
            return Data.Slice(0, ReadValue<byte>());
        }

        internal string ReadString()
        {
            var chars = new List<char>();
            while (true)
            {
                byte c = ReadValue<byte>();
                if (c == 0)
                {
                    break;
                }
                chars.Add((char)c);
            }
            return new string(chars.ToArray());
        }

        internal IPEndPoint ReadAddress()
        {
            byte length = ReadValue<byte>();
            if (length == 0)
            {
                return new IPEndPoint(IPAddress.None, 0);
            }
            var buf = Data.Slice(0, length);
            Data = Data.Slice(length);

            int family = buf[0] | ((ushort)buf[1] << 8);
            int port = (ushort)buf[3] | ((ushort)buf[2] << 8);

            if (family == 0) // unspecified
            {
                return new IPEndPoint(IPAddress.Any, port);
            }
            else if (family == 2) // v4
            {
                return new IPEndPoint(new IPAddress(buf.Slice(4, 4)), port);
            }
            else // v6
            {
                return new IPEndPoint(new IPAddress(buf.Slice(4, 16)), port);
            }
        }
    }
}
