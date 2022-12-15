using System;
using System.Collections.Generic;
using System.Net;
using System.Text;

namespace QuicTrace.DataModel.ETW
{
    internal interface IDataReader
    {
        T ReadValue<T>() where T : unmanaged;
        byte ReadByte() => ReadValue<byte>();
        ushort ReadUShort() => ReadValue<ushort>();
        uint ReadUInt() => ReadValue<uint>();
        ulong ReadULong() => ReadValue<ulong>();
        ulong ReadPointer();
        ReadOnlySpan<byte> ReadBytes();
        string ReadString();
        IPEndPoint ReadAddress();
    }
}
