using System;
using System.Net;

namespace QuicTrace.DataModel
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
