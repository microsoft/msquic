using System;
using System.Diagnostics;
using System.Runtime.InteropServices;

//ClangSharpPInvokeGenerator -f ..\inc\msquic.h -n Microsoft.Quic -o .\lib\msquic_generated.cs -m MsQuic -l msquic -c exclude-enum-operators

namespace Microsoft.Quic
{
    /// <summary>Defines the type of a member as it was used in the native signature.</summary>
    [AttributeUsage(AttributeTargets.Enum | AttributeTargets.Property | AttributeTargets.Field | AttributeTargets.Parameter | AttributeTargets.ReturnValue, AllowMultiple = false, Inherited = true)]
    [Conditional("DEBUG")]
    internal sealed class NativeTypeNameAttribute : Attribute
    {
        private readonly string _name;

        /// <summary>Initializes a new instance of the <see cref="NativeTypeNameAttribute" /> class.</summary>
        /// <param name="name">The name of the type that was used in the native signature.</param>
        public NativeTypeNameAttribute(string name)
        {
            _name = name;
        }

        /// <summary>Gets the name of the type that was used in the native signature.</summary>
        public string Name => _name;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct QuicAddrIn
    {
        internal ushort sin_family;
        internal ushort sin_port;
        internal byte sin_addr0;
        internal byte sin_addr1;
        internal byte sin_addr2;
        internal byte sin_addr3;

        internal byte[] Address
        {
            get
            {
                return new byte[] { sin_addr0, sin_addr1, sin_addr2, sin_addr3 };
            }
        }
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct QuicAddrIn6
    {
        internal ushort _family;
        internal ushort _port;
        internal uint _flowinfo;
        internal byte _addr0;
        internal byte _addr1;
        internal byte _addr2;
        internal byte _addr3;
        internal byte _addr4;
        internal byte _addr5;
        internal byte _addr6;
        internal byte _addr7;
        internal byte _addr8;
        internal byte _addr9;
        internal byte _addr10;
        internal byte _addr11;
        internal byte _addr12;
        internal byte _addr13;
        internal byte _addr14;
        internal byte _addr15;
        internal uint _scope_id;

        internal byte[] Address
        {
            get
            {
                return new byte[] {
                    _addr0, _addr1, _addr2, _addr3,
                    _addr4, _addr5, _addr6, _addr7,
                    _addr8, _addr9, _addr10, _addr11,
                    _addr12, _addr13, _addr14, _addr15 };
            }
        }
    }

    [StructLayout(LayoutKind.Explicit)]
    public struct QuicAddr
    {
        [FieldOffset(0)]
        internal QuicAddrIn Ipv4;
        [FieldOffset(0)]
        internal QuicAddrIn6 Ipv6;
        [FieldOffset(0)]
        internal ushort si_family;
    }
}
