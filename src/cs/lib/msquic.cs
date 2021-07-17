//
// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
//

using System;
using System.Diagnostics;
using System.Runtime.InteropServices;

namespace Microsoft.Quic
{
    public unsafe partial struct QUIC_BUFFER
    {
        public Span<byte> Span => new(Buffer, (int)Length);
    }

    public partial class MsQuic
    {
        public static unsafe QUIC_API_TABLE* Open()
        {
            QUIC_API_TABLE* ApiTable;
            int Status = MsQuicOpenVersion(1, (void**)&ApiTable);
            ThrowIfFailure(Status);
            return ApiTable;
        }

        public static unsafe void Close(QUIC_API_TABLE* ApiTable)
        {
            MsQuicClose(ApiTable);
        }

        public static void ThrowIfFailure(int status)
        {
            if (StatusFailed(status))
            {
                // TODO make custom exception, and maybe throw helpers
                throw new Exception($"Failed with code {status}");
            }
        }

        public static bool StatusSucceeded(int status)
        {
            if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
            {
                return status >= 0;
            }
            else
            {
                return status <= 0;
            }
        }

        public static bool StatusFailed(int status)
        {
            if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
            {
                return status < 0;
            }
            else
            {
                return status > 0;
            }
        }

        public static readonly int QUIC_STATUS_SUCCESS = RuntimeInformation.IsOSPlatform(OSPlatform.Windows) ? MsQuic_Windows.QUIC_STATUS_SUCCESS : MsQuic_Posix.QUIC_STATUS_SUCCESS;
        public static readonly int QUIC_STATUS_ABORTED = RuntimeInformation.IsOSPlatform(OSPlatform.Windows) ? MsQuic_Windows.QUIC_STATUS_ABORTED : MsQuic_Posix.QUIC_STATUS_ABORTED;
        public static readonly int QUIC_STATUS_PENDING = RuntimeInformation.IsOSPlatform(OSPlatform.Windows) ? MsQuic_Windows.QUIC_STATUS_PENDING : MsQuic_Posix.QUIC_STATUS_PENDING;
        public static readonly int QUIC_STATUS_CONTINUE = RuntimeInformation.IsOSPlatform(OSPlatform.Windows) ? MsQuic_Windows.QUIC_STATUS_CONTINUE : MsQuic_Posix.QUIC_STATUS_CONTINUE;

        public const int QUIC_ADDRESS_FAMILY_UNSPEC = 0;
        public const int QUIC_ADDRESS_FAMILY_INET = 2;
        public const int QUIC_ADDRESS_FAMILY_INET6 = 23;
    }

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
        public ushort sin_family;
        public ushort sin_port;
        public byte sin_addr0;
        public byte sin_addr1;
        public byte sin_addr2;
        public byte sin_addr3;

        public byte[] Address
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
        public ushort _family;
        public ushort _port;
        public uint _flowinfo;
        public byte _addr0;
        public byte _addr1;
        public byte _addr2;
        public byte _addr3;
        public byte _addr4;
        public byte _addr5;
        public byte _addr6;
        public byte _addr7;
        public byte _addr8;
        public byte _addr9;
        public byte _addr10;
        public byte _addr11;
        public byte _addr12;
        public byte _addr13;
        public byte _addr14;
        public byte _addr15;
        public uint _scope_id;

        public byte[] Address
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
        public QuicAddrIn Ipv4;
        [FieldOffset(0)]
        public QuicAddrIn6 Ipv6;
        [FieldOffset(0)]
        public ushort si_family;
    }
}
