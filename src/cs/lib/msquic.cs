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

        public static readonly int QUIC_STATUS_SUCCESS = RuntimeInformation.IsOSPlatform(OSPlatform.Windows) ? MsQuic_Windows.QUIC_STATUS_SUCCESS : RuntimeInformation.IsOSPlatform(OSPlatform.OSX) ? MsQuic_MacOS.QUIC_STATUS_SUCCESS : MsQuic_Linux.QUIC_STATUS_SUCCESS;
        public static readonly int QUIC_STATUS_PENDING = RuntimeInformation.IsOSPlatform(OSPlatform.Windows) ? MsQuic_Windows.QUIC_STATUS_PENDING : RuntimeInformation.IsOSPlatform(OSPlatform.OSX) ? MsQuic_MacOS.QUIC_STATUS_PENDING : MsQuic_Linux.QUIC_STATUS_PENDING;
        public static readonly int QUIC_STATUS_CONTINUE = RuntimeInformation.IsOSPlatform(OSPlatform.Windows) ? MsQuic_Windows.QUIC_STATUS_CONTINUE : RuntimeInformation.IsOSPlatform(OSPlatform.OSX) ? MsQuic_MacOS.QUIC_STATUS_CONTINUE : MsQuic_Linux.QUIC_STATUS_CONTINUE;
        public static readonly int QUIC_STATUS_OUT_OF_MEMORY = RuntimeInformation.IsOSPlatform(OSPlatform.Windows) ? MsQuic_Windows.QUIC_STATUS_OUT_OF_MEMORY : RuntimeInformation.IsOSPlatform(OSPlatform.OSX) ? MsQuic_MacOS.QUIC_STATUS_OUT_OF_MEMORY : MsQuic_Linux.QUIC_STATUS_OUT_OF_MEMORY;
        public static readonly int QUIC_STATUS_INVALID_PARAMETER = RuntimeInformation.IsOSPlatform(OSPlatform.Windows) ? MsQuic_Windows.QUIC_STATUS_INVALID_PARAMETER : RuntimeInformation.IsOSPlatform(OSPlatform.OSX) ? MsQuic_MacOS.QUIC_STATUS_INVALID_PARAMETER : MsQuic_Linux.QUIC_STATUS_INVALID_PARAMETER;
        public static readonly int QUIC_STATUS_INVALID_STATE = RuntimeInformation.IsOSPlatform(OSPlatform.Windows) ? MsQuic_Windows.QUIC_STATUS_INVALID_STATE : RuntimeInformation.IsOSPlatform(OSPlatform.OSX) ? MsQuic_MacOS.QUIC_STATUS_INVALID_STATE : MsQuic_Linux.QUIC_STATUS_INVALID_STATE;
        public static readonly int QUIC_STATUS_NOT_SUPPORTED = RuntimeInformation.IsOSPlatform(OSPlatform.Windows) ? MsQuic_Windows.QUIC_STATUS_NOT_SUPPORTED : RuntimeInformation.IsOSPlatform(OSPlatform.OSX) ? MsQuic_MacOS.QUIC_STATUS_NOT_SUPPORTED : MsQuic_Linux.QUIC_STATUS_NOT_SUPPORTED;
        public static readonly int QUIC_STATUS_NOT_FOUND = RuntimeInformation.IsOSPlatform(OSPlatform.Windows) ? MsQuic_Windows.QUIC_STATUS_NOT_FOUND : RuntimeInformation.IsOSPlatform(OSPlatform.OSX) ? MsQuic_MacOS.QUIC_STATUS_NOT_FOUND : MsQuic_Linux.QUIC_STATUS_NOT_FOUND;
        public static readonly int QUIC_STATUS_BUFFER_TOO_SMALL = RuntimeInformation.IsOSPlatform(OSPlatform.Windows) ? MsQuic_Windows.QUIC_STATUS_BUFFER_TOO_SMALL : RuntimeInformation.IsOSPlatform(OSPlatform.OSX) ? MsQuic_MacOS.QUIC_STATUS_BUFFER_TOO_SMALL : MsQuic_Linux.QUIC_STATUS_BUFFER_TOO_SMALL;
        public static readonly int QUIC_STATUS_HANDSHAKE_FAILURE = RuntimeInformation.IsOSPlatform(OSPlatform.Windows) ? MsQuic_Windows.QUIC_STATUS_HANDSHAKE_FAILURE : RuntimeInformation.IsOSPlatform(OSPlatform.OSX) ? MsQuic_MacOS.QUIC_STATUS_HANDSHAKE_FAILURE : MsQuic_Linux.QUIC_STATUS_HANDSHAKE_FAILURE;
        public static readonly int QUIC_STATUS_ABORTED = RuntimeInformation.IsOSPlatform(OSPlatform.Windows) ? MsQuic_Windows.QUIC_STATUS_ABORTED : RuntimeInformation.IsOSPlatform(OSPlatform.OSX) ? MsQuic_MacOS.QUIC_STATUS_ABORTED : MsQuic_Linux.QUIC_STATUS_ABORTED;
        public static readonly int QUIC_STATUS_ADDRESS_IN_USE = RuntimeInformation.IsOSPlatform(OSPlatform.Windows) ? MsQuic_Windows.QUIC_STATUS_ADDRESS_IN_USE : RuntimeInformation.IsOSPlatform(OSPlatform.OSX) ? MsQuic_MacOS.QUIC_STATUS_ADDRESS_IN_USE : MsQuic_Linux.QUIC_STATUS_ADDRESS_IN_USE;
        public static readonly int QUIC_STATUS_CONNECTION_TIMEOUT = RuntimeInformation.IsOSPlatform(OSPlatform.Windows) ? MsQuic_Windows.QUIC_STATUS_CONNECTION_TIMEOUT : RuntimeInformation.IsOSPlatform(OSPlatform.OSX) ? MsQuic_MacOS.QUIC_STATUS_CONNECTION_TIMEOUT : MsQuic_Linux.QUIC_STATUS_CONNECTION_TIMEOUT;
        public static readonly int QUIC_STATUS_CONNECTION_IDLE = RuntimeInformation.IsOSPlatform(OSPlatform.Windows) ? MsQuic_Windows.QUIC_STATUS_CONNECTION_IDLE : RuntimeInformation.IsOSPlatform(OSPlatform.OSX) ? MsQuic_MacOS.QUIC_STATUS_CONNECTION_IDLE : MsQuic_Linux.QUIC_STATUS_CONNECTION_IDLE;
        public static readonly int QUIC_STATUS_UNREACHABLE = RuntimeInformation.IsOSPlatform(OSPlatform.Windows) ? MsQuic_Windows.QUIC_STATUS_UNREACHABLE : RuntimeInformation.IsOSPlatform(OSPlatform.OSX) ? MsQuic_MacOS.QUIC_STATUS_UNREACHABLE : MsQuic_Linux.QUIC_STATUS_UNREACHABLE;
        public static readonly int QUIC_STATUS_INTERNAL_ERROR = RuntimeInformation.IsOSPlatform(OSPlatform.Windows) ? MsQuic_Windows.QUIC_STATUS_INTERNAL_ERROR : RuntimeInformation.IsOSPlatform(OSPlatform.OSX) ? MsQuic_MacOS.QUIC_STATUS_INTERNAL_ERROR : MsQuic_Linux.QUIC_STATUS_INTERNAL_ERROR;
        public static readonly int QUIC_STATUS_CONNECTION_REFUSED = RuntimeInformation.IsOSPlatform(OSPlatform.Windows) ? MsQuic_Windows.QUIC_STATUS_CONNECTION_REFUSED : RuntimeInformation.IsOSPlatform(OSPlatform.OSX) ? MsQuic_MacOS.QUIC_STATUS_CONNECTION_REFUSED : MsQuic_Linux.QUIC_STATUS_CONNECTION_REFUSED;
        public static readonly int QUIC_STATUS_PROTOCOL_ERROR = RuntimeInformation.IsOSPlatform(OSPlatform.Windows) ? MsQuic_Windows.QUIC_STATUS_PROTOCOL_ERROR : RuntimeInformation.IsOSPlatform(OSPlatform.OSX) ? MsQuic_MacOS.QUIC_STATUS_PROTOCOL_ERROR : MsQuic_Linux.QUIC_STATUS_PROTOCOL_ERROR;
        public static readonly int QUIC_STATUS_VER_NEG_ERROR = RuntimeInformation.IsOSPlatform(OSPlatform.Windows) ? MsQuic_Windows.QUIC_STATUS_VER_NEG_ERROR : RuntimeInformation.IsOSPlatform(OSPlatform.OSX) ? MsQuic_MacOS.QUIC_STATUS_VER_NEG_ERROR : MsQuic_Linux.QUIC_STATUS_VER_NEG_ERROR;
        public static readonly int QUIC_STATUS_TLS_ERROR = RuntimeInformation.IsOSPlatform(OSPlatform.Windows) ? MsQuic_Windows.QUIC_STATUS_TLS_ERROR : RuntimeInformation.IsOSPlatform(OSPlatform.OSX) ? MsQuic_MacOS.QUIC_STATUS_TLS_ERROR : MsQuic_Linux.QUIC_STATUS_TLS_ERROR;
        public static readonly int QUIC_STATUS_USER_CANCELED = RuntimeInformation.IsOSPlatform(OSPlatform.Windows) ? MsQuic_Windows.QUIC_STATUS_USER_CANCELED : RuntimeInformation.IsOSPlatform(OSPlatform.OSX) ? MsQuic_MacOS.QUIC_STATUS_USER_CANCELED : MsQuic_Linux.QUIC_STATUS_USER_CANCELED;
        public static readonly int QUIC_STATUS_ALPN_NEG_FAILURE = RuntimeInformation.IsOSPlatform(OSPlatform.Windows) ? MsQuic_Windows.QUIC_STATUS_ALPN_NEG_FAILURE : RuntimeInformation.IsOSPlatform(OSPlatform.OSX) ? MsQuic_MacOS.QUIC_STATUS_ALPN_NEG_FAILURE : MsQuic_Linux.QUIC_STATUS_ALPN_NEG_FAILURE;
        public static readonly int QUIC_STATUS_STREAM_LIMIT_REACHED = RuntimeInformation.IsOSPlatform(OSPlatform.Windows) ? MsQuic_Windows.QUIC_STATUS_STREAM_LIMIT_REACHED : RuntimeInformation.IsOSPlatform(OSPlatform.OSX) ? MsQuic_MacOS.QUIC_STATUS_STREAM_LIMIT_REACHED : MsQuic_Linux.QUIC_STATUS_STREAM_LIMIT_REACHED;
        public static readonly int QUIC_STATUS_CLOSE_NOTIFY = RuntimeInformation.IsOSPlatform(OSPlatform.Windows) ? MsQuic_Windows.QUIC_STATUS_CLOSE_NOTIFY : RuntimeInformation.IsOSPlatform(OSPlatform.OSX) ? MsQuic_MacOS.QUIC_STATUS_CLOSE_NOTIFY : MsQuic_Linux.QUIC_STATUS_CLOSE_NOTIFY;
        public static readonly int QUIC_STATUS_BAD_CERTIFICATE = RuntimeInformation.IsOSPlatform(OSPlatform.Windows) ? MsQuic_Windows.QUIC_STATUS_BAD_CERTIFICATE : RuntimeInformation.IsOSPlatform(OSPlatform.OSX) ? MsQuic_MacOS.QUIC_STATUS_BAD_CERTIFICATE : MsQuic_Linux.QUIC_STATUS_BAD_CERTIFICATE;
        public static readonly int QUIC_STATUS_UNSUPPORTED_CERTIFICATE = RuntimeInformation.IsOSPlatform(OSPlatform.Windows) ? MsQuic_Windows.QUIC_STATUS_UNSUPPORTED_CERTIFICATE : RuntimeInformation.IsOSPlatform(OSPlatform.OSX) ? MsQuic_MacOS.QUIC_STATUS_UNSUPPORTED_CERTIFICATE : MsQuic_Linux.QUIC_STATUS_UNSUPPORTED_CERTIFICATE;
        public static readonly int QUIC_STATUS_REVOKED_CERTIFICATE = RuntimeInformation.IsOSPlatform(OSPlatform.Windows) ? MsQuic_Windows.QUIC_STATUS_REVOKED_CERTIFICATE : RuntimeInformation.IsOSPlatform(OSPlatform.OSX) ? MsQuic_MacOS.QUIC_STATUS_REVOKED_CERTIFICATE : MsQuic_Linux.QUIC_STATUS_REVOKED_CERTIFICATE;
        public static readonly int QUIC_STATUS_EXPIRED_CERTIFICATE = RuntimeInformation.IsOSPlatform(OSPlatform.Windows) ? MsQuic_Windows.QUIC_STATUS_EXPIRED_CERTIFICATE : RuntimeInformation.IsOSPlatform(OSPlatform.OSX) ? MsQuic_MacOS.QUIC_STATUS_EXPIRED_CERTIFICATE : MsQuic_Linux.QUIC_STATUS_EXPIRED_CERTIFICATE;
        public static readonly int QUIC_STATUS_UNKNOWN_CERTIFICATE = RuntimeInformation.IsOSPlatform(OSPlatform.Windows) ? MsQuic_Windows.QUIC_STATUS_UNKNOWN_CERTIFICATE : RuntimeInformation.IsOSPlatform(OSPlatform.OSX) ? MsQuic_MacOS.QUIC_STATUS_UNKNOWN_CERTIFICATE : MsQuic_Linux.QUIC_STATUS_UNKNOWN_CERTIFICATE;
        public static readonly int QUIC_STATUS_CERT_EXPIRED = RuntimeInformation.IsOSPlatform(OSPlatform.Windows) ? MsQuic_Windows.QUIC_STATUS_CERT_EXPIRED : RuntimeInformation.IsOSPlatform(OSPlatform.OSX) ? MsQuic_MacOS.QUIC_STATUS_CERT_EXPIRED : MsQuic_Linux.QUIC_STATUS_CERT_EXPIRED;
        public static readonly int QUIC_STATUS_CERT_UNTRUSTED_ROOT = RuntimeInformation.IsOSPlatform(OSPlatform.Windows) ? MsQuic_Windows.QUIC_STATUS_CERT_UNTRUSTED_ROOT : RuntimeInformation.IsOSPlatform(OSPlatform.OSX) ? MsQuic_MacOS.QUIC_STATUS_CERT_UNTRUSTED_ROOT : MsQuic_Linux.QUIC_STATUS_CERT_UNTRUSTED_ROOT;


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
