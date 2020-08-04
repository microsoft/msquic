/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.

--*/

using System;
using System.Text;
using System.Net;
using System.Runtime.InteropServices;

namespace msquic.clog_config
{
    public class Types
    {
        [StructLayout(LayoutKind.Explicit)]
        public struct SocketAddress
        {
            [FieldOffset(0)]
            public ushort si_family;

            [FieldOffset(2)]
            public ushort sin_port;

            // IPv4
            [FieldOffset(4)]
            public ulong S_addr;


            // IPv6
            [FieldOffset(4)]
            public ulong sin6_flowinfo;

            [FieldOffset(8)]
            public ulong S_v6Addr1;

            [FieldOffset(16)]
            public ulong S_v6Addr2;
        };

        public static string ADDR(byte[] value)
        {
            int si_family = value[0] | ((ushort)value[1] << 8);
            int sin_port = value[2] | ((ushort)value[3] << 8);

            Span<byte> sa2 = value;

            string msg = "";

            switch (si_family)
            {
                case 0:  //<--unspecified
                    msg += $"*:{sin_port}";
                    break;
                case 2:  //< --v4
                    msg += $"{new IPAddress(sa2.Slice(4, 4)).ToString()}:{sin_port}";
                    break;
                case 10:  //<--v6 (linux)
                case 23: //<--v6
                {
                    uint flowInfo = value[4] | ((uint)value[5] << 8) | ((uint)value[6] << 16) | ((uint)value[7] << 24);
                    msg += $"flowinfo={flowInfo.ToString("X8")} [{new IPAddress(sa2.Slice(8, 16)).ToString()}]:{sin_port}";
                    break;
                }
                default:
                    throw new NotSupportedException("Invalid SI_FAMILY : " + si_family);
            }
            
            return msg;
        }

        public static string CID(byte [] value)
        {
            StringBuilder hex = new StringBuilder(value.Length * 2);
            foreach (byte v in value)
            {
                hex.AppendFormat(v.ToString("X2"));
            }
            return hex.ToString();
        }
    }
}
