/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.

--*/

using System;
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

        public static string QUIC_FLAGS(uint value)
        {
            return "QUIC_FLAGS (good!) " + value;
        }

        public static string QUIC_IP_ADDR(byte[] value)
        {
            int len = value.Length;
            IntPtr i = System.Runtime.InteropServices.Marshal.AllocHGlobal(len);
            System.Runtime.InteropServices.Marshal.Copy(value, 0, i, len);
            string msg = "";
            SocketAddress sa2 = (SocketAddress)System.Runtime.InteropServices.Marshal.PtrToStructure(i, typeof(SocketAddress));

            switch (sa2.si_family)
            {
                case 0:  //<--unspecified
                    msg += "Unspecified";
                    break;
                case 23: //<--v6
                    msg += "IPV6: sin6_flowinfo=" + sa2.sin6_flowinfo + " port=" + sa2.sin_port + "part1=" + sa2.S_v6Addr1 + ", part2=" + sa2.S_v6Addr2;
                    break;
                case 10:  //<--v6 (linux)
                    msg += "IPV6: sin6_flowinfo=" + sa2.sin6_flowinfo + " port=" + sa2.sin_port + "part1=" + sa2.S_v6Addr1 + ", part2=" + sa2.S_v6Addr2;
                    break;
                case 2:  //< --v4
                    msg += "IPV4:" + sa2.S_addr + ":" + sa2.sin_port;
                    break;
                default:
                    throw new Exception("Invalid SI_FAMILY : " + sa2.si_family);
            }

            System.Runtime.InteropServices.Marshal.FreeHGlobal(i);
            return msg;
        }

        public static string DecodeCID(byte [] value)
        {
            return "CID!";
        }
    }
}