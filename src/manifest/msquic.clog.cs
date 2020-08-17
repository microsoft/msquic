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
        public static string ADDR(byte[] value)
        {
            int si_family = value[0] | ((ushort)value[1] << 8);
            int sin_port = value[2] | ((ushort)value[3] << 8);

            byte[] sa2;

            string msg = "";

            switch (si_family)
            {
                case 0:  //<--unspecified
                    msg += $"*:{sin_port}";
                    break;
                case 2:  //< --v4
                    sa2 = new byte[4];
                    Array.Copy(value, 4, sa2, 0, 4);
                    msg += $"{new IPAddress(sa2).ToString()}:{sin_port}";
                    break;
                case 10:  //<--v6 (linux)
                case 23: //<--v6
                    sa2 = new byte[16];
                    Array.Copy(value, 8, sa2, 0, 16);
                    msg += $"[{new IPAddress(sa2).ToString()}]:{sin_port}";
                    break;
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
