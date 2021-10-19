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
            if (value.Length == 0)
            {
                return "None";
            }

            int si_family = value[0] | ((ushort)value[1] << 8);
            int sin_port = value[3] | ((ushort)value[2] << 8);

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

        public static string VNL(byte [] value)
        {
            if (value.Length == 0) {
                return "Empty";
            }
            if (value.Length < 4)
            {
                return "Invalid";
            }
            StringBuilder hex = new StringBuilder(
                (value.Length * 2) +                    // Hex length for all characters
                ((value.Length / sizeof(int)) - 1));    // Space for commas, if list is long enough.

            for (int i = 0; value.Length - i >= sizeof(int); i += sizeof(int))
            {
                int Version = (int)(value[i] << 24) | (int)(value[i + 1] << 16) | (int)(value[i + 2] << 8) | (int)(value[i + 3]);
                hex.Append(Version.ToString("X8"));
                if (value.Length - (i + sizeof(int)) >= sizeof(int)) {
                    hex.Append(",");
                }
            }
            return hex.ToString();
        }

        public static string ALPN(byte [] value)
        {
            if (value.Length == 0) {
                return "Empty";
            }
            UTF8Encoding utf8 = new UTF8Encoding(false, true);
            StringBuilder AlpnList = new StringBuilder(value.Length);
            uint i = 0;
            while (i < value.Length)
            {
                uint AlpnLength = value[i];
                i++;
                if (AlpnLength > value.Length - i)
                {
                    // Alpn longer than remaining buffer, print to the end.
                    AlpnLength = (uint)value.Length - i;
                }
                try {
                    String CurrentAlpn = utf8.GetString(value, (int)i, (int)AlpnLength);
                    AlpnList.Append(CurrentAlpn);
                    i += AlpnLength;
                } catch {
                    // Fall back to printing hex
                    for (; AlpnLength > 0; AlpnLength--, i++)
                    {
                        AlpnList.Append(value[i].ToString("x2"));
                        if (AlpnLength > 1) {
                            AlpnList.Append(",");
                        }
                    }
                }
                if (i < value.Length)
                {
                    AlpnList.Append(';');
                }
            }
            return AlpnList.ToString();
        }
    }
}
