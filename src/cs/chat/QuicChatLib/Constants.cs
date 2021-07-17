using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace QuicChatLib
{
    public static class Constants
    {
        public static readonly ushort Port = 5678;
        public static readonly byte[] Alpn = new byte[] { (byte)'Q', (byte)'C', (byte)'H', (byte)'A', (byte)'T' };
    }
}
