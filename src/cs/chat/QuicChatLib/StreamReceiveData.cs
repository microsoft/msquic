using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Microsoft.Quic;

namespace QuicChatLib
{
    public unsafe struct StreamReceiveData
    {
        public Stream Stream { get; init; }
        public DataReceiveTag Tag { get; init; }
        public Memory<byte>? Buffer { get; init; }
    }
}
