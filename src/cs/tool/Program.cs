using System;
using Microsoft.Quic;

namespace tool
{
    class Program
    {
        static unsafe void Main(string[] args)
        {
            QUIC_API_TABLE* ApiTable;
            MsQuic.MsQuicOpen(&ApiTable);
        }
    }
}
