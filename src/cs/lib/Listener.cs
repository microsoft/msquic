using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Microsoft.Quic;

namespace Microsoft.Quic
{
    public unsafe sealed class Listener : IDisposable
    {
        private QUIC_HANDLE* handle;
        private readonly QUIC_API_TABLE* table;

        public QUIC_HANDLE* Handle => handle;

        internal Listener(QUIC_HANDLE* handle, QUIC_API_TABLE* table)
        {
            this.handle = handle;
            this.table = table;
        }

        public void Close()
        {
            if (handle != null)
            {
                table->ListenerClose(handle);
                handle = null;
            }
        }

        public void Dispose()
        {
            Close();
        }
    }
}
