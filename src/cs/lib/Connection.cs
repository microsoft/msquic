using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Microsoft.Quic;

namespace Microsoft.Quic
{
    public sealed unsafe class Connection : IDisposable
    {
        private QUIC_HANDLE* handle;
        private readonly QUIC_API_TABLE* table;

        public QUIC_HANDLE* Handle => handle;

        internal Connection(QUIC_HANDLE* handle, QUIC_API_TABLE* table)
        {
            this.handle = handle;
            this.table = table;
        }

        public void Start(QUIC_HANDLE* configuration, ushort family, byte* server, ushort port)
        {
            int status = table->ConnectionStart(handle, configuration, family, server, port);
            MsQuic.ThrowIfFailure(status);
        }

        public void Start(Configuration configuration, ushort family, byte* server, ushort port)
        {
            Start(configuration.Handle, family, server, port);
        }

        public void Close()
        {
            if (handle != null)
            {
                table->ConnectionClose(handle);
                handle = null;
            }
        }

        public void Dispose()
        {
            Close();
        }
    }
}
