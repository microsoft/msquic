using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Microsoft.Quic
{
    public sealed unsafe class Configuration : IDisposable
    {
        private QUIC_HANDLE* handle;
        private readonly QUIC_API_TABLE* table;

        public QUIC_HANDLE* Handle => handle;

        internal Configuration(QUIC_HANDLE* handle, QUIC_API_TABLE* table)
        {
            this.handle = handle;
            this.table = table;
        }

        public void LoadCredential(QUIC_CREDENTIAL_CONFIG* config)
        {
            table->ConfigurationLoadCredential(handle, config);
        }

        public void Close()
        {
            if (handle != null)
            {
                table->ConfigurationClose(handle);
                handle = null;
            }
        }

        public void Dispose()
        {
            Close();
        }
    }
}
