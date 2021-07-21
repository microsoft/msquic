using System;
using Microsoft.Quic;

namespace Microsoft.Quic
{
    public sealed unsafe class QuicApi : IDisposable
    {
        private readonly QUIC_API_TABLE* table;

        public QUIC_API_TABLE* ApiTable => table;

        public QuicApi()
        {
            table = MsQuic.Open();
        }

        public static implicit operator QUIC_API_TABLE*(QuicApi api)
        {
            return api.table;
        }

        public void Dispose()
        {
            MsQuic.Close(table);
        }

        public Registration OpenRegistration(QUIC_REGISTRATION_CONFIG* config)
        {
            QUIC_HANDLE* handle = null;
            int status = table->RegistrationOpen(config, &handle);
            MsQuic.ThrowIfFailure(status);
            return new Registration(handle, table);
        }
    }
}
