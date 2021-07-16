using System;
using System.Text;
using Microsoft.Quic;

namespace QuicChatLib
{
    public unsafe class Registration : IDisposable
    {
        private QUIC_API_TABLE* table;

        public ref QUIC_API_TABLE Table => ref *table;


        public QUIC_HANDLE* Handle { get; }

        public Registration()
        {
            table = MsQuic.Open();
            QUIC_HANDLE* handle = null;
            QUIC_REGISTRATION_CONFIG config;
            config.ExecutionProfile = QUIC_EXECUTION_PROFILE.QUIC_EXECUTION_PROFILE_LOW_LATENCY;
            byte* name = stackalloc byte[10];
            Span<byte> nameSpan = new Span<byte>(name, 10);
            int writeLen = Encoding.UTF8.GetBytes("QuicChat", nameSpan);
            nameSpan[writeLen] = 0;
            config.AppName = name;
            int status = table->RegistrationOpen(&config, &handle);
            if (MsQuic.StatusFailed(status))
            {
                MsQuic.Close(table);
                table = null;
                MsQuic.ThrowIfFailure(status);
            }
            Handle = handle;
        }

        public void Shutdown(ulong ErrorCode)
        {
            Table.RegistrationShutdown(Handle, QUIC_CONNECTION_SHUTDOWN_FLAGS.QUIC_CONNECTION_SHUTDOWN_FLAG_NONE, ErrorCode);
        }

        public void Dispose()
        {
            if (table != null)
            {
                if (Handle != null)
                {
                    table->RegistrationClose(Handle);
                }
                MsQuic.Close(table);
            }
        }
    }
}
