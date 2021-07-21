using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Microsoft.Quic;

namespace Microsoft.Quic
{
    public unsafe sealed class Registration : IDisposable
    {
        private QUIC_HANDLE* regHandle;
        private readonly QUIC_API_TABLE* table;

        public QUIC_HANDLE* Handle => regHandle;

        internal Registration(QUIC_HANDLE* handle, QUIC_API_TABLE* table)
        {
            this.regHandle = handle;
            this.table = table;
        }

        public Listener OpenListener(delegate* unmanaged[Cdecl]<QUIC_HANDLE*, void*, QUIC_LISTENER_EVENT*, int> callback, void* context)
        {
            QUIC_HANDLE* listenerHandle = null;
            int status = table->ListenerOpen(regHandle, callback, context, &listenerHandle);
            MsQuic.ThrowIfFailure(status);
            return new Listener(listenerHandle, table);
        }

        public Connection OpenClientConnection(delegate* unmanaged[Cdecl]<QUIC_HANDLE*, void*, QUIC_CONNECTION_EVENT*, int> callback, void* context)
        {
            QUIC_HANDLE* connectionHandle = null;
            int status = table->ConnectionOpen(regHandle, callback, context, &connectionHandle);
            MsQuic.ThrowIfFailure(status);
            return new Connection(connectionHandle, table);
        }

        public Configuration OpenConfiguration(QUIC_BUFFER* alpns, uint alpnsLength, QUIC_SETTINGS* settings, uint settingsSize, void* context)
        {
            QUIC_HANDLE* configurationHandle = null;
            int status = table->ConfigurationOpen(regHandle, alpns, alpnsLength, settings, settingsSize, context, &configurationHandle);
            MsQuic.ThrowIfFailure(status);
            return new Configuration(configurationHandle, table);
        }

        public void Shutdown(QUIC_CONNECTION_SHUTDOWN_FLAGS flags, ulong errorCode)
        {
            table->RegistrationShutdown(regHandle, flags, errorCode);
        }

        public void Close()
        {
            if (regHandle != null)
            {
                table->RegistrationClose(regHandle);
                regHandle = null;
            }
        }

        public void Dispose()
        {
            Close();
        }
    }
}
