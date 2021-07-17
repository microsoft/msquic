using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Channels;
using System.Threading.Tasks;

namespace QuicChatLib
{
    public interface IDataReceiver
    {
        public Channel<StreamReceiveData> ReceiveChannel { get; }
    }
}
