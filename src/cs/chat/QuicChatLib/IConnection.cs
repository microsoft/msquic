using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace QuicChatLib
{
    public interface IConnection
    {
        void Shutdown();
    }
}
