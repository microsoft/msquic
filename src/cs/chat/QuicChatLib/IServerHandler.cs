using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace QuicChatLib
{
    public interface IServerHandler
    {
        bool AddStream(Stream stream);
    }
}
