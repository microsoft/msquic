using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.Linq;
using System.Threading.Tasks;

namespace QuicDataServer.Models
{
    public class ThroughputRequest
    {
        [Required]
        public string PlatformName { get; set; } = null!;

        [Required]
        public bool Loopback { get; set; }
        [Required]
        public bool Encryption { get; set; }
        [Required]
        public bool SendBuffering { get; set; }
        [Required]
        public int NumberOfStreams { get; set; }
        [Required]
        public bool ServerToClient { get; set; }
    }
}
