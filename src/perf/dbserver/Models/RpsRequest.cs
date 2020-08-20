using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.Linq;
using System.Threading.Tasks;

namespace QuicDataServer.Models
{
    public class RpsRequest
    {
        [Required]
        public string PlatformName { get; set; } = null!;

        [Required]
        public int ConnectionCount { get; set; }
        [Required]
        public int RequestSize { get; set; }
        [Required]
        public int ResponseSize { get; set; }
        [Required]
        public int ParallelRequests { get; set; }
    }
}
