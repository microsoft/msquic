// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;

namespace QuicDataServer.Models
{
    public class RpsTestPublishResult : IAuthorizable
    {
        public string? MachineName { get; set; }
        [Required]
        public string PlatformName { get; set; } = null!;
        [Required]
        public string TestName { get; set; } = null!;
        [Required]
        public string CommitHash { get; set; } = null!;
        [Required]
        public string AuthKey { get; set; } = null!;
        [Required]
        public IEnumerable<double> IndividualRunResults { get; set; } = null!;

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
