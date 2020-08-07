// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;

namespace QuicDataServer.Models
{
    public class ThroughputTestPublishResultWithTime : IAuthorizable
    {
        public string? MachineName { get; set; }
        [Required]
        public string PlatformName { get; set; } = null!;
        [Required]
        public string CommitHash { get; set; } = null!;
        [Required]
        public string AuthKey { get; set; } = null!;
        [Required]
        public DateTime Time { get; set; }
        [Required]
        public IEnumerable<double> IndividualRunResults { get; set; } = null!;

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
