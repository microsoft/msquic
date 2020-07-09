// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;

namespace QuicDataServer.Models
{
    public class TestPublishResultWithTime : IAuthorizable
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
        public DateTime Time { get; set; }
        [Required]
        public IEnumerable<double> IndividualRunResults { get; set; } = null!;
    }
}
