// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;

namespace QuicDataServer.Models
{
    public class TestRecord
    {
        [Required]
        public string MachineName { get; set; } = null!;
        [Required]
        public string PlatformName { get; set; } = null!;
        [Required]
        public string TestName { get; set; } = null!;
        [Required]
        public string CommitHash { get; set; } = null!;
        [Required]
        public DateTime ResultDate { get; set; }
        [Required]
        public IEnumerable<double> IndividualRunResults { get; set; } = null!;
    }
}
