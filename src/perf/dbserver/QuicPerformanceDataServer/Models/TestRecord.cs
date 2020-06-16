// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#pragma warning disable CS8618 // Non-nullable field is uninitialized. Consider declaring as nullable.

using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;

namespace QuicDataServer.Models
{
    public class TestRecord
    {
        [Required]
        public string PlatformName { get; set; }
        [Required]
        public string TestName { get; set; }
        [Required]
        public string CommitHash { get; set; }
        [Required]
        public DateTime ResultDate { get; set; }
        [Required]
        public IEnumerable<double> IndividualRunResults { get; set; }
    }
}
