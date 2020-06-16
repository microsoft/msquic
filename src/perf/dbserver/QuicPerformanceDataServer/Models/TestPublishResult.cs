// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;

namespace QuicDataServer.Models
{
    public class TestPublishResult : IAuthorizable
    {
#pragma warning disable CS8618 // Non-nullable field is uninitialized. Consider declaring as nullable.
        [Required]
        public string PlatformName { get; set; }
        [Required]
        public string TestName { get; set; }
        [Required]
        public string CommitHash { get; set; }
        [Required]
        public string AuthKey { get; set; }
        [Required]
        public IEnumerable<double> IndividualRunResults { get; set; }
#pragma warning restore CS8618 // Non-nullable field is uninitialized. Consider declaring as nullable.
    }
}
