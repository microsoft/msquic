// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using System.ComponentModel.DataAnnotations;

namespace QuicDataServer.Models
{
    public class TestCreate : IAuthorizable
    {
        [Required]
        public string TestName { get; set; } = null!;
        [Required]
        public string PlatformName { get; set; } = null!;
        [Required]
        public string AuthKey { get; set; } = null!;
    }
}
