// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using System.ComponentModel.DataAnnotations;

namespace QuicDataServer.Models
{
    public class TestCreate : IAuthorizable
    {
#pragma warning disable CS8618 // Non-nullable field is uninitialized. Consider declaring as nullable.
        [Required]
        public string TestName { get; set; }
        [Required]
        public string PlatformName { get; set; }
        [Required]
        public string AuthKey { get; set; }
#pragma warning restore CS8618 // Non-nullable field is uninitialized. Consider declaring as nullable.
    }
}
