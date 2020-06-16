// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#pragma warning disable CS8618 // Non-nullable field is uninitialized. Consider declaring as nullable.

using System.ComponentModel.DataAnnotations;

namespace QuicDataServer.Models
{
    public class PlatformCreate : IAuthorizable
    {
        [Required]
        public string PlatformName { get; set; }
        [Required]
        public string AuthKey { get; set; }
    }
}
