// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using System.ComponentModel.DataAnnotations;

namespace QuicDataServer.Models
{
    public class HpsRequest
    {
        [Required]
        public string PlatformName { get; set; } = null!;
    }
}
