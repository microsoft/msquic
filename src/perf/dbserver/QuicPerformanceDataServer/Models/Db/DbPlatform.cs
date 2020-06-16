// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#pragma warning disable CS8618 // Non-nullable field is uninitialized. Consider declaring as nullable.

using System.Collections.Generic;

namespace QuicDataServer.Models.Db
{
    public class DbPlatform
    {
        public int DbPlatformId { get; set; }
        public string PlatformName { get; set; }
        public ICollection<DbTest> Tests { get; set; }
    }
}
