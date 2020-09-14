// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using System.Collections.Generic;

namespace QuicDataServer.Models.Db
{
    public class DbPlatform
    {
        public int DbPlatformId { get; set; }
        public string PlatformName { get; set; } = null!;

        public ICollection<DbTest> Tests { get; set; } = null!;

        public ICollection<DbThroughputTestRecord> ThroughputTests { get; set; } = null!;
        public ICollection<DbRpsTestRecord> RpsTests { get; set; } = null!;
        public ICollection<DbHpsTestRecord> HpsTests { get; set; } = null!;
    }
}
