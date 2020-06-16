// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using System.Collections.Generic;

namespace QuicDataServer.Models.Db
{
    public class DbTest
    {
        public int DbTestId { get; set; }
        public int DbPlatformId { get; set; }
        public string TestName { get; set; } = null!;
        public ICollection<DbTestRecord> TestRecords { get; set; } = null!;
    }
}
