// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#pragma warning disable CS8618 // Non-nullable field is uninitialized. Consider declaring as nullable.

using System.Collections.Generic;

namespace QuicDataServer.Models.Db
{
    public class DbTest
    {
        public int DbTestId { get; set; }
        public int DbPlatformId { get; set; }
        public string TestName { get; set; }
        public ICollection<DbTestRecord> TestRecords { get; set; }
    }
}
