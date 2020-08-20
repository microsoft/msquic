// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using System;
using System.Collections.Generic;

namespace QuicDataServer.Models.Db
{
    public class DbRpsTestRecord
    {
        public int DbRpsTestRecordId { get; set; }
        public int DbMachineId { get; set; }
        public int DbPlatformId { get; set; }
        public int ConnectionCount { get; set; }
        public int RequestSize { get; set; }
        public int ResponseSize { get; set; }
        public int ParallelRequests { get; set; }
        public DateTime TestDate { get; set; }
        public string CommitHash { get; set; } = null!;
        public ICollection<RpsTestResult> TestResults { get; set; } = null!;
    }
}
