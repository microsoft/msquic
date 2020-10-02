// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using System;
using System.Collections.Generic;

namespace QuicDataServer.Models.Db
{
    public class DbHpsTestRecord
    {
        public int DbHpsTestRecordId { get; set; }
        public int DbMachineId { get; set; }
        public int DbPlatformId { get; set; }
        public DateTime TestDate { get; set; }
        public string CommitHash { get; set; } = null!;
        public ICollection<HpsTestResult> TestResults { get; set; } = null!;
    }
}
