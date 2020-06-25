// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using System;
using System.Collections.Generic;

namespace QuicDataServer.Models.Db
{
    public class DbTestRecord
    {
        public int DbTestRecordId { get; set; }
        public int DbTestId { get; set; }
        public int DbMachineId { get; set; }
        public DateTime TestDate { get; set; }
        public string CommitHash { get; set; } = null!;
        public ICollection<TestResult> TestResults { get; set; } = null!;
    }
}
