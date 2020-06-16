// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#pragma warning disable CS8618 // Non-nullable field is uninitialized. Consider declaring as nullable.

using System;
using System.Collections.Generic;

namespace QuicDataServer.Models.Db
{
    public class DbTestRecord
    {
        public int DbTestRecordId { get; set; }
        public int DbTestId { get; set; }
        public DateTime TestDate { get; set; }
        public string CommitHash { get; set; }
        public ICollection<TestResult> TestResults { get; set; }
    }
}
