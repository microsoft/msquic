// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using System;
using System.Collections.Generic;

namespace QuicDataServer.Models.Db
{
    public class DbTestRecord
    {
#pragma warning disable CS8618 // Non-nullable field is uninitialized. Consider declaring as nullable.
        public int DbTestRecordId { get; set; }
        public int DbTestId { get; set; }
        public DateTime TestDate { get; set; }
        public string CommitHash { get; set; }

        public ICollection<TestResult> TestResults { get; set; }
#pragma warning restore CS8618 // Non-nullable field is uninitialized. Consider declaring as nullable.
    }
}
