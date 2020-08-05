// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using System;
using System.Collections.Generic;

namespace QuicDataServer.Models.Db
{
    public class DbThroughputTestRecord
    {
        public int DbThroughputTestRecordId { get; set; }
        public int DbMachineId { get; set; }
        public int DbPlatformId { get; set; }
        public bool Loopback { get; set; }
        public bool Encryption { get; set; }
        public bool SendBuffering { get; set; }
        public int NumberOfStreams { get; set; }
        public bool ServerToClient { get; set; }
        public DateTime TestDate { get; set; }
        public string CommitHash { get; set; } = null!;
        public ICollection<ThroughputTestResult> TestResults { get; set; } = null!;
    }
}
