// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using System.Collections.Generic;

namespace QuicDataServer.Models.Db
{
    public class DbMachine
    {
        public int DbMachineId { get; set; }
        public string MachineName { get; set; } = null!;
        public string? Description { get; set; }
        public string? OperatingSystem { get; set; }
        public string? CPUInfo { get; set; }
        public string? MemoryInfo { get; set; }
        public string? NicInfo { get; set; }
        public string? ExtraInfo { get; set; }

        public ICollection<DbTestRecord> TestRecords { get; set; } = null!;

        public ICollection<DbThroughputTestRecord> ThroughputTestRecords { get; set; } = null!;

        public ICollection<DbRpsTestRecord> RpsTestRecords { get; set; } = null!;
        public ICollection<DbHpsTestRecord> HpsTestRecords { get; set; } = null!;
    }
}
