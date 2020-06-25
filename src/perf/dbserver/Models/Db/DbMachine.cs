// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using System.Collections.Generic;

namespace QuicDataServer.Models.Db
{
    public class DbMachine
    {
        public int DbMachineId { get; set; }
        public string MachineName { get; set; } = null!;
        public string Description { get; set; } = null!;
        public string OperatingSystem { get; set; } = null!;
        public string CPUInfo { get; set; } = null!;
        public string MemoryInfo { get; set; } = null!;
        public string NicInfo { get; set; } = null!;
        public string ExtraInfo { get; set; } = null!;

        public ICollection<DbTestRecord> TestRecords { get; set; } = null!;
    }
}
