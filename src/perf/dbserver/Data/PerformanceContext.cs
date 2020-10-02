// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using Microsoft.EntityFrameworkCore;
using QuicDataServer.Models.Db;

namespace QuicDataServer.Data
{
    public class PerformanceContext : DbContext
    {

        public PerformanceContext(DbContextOptions<PerformanceContext> options) : base(options)
        {

        }

        public DbSet<DbPlatform> Platforms { get; set; } = null!;

        public DbSet<DbTest> Tests { get; set; } = null!;
        public DbSet<DbTestRecord> TestRecords { get; set; } = null!;

        public DbSet<DbThroughputTestRecord> ThroughputTestRecords { get; set; } = null!;
        public DbSet<DbRpsTestRecord> RpsTestRecords { get; set; } = null!;
        public DbSet<DbHpsTestRecord> HpsTestRecords { get; set; } = null!;

        public DbSet<DbMachine> Machines { get; set; } = null!;

    }
}
