using Microsoft.EntityFrameworkCore;
using QuicDataServer.Models.Db;

namespace QuicDataServer.Data
{
    public class PerformanceContext : DbContext
    {
#pragma warning disable CS8618 // Non-nullable field is uninitialized. Consider declaring as nullable.
        public PerformanceContext(DbContextOptions<PerformanceContext> options) : base(options)
#pragma warning restore CS8618 // Non-nullable field is uninitialized. Consider declaring as nullable.
        {

        }

        public DbSet<DbPlatform> Platforms { get; set; }
        public DbSet<DbTest> Tests { get; set; }
        public DbSet<DbTestRecord> TestRecords { get; set; }

    }
}
