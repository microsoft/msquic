using System.Collections.Generic;

namespace QuicDataServer.Models.Db
{
    public class DbPlatform
    {
#pragma warning disable CS8618 // Non-nullable field is uninitialized. Consider declaring as nullable.
        public int DbPlatformId { get; set; }
        public string PlatformName { get; set; }

        public ICollection<DbTest> Tests { get; set; }
#pragma warning restore CS8618 // Non-nullable field is uninitialized. Consider declaring as nullable.
    }
}
