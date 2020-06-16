using Microsoft.EntityFrameworkCore.Internal;
using Newtonsoft.Json;
using QuicDataServer.Models;
using QuicDataServer.Models.Db;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Http;
using System.Threading.Tasks;

namespace QuicDataServer.Data
{
    public static class DbInitializer
    {
        public static async Task Initialize(PerformanceContext context)
        {
            if (context == null)
            {
                throw new ArgumentNullException(nameof(context));
            }

            await context.Database.EnsureCreatedAsync().ConfigureAwait(false);
            if (context.Platforms.Any())
            {
                return; // DB has been seeded
            }

            context.Platforms.Add(new DbPlatform
            {
                PlatformName = "Windows_x64_stub",
            });

            context.Platforms.Add(new DbPlatform
            {
                PlatformName = "Linux_x64_openssl"
            });

            await context.SaveChangesAsync().ConfigureAwait(false);
            

            var plat = context.Platforms.Where(x => x.PlatformName == "Windows_x64_stub").FirstOrDefault();

            plat.Tests = new List<DbTest>();

            plat.Tests.Add(new DbTest
            {
                TestName = "loopback",
            });

            plat = context.Platforms.Where(x => x.PlatformName == "Linux_x64_openssl").FirstOrDefault();

            plat.Tests = new List<DbTest>();

            plat.Tests.Add(new DbTest
            {
                DbPlatformId = 2,
                TestName = "loopback",
            });

            await context.SaveChangesAsync().ConfigureAwait(false);

            using HttpClient client = new HttpClient();

            var seedUri = new Uri("https://raw.githubusercontent.com/ThadHouse/msquic/dbseed/seeddata.json");

            var seedDataStr = await client.GetStringAsync(seedUri).ConfigureAwait(false);

            var seedData = JsonConvert.DeserializeObject<TestRecord[]>(seedDataStr);

            Dictionary<string, DbTest> keyMap = new Dictionary<string, DbTest>()
            {

            };

            keyMap["Windows_x64_stub"] = context.Platforms.Where(x => x.PlatformName == "Windows_x64_stub").Select(x => x.Tests).First().First();
            keyMap["Linux_x64_openssl"] = context.Platforms.Where(x => x.PlatformName == "Linux_x64_openssl").Select(x => x.Tests).First().First();
            ;


            foreach (var data in seedData)
            {
                var record = new DbTestRecord
                {
                    CommitHash = data.CommitHash,
                    TestDate = data.ResultDate,
                    TestResults = data.IndividualRunResults.Select(x => new TestResult { Result = x }).ToList(),
                };
                var test = keyMap[data.PlatformName];
                if (test.TestRecords == null)
                {
                    test.TestRecords = new List<DbTestRecord>();
                }
                test.TestRecords.Add(record);
            }

            await context.SaveChangesAsync().ConfigureAwait(false);
        }
    }
}
