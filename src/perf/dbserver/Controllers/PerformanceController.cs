// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using System;
using System.Collections;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;
using QuicDataServer.Data;
using QuicDataServer.Models;
using QuicDataServer.Models.Db;

#pragma warning disable CA2007 // Consider calling ConfigureAwait on the awaited task

namespace QuicDataServer.Controllers
{

    [ApiController]
    [Route("[controller]")]
    public class PerformanceController : ControllerBase
    {
        private readonly PerformanceContext _context;
        private readonly ILogger<PerformanceController> _logger;
        private readonly IConfiguration _configuration;

        public PerformanceController(ILogger<PerformanceController> logger, PerformanceContext context,
            IConfiguration configuration)
        {
            _context = context;
            _logger = logger;
            _configuration = configuration;
        }

        /// <summary>
        /// Get a list of all runs and results for all platforms
        /// </summary>
        /// <returns>A list of all test runs ever done</returns>
        [HttpGet]
        public async Task<IEnumerable<TestRecord>> Get()
        {
            var query = _context.Platforms.SelectMany(x => x.Tests, (platform, test) => new { platform, test })
                .SelectMany(x => x.test.TestRecords, (plattest, testrun) => new { plattest.platform, plattest.test, testrun })
                .Select(x => new TestRecord
                {
                    CommitHash = x.testrun.CommitHash,
                    IndividualRunResults = x.testrun.TestResults.Select(x => x.Result),
                    PlatformName = x.platform.PlatformName,
                    TestName = x.test.TestName,
                    ResultDate = x.testrun.TestDate,
                    MachineName = _context.Machines.Where(y => y.DbMachineId == x.testrun.DbMachineId).Select(y => y.MachineName).First()
                });

            return await query.ToListAsync();
        }

        /// <summary>
        /// Get a list of all tests that are configured to be used
        /// </summary>
        /// <returns>A list of all tests and platforms</returns>
        [HttpGet("allTests")]
        public async Task<IEnumerable> GetAllTests()
        {
            return await _context.Platforms.SelectMany(x => x.Tests, (platform, test) => new { platform.PlatformName, test.TestName }).ToListAsync();
        }

        /// <summary>
        /// Get the latest test result for a specific platform and test
        /// </summary>
        /// <param name="platform">The platform</param>
        /// <param name="test">The test</param>
        /// <returns>The latest result</returns>
        [HttpGet("{platform}/{test}")]
        public async Task<TestRecord> GetLatestTestResultForPlatformAndTest(string platform, string test)
        {
            return await _context.Platforms.Where(x => x.PlatformName == platform)
                .SelectMany(x => x.Tests)
                .Where(x => x.TestName == test)
                .SelectMany(x => x.TestRecords)
                .OrderByDescending(x => x.TestDate)
                .Select(x => new TestRecord
                {
                    CommitHash = x.CommitHash,
                    IndividualRunResults = x.TestResults.Select(x => x.Result),
                    PlatformName = platform,
                    TestName = test,
                    ResultDate = x.TestDate,
                    MachineName = _context.Machines.Where(y => y.DbMachineId == x.DbMachineId).Select(y => y.MachineName).First()
                })
                .FirstOrDefaultAsync();
        }

        /// <summary>
        /// Get the last N test results for a specific platform and test.
        /// </summary>
        /// <param name="platform">The platform</param>
        /// <param name="test">The test</param>
        /// <param name="numResults">The number of results to return</param>
        /// <returns>A list of the last N runs</returns>
        [HttpGet("{platform}/{test}/{numResults}")]
        public async Task<IEnumerable<TestRecord>> GetTestResultsForPlatformAndTest(string platform, string test, int numResults)
        {
            return await _context.Platforms.Where(x => x.PlatformName == platform)
                .SelectMany(x => x.Tests)
                .Where(x => x.TestName == test)
                .SelectMany(x => x.TestRecords)
                .OrderByDescending(x => x.TestDate)
                .Select(x => new TestRecord
                {
                    CommitHash = x.CommitHash,
                    IndividualRunResults = x.TestResults.Select(x => x.Result),
                    PlatformName = platform,
                    TestName = test,
                    ResultDate = x.TestDate
                })
                .Take(numResults)
                .ToListAsync();
        }

        private bool Authorize(IAuthorizable authorization)
        {
            return authorization.AuthKey == _configuration["ApiAuthorizationKey"];
        }

        private async Task<(int testId, int machineId)> VerifyPlatformTestAndMachine(string platformName, string testName, string? machineName)
        {
            var testId = await _context.Platforms.SelectMany(x => x.Tests, (platform, test) => new { platform, test })
                .Where(x => x.test.TestName == testName && x.platform.PlatformName == platformName)
                .Select(x => (int?)x.test.DbTestId)
                .FirstOrDefaultAsync();

            var machineId = await _context.Machines.Where(x => x.MachineName == machineName)
                .Select(x => (int?)x.DbMachineId)
                .FirstOrDefaultAsync();

            if (string.IsNullOrWhiteSpace(machineName))
            {
                machineId = 1;
            }

            if (testId != null && machineId != null)
            {
                return (testId.Value, machineId.Value);
            }

            // If machineId == null create
            if (machineId == null)
            {
                var entity = _context.Machines.Add(new DbMachine
                {
                    CPUInfo = "",
                    Description = "",
                    ExtraInfo = "",
                    MemoryInfo = "",
                    NicInfo = "",
                    OperatingSystem = "",
                    MachineName = machineName!
                });
                await _context.SaveChangesAsync();
                machineId = entity.Entity.DbMachineId;
            }

            if (testId != null)
            {
                return (testId.Value, machineId.Value);
            }

            var platformId = await _context.Platforms.Where(x => x.PlatformName == platformName)
                .Select(x => (int?)x.DbPlatformId).FirstOrDefaultAsync();
            if (platformId == null)
            {
                // Create platform
                var entity = _context.Platforms.Add(new DbPlatform
                {
                    PlatformName = platformName,
                });
                await _context.SaveChangesAsync();
                platformId = entity.Entity.DbPlatformId;
            }

            var testEntity = _context.Tests.Add(new DbTest
            {
                DbPlatformId = platformId.Value,
                TestName = testName
            });
            await _context.SaveChangesAsync();
            return (testEntity.Entity.DbTestId, machineId.Value);
        }


        /// <summary>
        /// Adds a new test result, with the time specified in the submitted data.
        /// </summary>
        /// <remarks>
        /// This is usually used for seeding the DB and adding missing runs. For common use, use the publish without time.
        /// </remarks>
        /// <param name="testResult">The data to add</param>
        /// <returns>The success result</returns>
        /// <response code="200">On success</response>
        /// <response code="401">Missing or incorrect Auth Key</response>
        [HttpPost("withTime")]
        [ProducesResponseType(StatusCodes.Status200OK)]
        [ProducesResponseType(StatusCodes.Status401Unauthorized)]
        public async Task<IActionResult> PublishTestResultWithTime([FromBody] TestPublishResultWithTime testResult)
        {
            if (testResult == null)
            {
                throw new ArgumentNullException(nameof(testResult));
            }

            if (!Authorize(testResult))
            {
                return Unauthorized();
            }

            // Get Test Records 
            (var testId, var machineId) = await VerifyPlatformTestAndMachine(testResult.PlatformName, testResult.TestName, testResult.MachineName);

            var newRecord = new DbTestRecord
            {
                CommitHash = testResult.CommitHash,
                TestDate = testResult.Time,
                TestResults = testResult.IndividualRunResults.Select(x => new TestResult { Result = x }).ToList(),
                DbMachineId = machineId,
                DbTestId = testId,
            };

            _context.TestRecords.Add(newRecord);

            await _context.SaveChangesAsync();

            return Ok();
        }

        /// <summary>
        /// Adds a new test result, using server time for the test time
        /// </summary>
        /// <param name="testResult">The data to add</param>
        /// <returns>The success result</returns>
        /// <response code="200">On success</response>
        /// <response code="401">Missing or incorrect Auth Key</response>
        [HttpPost]
        [ProducesResponseType(StatusCodes.Status200OK)]
        [ProducesResponseType(StatusCodes.Status401Unauthorized)]
        public async Task<IActionResult> PublishTestResult([FromBody] TestPublishResult testResult)
        {
            if (testResult == null)
            {
                throw new ArgumentNullException(nameof(testResult));
            }

            if (!Authorize(testResult))
            {
                return Unauthorized();
            }

            // Get Test Records 
            (var testId, var machineId) = await VerifyPlatformTestAndMachine(testResult.PlatformName, testResult.TestName, testResult.MachineName);

            var newRecord = new DbTestRecord
            {
                CommitHash = testResult.CommitHash,
                TestDate = DateTime.UtcNow,
                TestResults = testResult.IndividualRunResults.Select(x => new TestResult { Result = x }).ToList(),
                DbMachineId = machineId,
                DbTestId = testId,
            };

            _context.TestRecords.Add(newRecord);

            await _context.SaveChangesAsync();

            return Ok();
        }
    }
}
