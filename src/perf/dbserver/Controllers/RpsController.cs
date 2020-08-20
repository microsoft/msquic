// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using System;
using System.Collections;
using System.Collections.Generic;
using System.Linq;
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

namespace QuicPerformanceDataServer.Controllers
{
    [ApiController]
    [Route("[controller]")]
    public class RpsController : ControllerBase
    {
        private readonly PerformanceContext _context;
        private readonly ILogger<ThroughputController> _logger;
        private readonly IConfiguration _configuration;

        public RpsController(ILogger<ThroughputController> logger, PerformanceContext context,
            IConfiguration configuration)
        {
            _context = context;
            _logger = logger;
            _configuration = configuration;
        }

        /// <summary>
        /// Get the latest test result for a specific platform and test
        /// </summary>
        /// <param name="requestData">The data for the request</param>
        /// <returns>The latest result</returns>
        [HttpPost("get")]
        public async Task<TestRecord> GetLatestThroughputResultsForPlatform([FromBody] RpsRequest requestData)
        {
            return await _context.Platforms.Where(x => x.PlatformName == requestData.PlatformName)
                .SelectMany(x => x.RpsTests)
                .Where(x => x.ConnectionCount == requestData.ConnectionCount &&
                            x.RequestSize == requestData.RequestSize &&
                            x.ResponseSize == requestData.ResponseSize &&
                            x.ParallelRequests == requestData.ParallelRequests)
                .OrderByDescending(x => x.TestDate)
                .Select(x => new TestRecord
                {
                    CommitHash = x.CommitHash,
                    IndividualRunResults = x.TestResults.Select(x => x.Result),
                    PlatformName = requestData.PlatformName,
                    TestName = "RPS",
                    ResultDate = x.TestDate,
                    MachineName = _context.Machines.Where(y => y.DbMachineId == x.DbMachineId).Select(y => y.MachineName).First()
                })
                .FirstOrDefaultAsync();
        }

        /// <summary>
        /// Get the last N test results for a specific platform and test.
        /// </summary>
        /// <param name="numResults">The number of results to return</param>
        /// <param name="requestData">The request data</param>
        /// <returns>A list of the last N runs</returns>
        [HttpPost("get/{numResults}")]
        public async Task<IEnumerable<TestRecord>> GetThroughputTestResultsForPlatform([FromBody] RpsRequest requestData, [FromQuery] int numResults)
        {
            return await _context.Platforms.Where(x => x.PlatformName == requestData.PlatformName)
                .SelectMany(x => x.RpsTests)
                .Where(x => x.ConnectionCount == requestData.ConnectionCount &&
                            x.RequestSize == requestData.RequestSize &&
                            x.ResponseSize == requestData.ResponseSize &&
                            x.ParallelRequests == requestData.ParallelRequests)
                .Select(x => new TestRecord
                {
                    CommitHash = x.CommitHash,
                    IndividualRunResults = x.TestResults.Select(x => x.Result),
                    PlatformName = requestData.PlatformName,
                    TestName = "RPS",
                    ResultDate = x.TestDate
                })
                .Take(numResults)
                .ToListAsync();
        }

        private bool Authorize(IAuthorizable authorization)
        {
            return authorization.AuthKey == _configuration["ApiAuthorizationKey"];
        }

        private async Task<(int platformId, int machineId)> VerifyPlatformAndMachine(string platformName, string? machineName)
        {
            var platformId = await _context.Platforms
                .Where(x => x.PlatformName == platformName)
                .Select(x => (int?)x.DbPlatformId)
                .FirstOrDefaultAsync();

            var machineId = await _context.Machines.Where(x => x.MachineName == machineName)
                .Select(x => (int?)x.DbMachineId)
                .FirstOrDefaultAsync();

            if (string.IsNullOrWhiteSpace(machineName))
            {
                machineId = 1;
            }

            if (platformId != null && machineId != null)
            {
                return (platformId.Value, machineId.Value);
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

            if (platformId != null)
            {
                return (platformId.Value, machineId.Value);
            }
            else
            {
                // Create platform
                var entity = _context.Platforms.Add(new DbPlatform
                {
                    PlatformName = platformName,
                });
                await _context.SaveChangesAsync();

                platformId = entity.Entity.DbPlatformId;
                return (platformId.Value, machineId.Value);
            }
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
        public async Task<IActionResult> PublishTestResultWithTime([FromBody] RpsTestPublishResultWithTime testResult)
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
            (var platformId, var machineId) = await VerifyPlatformAndMachine(testResult.PlatformName, testResult.MachineName);

            var newRecord = new DbRpsTestRecord
            {
                CommitHash = testResult.CommitHash,
                TestDate = testResult.Time,
                TestResults = testResult.IndividualRunResults.Select(x => new RpsTestResult { Result = x }).ToList(),
                DbMachineId = machineId,
                DbPlatformId = platformId,
                ConnectionCount = testResult.ConnectionCount,
                RequestSize = testResult.RequestSize,
                ResponseSize = testResult.ResponseSize,
                ParallelRequests = testResult.ParallelRequests
            };

            _context.RpsTestRecords.Add(newRecord);

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
        public async Task<IActionResult> PublishTestResult([FromBody] RpsTestPublishResult testResult)
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
            (var platformId, var machineId) = await VerifyPlatformAndMachine(testResult.PlatformName, testResult.MachineName);

            var newRecord = new DbRpsTestRecord
            {
                CommitHash = testResult.CommitHash,
                TestDate = DateTime.UtcNow,
                TestResults = testResult.IndividualRunResults.Select(x => new RpsTestResult { Result = x }).ToList(),
                DbMachineId = machineId,
                DbPlatformId = platformId,
                ConnectionCount = testResult.ConnectionCount,
                RequestSize = testResult.RequestSize,
                ResponseSize = testResult.ResponseSize,
                ParallelRequests = testResult.ParallelRequests
            };

            _context.RpsTestRecords.Add(newRecord);

            await _context.SaveChangesAsync();

            return Ok();
        }
    }
}
