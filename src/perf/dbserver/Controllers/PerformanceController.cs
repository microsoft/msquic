﻿// Copyright (c) Microsoft Corporation.
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
                .OrderByDescending(x => x.testrun.TestDate)
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
        [Obsolete("Tests are now explicit")]
        public async Task<IEnumerable> GetAllTests()
        {
            return await _context.Platforms.SelectMany(x => x.Tests, (platform, test) => new { platform.PlatformName, test.TestName }).ToListAsync();
        }



        /// <summary>
        /// Get the latest test result for a specific platform and test
        /// </summary>
        /// <param name="requestData">The data for the request</param>
        /// <returns>The latest result</returns>
        [HttpPost("getthroughput")]
        public async Task<TestRecord> GetLatestThroughputResultsForPlatform([FromBody]ThroughputRequest requestData)
        {

            return await _context.Platforms.Where(x => x.PlatformName == requestData.PlatformName)
                .SelectMany(x => x.ThroughputTests)
                .Where(x => x.Loopback          == requestData.Loopback &&
                            x.Encryption        == requestData.Encryption &&
                            x.SendBuffering     == requestData.SendBuffering &&
                            x.NumberOfStreams   == requestData.NumberOfStreams &&
                            x.ServerToClient    == requestData.ServerToClient)
                .OrderByDescending(x => x.TestDate)
                .Select(x => new TestRecord
                {
                    CommitHash = x.CommitHash,
                    IndividualRunResults = x.TestResults.Select(x => x.Result),
                    PlatformName = requestData.PlatformName,
                    TestName = "Throughput",
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
        [HttpPost("getthroughput/{numResults}")]
        public async Task<IEnumerable<TestRecord>> GetThroughputTestResultsForPlatform([FromBody] ThroughputRequest requestData, [FromQuery]int numResults)
        {
            return await _context.Platforms.Where(x => x.PlatformName == requestData.PlatformName)
                .SelectMany(x => x.ThroughputTests)
                .Where(x => x.Loopback == requestData.Loopback &&
                            x.Encryption == requestData.Encryption &&
                            x.SendBuffering == requestData.SendBuffering &&
                            x.NumberOfStreams == requestData.NumberOfStreams &&
                            x.ServerToClient == requestData.ServerToClient)
                .Select(x => new TestRecord
                {
                    CommitHash = x.CommitHash,
                    IndividualRunResults = x.TestResults.Select(x => x.Result),
                    PlatformName = requestData.PlatformName,
                    TestName = "Throughput",
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
        public async Task<IActionResult> PublishThroughputTestResultWithTime([FromBody] ThroughputTestPublishResultWithTime testResult)
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

            var newRecord = new DbThroughputTestRecord
            {
                CommitHash = testResult.CommitHash,
                TestDate = testResult.Time,
                TestResults = testResult.IndividualRunResults.Select(x => new ThroughputTestResult { Result = x }).ToList(),
                DbMachineId = machineId,
                DbPlatformId = platformId,
            };

            _context.ThroughputTestRecords.Add(newRecord);

            await _context.SaveChangesAsync();

            return Ok();
        }

        ///// <summary>
        ///// Adds a new test result, using server time for the test time
        ///// </summary>
        ///// <param name="testResult">The data to add</param>
        ///// <returns>The success result</returns>
        ///// <response code="200">On success</response>
        ///// <response code="401">Missing or incorrect Auth Key</response>
        //[HttpPost]
        //[ProducesResponseType(StatusCodes.Status200OK)]
        //[ProducesResponseType(StatusCodes.Status401Unauthorized)]
        //public async Task<IActionResult> PublishTestResult([FromBody] TestPublishResult testResult)
        //{
        //    if (testResult == null)
        //    {
        //        throw new ArgumentNullException(nameof(testResult));
        //    }

        //    if (!Authorize(testResult))
        //    {
        //        return Unauthorized();
        //    }

        //    // Get Test Records 
        //    (var testId, var machineId) = await VerifyPlatformTestAndMachine(testResult.PlatformName, testResult.TestName, testResult.MachineName);

        //    var newRecord = new DbTestRecord
        //    {
        //        CommitHash = testResult.CommitHash,
        //        TestDate = DateTime.UtcNow,
        //        TestResults = testResult.IndividualRunResults.Select(x => new TestResult { Result = x }).ToList(),
        //        DbMachineId = machineId,
        //        DbTestId = testId,
        //    };

        //    _context.TestRecords.Add(newRecord);

        //    await _context.SaveChangesAsync();

        //    return Ok();
        //}
    }
}
