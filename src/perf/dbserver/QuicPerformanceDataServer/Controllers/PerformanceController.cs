using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;
using QuicDataServer.Data;
using QuicDataServer.Models;
using QuicDataServer.Models.Db;
using System;
using System.Collections;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

#pragma warning disable CA2007 // Consider calling ConfigureAwait on the awaited task

namespace QuicDataServer.Controllers
{

    [ApiController]
    [Route("[controller]")]
    public class PerformanceController : ControllerBase
    {
        private readonly PerformanceContext context;
        private readonly ILogger<PerformanceController> logger;
        private readonly IConfiguration configuration;

        public PerformanceController(ILogger<PerformanceController> logger, PerformanceContext context,
            IConfiguration configuration)
        {
            this.context = context;
            this.logger = logger;
            this.configuration = configuration;
        }

        /// <summary>
        /// Get a list of all runs and results for all platforms
        /// </summary>
        /// <returns>A list of all test runs ever done</returns>
        [HttpGet]
        public async Task<IEnumerable<TestRecord>> Get()
        {
            var query = context.Platforms.SelectMany(x => x.Tests, (platform, test) => new { platform, test })
                .SelectMany(x => x.test.TestRecords, (plattest, testrun) => new { plattest.platform, plattest.test, testrun })
                .Select(x => new TestRecord
                {
                    CommitHash = x.testrun.CommitHash,
                    IndividualRunResults = x.testrun.TestResults.Select(x => x.Result),
                    PlatformName = x.platform.PlatformName,
                    TestName = x.test.TestName,
                    ResultDate = x.testrun.TestDate
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
            return await context.Platforms.SelectMany(x => x.Tests, (platform, test) => new { platform.PlatformName, test.TestName }).ToListAsync();
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
            return await context.Platforms.Where(x => x.PlatformName == platform)
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
            return await context.Platforms.Where(x => x.PlatformName == platform)
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
            return authorization.AuthKey == configuration["ApiAuthorizationKey"];
        }

        /// <summary>
        /// Create a new platform.
        /// </summary>
        /// <remarks>
        /// Does nothing if the platform does not exist
        /// </remarks>
        /// <param name="platformToCreate">The platform to create</param>
        /// <returns>Creation result</returns>
        /// <response code="200">On success</response>
        /// <response code="401">Missing or incorrect Auth Key</response>
        [HttpPost("createPlatform")]
        [ProducesResponseType(StatusCodes.Status200OK)]
        [ProducesResponseType(StatusCodes.Status401Unauthorized)]
        public async Task<IActionResult> CreatePlatform([FromBody]PlatformCreate platformToCreate)
        {
            if (platformToCreate == null)
            {
                throw new ArgumentNullException(nameof(platformToCreate));
            }

            if (!Authorize(platformToCreate))
            {
                return Unauthorized();
            }

            if (await context.Platforms.Select(x => x.PlatformName == platformToCreate.PlatformName).AnyAsync())
            {
                return Ok();
            }

            context.Platforms.Add(new DbPlatform
            {
                PlatformName = platformToCreate.PlatformName
            });

            await context.SaveChangesAsync();

            return Ok();
        }

        /// <summary>
        /// Create a new test
        /// </summary>
        /// <remarks>
        /// Requires the platform to already be created
        /// </remarks>
        /// <param name="testToCreate">The test to create</param>
        /// <returns></returns>
        /// <response code="200">On success</response>
        /// <response code="400">Platform does not already exist</response>
        /// <response code="401">Missing or incorrect Auth Key</response>
        [HttpPost("createTest")]
        [ProducesResponseType(StatusCodes.Status200OK)]
        [ProducesResponseType(StatusCodes.Status400BadRequest)]
        [ProducesResponseType(StatusCodes.Status401Unauthorized)]
        public async Task<IActionResult> CreateTest([FromBody]TestCreate testToCreate)
        {
            if (testToCreate == null)
            {
                throw new ArgumentNullException(nameof(testToCreate));
            }

            if (!Authorize(testToCreate))
            {
                return Unauthorized();
            }

            var tests = await context.Platforms.Where(x => x.PlatformName == testToCreate.PlatformName).Select(x => x.Tests).FirstOrDefaultAsync();

            if (tests == null)
            {
                return BadRequest("Platform does not exist");
            }

            if (tests.Select(x => x.TestName).Contains(testToCreate.TestName))
            {
                return Ok();
            }

            tests.Add(new DbTest
            {
                TestName = testToCreate.TestName
            });

            await context.SaveChangesAsync();

            return Ok();
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
        /// <response code="400">Platform and test do not already exist</response>
        /// <response code="401">Missing or incorrect Auth Key</response>
        [HttpPost("withTime")]
        [ProducesResponseType(StatusCodes.Status200OK)]
        [ProducesResponseType(StatusCodes.Status400BadRequest)]
        [ProducesResponseType(StatusCodes.Status401Unauthorized)]
        public async Task<IActionResult> PublishTestResultWithTime([FromBody]TestPublishResultWithTime testResult)
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
            var testRecords = await context.Platforms.SelectMany(x => x.Tests, (platform, test) => new { platform, test })
                .Where(x => x.test.TestName == testResult.TestName && x.platform.PlatformName == testResult.PlatformName)
                .Select(x => x.test.TestRecords)
                .FirstOrDefaultAsync();

            if (testRecords == null)
            {
                return BadRequest("Platform and Test not found");
            }

            var newRecord = new DbTestRecord
            {
                CommitHash = testResult.CommitHash,
                TestDate = testResult.Time,
                TestResults = testResult.IndividualRunResults.Select(x => new TestResult { Result = x }).ToList(),
            };

            testRecords.Add(newRecord);

            await context.SaveChangesAsync();

            return Ok();
        }

        /// <summary>
        /// Adds a new test result, using server time for the test time
        /// </summary>
        /// <param name="testResult">The data to add</param>
        /// <returns>The success result</returns>
        /// <response code="200">On success</response>
        /// <response code="400">Platform and test do not already exist</response>
        /// <response code="401">Missing or incorrect Auth Key</response>
        [HttpPost]
        [ProducesResponseType(StatusCodes.Status200OK)]
        [ProducesResponseType(StatusCodes.Status400BadRequest)]
        [ProducesResponseType(StatusCodes.Status401Unauthorized)]
        public async Task<IActionResult> PublishTestResult([FromBody]TestPublishResult testResult)
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
            var testRecords = await context.Platforms.SelectMany(x => x.Tests, (platform, test) => new { platform, test })
                .Where(x => x.test.TestName == testResult.TestName && x.platform.PlatformName == testResult.PlatformName)
                .Select(x => x.test.TestRecords)
                .FirstOrDefaultAsync();

            if (testRecords == null)
            {
                return BadRequest("Platform and Test not found");
            }

            var newRecord = new DbTestRecord
            {
                CommitHash = testResult.CommitHash,
                TestDate = DateTime.UtcNow,
                TestResults = testResult.IndividualRunResults.Select(x => new TestResult { Result = x }).ToList(),
            };

            testRecords.Add(newRecord);

            await context.SaveChangesAsync();

            return Ok();
        }
    }
}
