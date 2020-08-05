// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using System;
using Microsoft.EntityFrameworkCore.Migrations;

namespace QuicPerformanceDataServer.Migrations
{
    public partial class InitialCreate : Migration
    {
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            if (migrationBuilder == null)
            {
                throw new ArgumentNullException(nameof(migrationBuilder));
            }

            migrationBuilder.CreateTable(
                name: "Machines",
                columns: table => new
                {
                    DbMachineId = table.Column<int>(nullable: false)
                        .Annotation("SqlServer:Identity", "1, 1"),
                    MachineName = table.Column<string>(nullable: false),
                    Description = table.Column<string>(nullable: false),
                    OperatingSystem = table.Column<string>(nullable: false),
                    CPUInfo = table.Column<string>(nullable: false),
                    MemoryInfo = table.Column<string>(nullable: false),
                    NicInfo = table.Column<string>(nullable: false),
                    ExtraInfo = table.Column<string>(nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_Machines", x => x.DbMachineId);
                });

            migrationBuilder.CreateTable(
                name: "Platforms",
                columns: table => new
                {
                    DbPlatformId = table.Column<int>(nullable: false)
                        .Annotation("SqlServer:Identity", "1, 1"),
                    PlatformName = table.Column<string>(nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_Platforms", x => x.DbPlatformId);
                });

            migrationBuilder.CreateTable(
                name: "Tests",
                columns: table => new
                {
                    DbTestId = table.Column<int>(nullable: false)
                        .Annotation("SqlServer:Identity", "1, 1"),
                    DbPlatformId = table.Column<int>(nullable: false),
                    TestName = table.Column<string>(nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_Tests", x => x.DbTestId);
                    table.ForeignKey(
                        name: "FK_Tests_Platforms_DbPlatformId",
                        column: x => x.DbPlatformId,
                        principalTable: "Platforms",
                        principalColumn: "DbPlatformId",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.CreateTable(
                name: "TestRecords",
                columns: table => new
                {
                    DbTestRecordId = table.Column<int>(nullable: false)
                        .Annotation("SqlServer:Identity", "1, 1"),
                    DbTestId = table.Column<int>(nullable: false),
                    DbMachineId = table.Column<int>(nullable: false),
                    TestDate = table.Column<DateTime>(nullable: false),
                    CommitHash = table.Column<string>(nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_TestRecords", x => x.DbTestRecordId);
                    table.ForeignKey(
                        name: "FK_TestRecords_Machines_DbMachineId",
                        column: x => x.DbMachineId,
                        principalTable: "Machines",
                        principalColumn: "DbMachineId",
                        onDelete: ReferentialAction.Cascade);
                    table.ForeignKey(
                        name: "FK_TestRecords_Tests_DbTestId",
                        column: x => x.DbTestId,
                        principalTable: "Tests",
                        principalColumn: "DbTestId",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.CreateTable(
                name: "TestResult",
                columns: table => new
                {
                    DbTestRecordId = table.Column<int>(nullable: false),
                    Id = table.Column<int>(nullable: false)
                        .Annotation("SqlServer:Identity", "1, 1"),
                    Result = table.Column<double>(nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_TestResult", x => new { x.DbTestRecordId, x.Id });
                    table.ForeignKey(
                        name: "FK_TestResult_TestRecords_DbTestRecordId",
                        column: x => x.DbTestRecordId,
                        principalTable: "TestRecords",
                        principalColumn: "DbTestRecordId",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.CreateIndex(
                name: "IX_TestRecords_DbMachineId",
                table: "TestRecords",
                column: "DbMachineId");

            migrationBuilder.CreateIndex(
                name: "IX_TestRecords_DbTestId",
                table: "TestRecords",
                column: "DbTestId");

            migrationBuilder.CreateIndex(
                name: "IX_Tests_DbPlatformId",
                table: "Tests",
                column: "DbPlatformId");
        }

        protected override void Down(MigrationBuilder migrationBuilder)
        {
            if (migrationBuilder == null)
            {
                throw new ArgumentNullException(nameof(migrationBuilder));
            }

            migrationBuilder.DropTable(
                name: "TestResult");

            migrationBuilder.DropTable(
                name: "TestRecords");

            migrationBuilder.DropTable(
                name: "Machines");

            migrationBuilder.DropTable(
                name: "Tests");

            migrationBuilder.DropTable(
                name: "Platforms");
        }
    }
}
