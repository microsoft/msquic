// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using System;
using Microsoft.EntityFrameworkCore.Migrations;

namespace QuicPerformanceDataServer.Migrations
{
    public partial class RPSData : Migration
    {
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            if (migrationBuilder == null)
            {
                throw new ArgumentNullException(nameof(migrationBuilder));
            }

            migrationBuilder.CreateTable(
                name: "RpsTestRecords",
                columns: table => new
                {
                    DbRpsTestRecordId = table.Column<int>(nullable: false)
                        .Annotation("SqlServer:Identity", "1, 1"),
                    DbMachineId = table.Column<int>(nullable: false),
                    DbPlatformId = table.Column<int>(nullable: false),
                    ConnectionCount = table.Column<int>(nullable: false),
                    RequestSize = table.Column<int>(nullable: false),
                    ResponseSize = table.Column<int>(nullable: false),
                    ParallelRequests = table.Column<int>(nullable: false),
                    TestDate = table.Column<DateTime>(nullable: false),
                    CommitHash = table.Column<string>(nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_RpsTestRecords", x => x.DbRpsTestRecordId);
                    table.ForeignKey(
                        name: "FK_RpsTestRecords_Machines_DbMachineId",
                        column: x => x.DbMachineId,
                        principalTable: "Machines",
                        principalColumn: "DbMachineId",
                        onDelete: ReferentialAction.Cascade);
                    table.ForeignKey(
                        name: "FK_RpsTestRecords_Platforms_DbPlatformId",
                        column: x => x.DbPlatformId,
                        principalTable: "Platforms",
                        principalColumn: "DbPlatformId",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.CreateTable(
                name: "RpsTestResult",
                columns: table => new
                {
                    DbRpsTestRecordId = table.Column<int>(nullable: false),
                    Id = table.Column<int>(nullable: false)
                        .Annotation("SqlServer:Identity", "1, 1"),
                    Result = table.Column<double>(nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_RpsTestResult", x => new { x.DbRpsTestRecordId, x.Id });
                    table.ForeignKey(
                        name: "FK_RpsTestResult_RpsTestRecords_DbRpsTestRecordId",
                        column: x => x.DbRpsTestRecordId,
                        principalTable: "RpsTestRecords",
                        principalColumn: "DbRpsTestRecordId",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.CreateIndex(
                name: "IX_RpsTestRecords_DbMachineId",
                table: "RpsTestRecords",
                column: "DbMachineId");

            migrationBuilder.CreateIndex(
                name: "IX_RpsTestRecords_DbPlatformId",
                table: "RpsTestRecords",
                column: "DbPlatformId");
        }

        protected override void Down(MigrationBuilder migrationBuilder)
        {
            if (migrationBuilder == null)
            {
                throw new ArgumentNullException(nameof(migrationBuilder));
            }

            migrationBuilder.DropTable(
                name: "RpsTestResult");

            migrationBuilder.DropTable(
                name: "RpsTestRecords");
        }
    }
}
