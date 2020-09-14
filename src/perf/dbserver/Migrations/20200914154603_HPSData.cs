// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using System;
using Microsoft.EntityFrameworkCore.Migrations;

namespace QuicPerformanceDataServer.Migrations
{
    public partial class HPSData : Migration
    {
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            if (migrationBuilder == null)
            {
                throw new ArgumentNullException(nameof(migrationBuilder));
            }

            migrationBuilder.CreateTable(
                name: "HpsTestRecords",
                columns: table => new
                {
                    DbHpsTestRecordId = table.Column<int>(nullable: false)
                        .Annotation("SqlServer:Identity", "1, 1"),
                    DbMachineId = table.Column<int>(nullable: false),
                    DbPlatformId = table.Column<int>(nullable: false),
                    TestDate = table.Column<DateTime>(nullable: false),
                    CommitHash = table.Column<string>(nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_HpsTestRecords", x => x.DbHpsTestRecordId);
                    table.ForeignKey(
                        name: "FK_HpsTestRecords_Machines_DbMachineId",
                        column: x => x.DbMachineId,
                        principalTable: "Machines",
                        principalColumn: "DbMachineId",
                        onDelete: ReferentialAction.Cascade);
                    table.ForeignKey(
                        name: "FK_HpsTestRecords_Platforms_DbPlatformId",
                        column: x => x.DbPlatformId,
                        principalTable: "Platforms",
                        principalColumn: "DbPlatformId",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.CreateTable(
                name: "HpsTestResult",
                columns: table => new
                {
                    DbHpsTestRecordId = table.Column<int>(nullable: false),
                    Id = table.Column<int>(nullable: false)
                        .Annotation("SqlServer:Identity", "1, 1"),
                    Result = table.Column<double>(nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_HpsTestResult", x => new { x.DbHpsTestRecordId, x.Id });
                    table.ForeignKey(
                        name: "FK_HpsTestResult_HpsTestRecords_DbHpsTestRecordId",
                        column: x => x.DbHpsTestRecordId,
                        principalTable: "HpsTestRecords",
                        principalColumn: "DbHpsTestRecordId",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.CreateIndex(
                name: "IX_HpsTestRecords_DbMachineId",
                table: "HpsTestRecords",
                column: "DbMachineId");

            migrationBuilder.CreateIndex(
                name: "IX_HpsTestRecords_DbPlatformId",
                table: "HpsTestRecords",
                column: "DbPlatformId");
        }

        protected override void Down(MigrationBuilder migrationBuilder)
        {
            if (migrationBuilder == null)
            {
                throw new ArgumentNullException(nameof(migrationBuilder));
            }

            migrationBuilder.DropTable(
                name: "HpsTestResult");

            migrationBuilder.DropTable(
                name: "HpsTestRecords");
        }
    }
}
