// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using System;
using Microsoft.EntityFrameworkCore.Migrations;

namespace QuicPerformanceDataServer.Migrations
{
    public partial class SeparateThroughputTable : Migration
    {
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            if (migrationBuilder == null)
            {
                throw new ArgumentNullException(nameof(migrationBuilder));
            }

            migrationBuilder.AlterColumn<string>(
                name: "OperatingSystem",
                table: "Machines",
                nullable: true,
                oldClrType: typeof(string),
                oldType: "nvarchar(max)");

            migrationBuilder.AlterColumn<string>(
                name: "NicInfo",
                table: "Machines",
                nullable: true,
                oldClrType: typeof(string),
                oldType: "nvarchar(max)");

            migrationBuilder.AlterColumn<string>(
                name: "MemoryInfo",
                table: "Machines",
                nullable: true,
                oldClrType: typeof(string),
                oldType: "nvarchar(max)");

            migrationBuilder.AlterColumn<string>(
                name: "ExtraInfo",
                table: "Machines",
                nullable: true,
                oldClrType: typeof(string),
                oldType: "nvarchar(max)");

            migrationBuilder.AlterColumn<string>(
                name: "Description",
                table: "Machines",
                nullable: true,
                oldClrType: typeof(string),
                oldType: "nvarchar(max)");

            migrationBuilder.AlterColumn<string>(
                name: "CPUInfo",
                table: "Machines",
                nullable: true,
                oldClrType: typeof(string),
                oldType: "nvarchar(max)");

            migrationBuilder.CreateTable(
                name: "ThroughputTestRecords",
                columns: table => new
                {
                    DbThroughputTestRecordId = table.Column<int>(nullable: false)
                        .Annotation("SqlServer:Identity", "1, 1"),
                    DbMachineId = table.Column<int>(nullable: false),
                    DbPlatformId = table.Column<int>(nullable: false),
                    Loopback = table.Column<bool>(nullable: false),
                    Encryption = table.Column<bool>(nullable: false),
                    SendBuffering = table.Column<bool>(nullable: false),
                    NumberOfStreams = table.Column<int>(nullable: false),
                    ServerToClient = table.Column<bool>(nullable: false),
                    TestDate = table.Column<DateTime>(nullable: false),
                    CommitHash = table.Column<string>(nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_ThroughputTestRecords", x => x.DbThroughputTestRecordId);
                    table.ForeignKey(
                        name: "FK_ThroughputTestRecords_Machines_DbMachineId",
                        column: x => x.DbMachineId,
                        principalTable: "Machines",
                        principalColumn: "DbMachineId",
                        onDelete: ReferentialAction.Cascade);
                    table.ForeignKey(
                        name: "FK_ThroughputTestRecords_Platforms_DbPlatformId",
                        column: x => x.DbPlatformId,
                        principalTable: "Platforms",
                        principalColumn: "DbPlatformId",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.CreateTable(
                name: "ThroughputTestResult",
                columns: table => new
                {
                    DbThroughputTestRecordId = table.Column<int>(nullable: false),
                    Id = table.Column<int>(nullable: false)
                        .Annotation("SqlServer:Identity", "1, 1"),
                    Result = table.Column<double>(nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_ThroughputTestResult", x => new { x.DbThroughputTestRecordId, x.Id });
                    table.ForeignKey(
                        name: "FK_ThroughputTestResult_ThroughputTestRecords_DbThroughputTestRecordId",
                        column: x => x.DbThroughputTestRecordId,
                        principalTable: "ThroughputTestRecords",
                        principalColumn: "DbThroughputTestRecordId",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.CreateIndex(
                name: "IX_ThroughputTestRecords_DbMachineId",
                table: "ThroughputTestRecords",
                column: "DbMachineId");

            migrationBuilder.CreateIndex(
                name: "IX_ThroughputTestRecords_DbPlatformId",
                table: "ThroughputTestRecords",
                column: "DbPlatformId");
        }

        protected override void Down(MigrationBuilder migrationBuilder)
        {
            if (migrationBuilder == null)
            {
                throw new ArgumentNullException(nameof(migrationBuilder));
            }

            migrationBuilder.DropTable(
                name: "ThroughputTestResult");

            migrationBuilder.DropTable(
                name: "ThroughputTestRecords");

            migrationBuilder.AlterColumn<string>(
                name: "OperatingSystem",
                table: "Machines",
                type: "nvarchar(max)",
                nullable: false,
                oldClrType: typeof(string),
                oldNullable: true);

            migrationBuilder.AlterColumn<string>(
                name: "NicInfo",
                table: "Machines",
                type: "nvarchar(max)",
                nullable: false,
                oldClrType: typeof(string),
                oldNullable: true);

            migrationBuilder.AlterColumn<string>(
                name: "MemoryInfo",
                table: "Machines",
                type: "nvarchar(max)",
                nullable: false,
                oldClrType: typeof(string),
                oldNullable: true);

            migrationBuilder.AlterColumn<string>(
                name: "ExtraInfo",
                table: "Machines",
                type: "nvarchar(max)",
                nullable: false,
                oldClrType: typeof(string),
                oldNullable: true);

            migrationBuilder.AlterColumn<string>(
                name: "Description",
                table: "Machines",
                type: "nvarchar(max)",
                nullable: false,
                oldClrType: typeof(string),
                oldNullable: true);

            migrationBuilder.AlterColumn<string>(
                name: "CPUInfo",
                table: "Machines",
                type: "nvarchar(max)",
                nullable: false,
                oldClrType: typeof(string),
                oldNullable: true);
        }
    }
}
