using System;
using Gml.Web.Api.Data;
using Microsoft.EntityFrameworkCore.Infrastructure;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace Gml.Web.Api.Migrations;

[DbContext(typeof(DatabaseContext))]
[Migration("20261018100000_AddPlayerLauncherSessions")]
public sealed class AddPlayerLauncherSessions : Migration
{
    protected override void Up(MigrationBuilder migrationBuilder)
    {
        migrationBuilder.CreateTable(
            name: "PlayerLauncherSessions",
            columns: table => new
            {
                Id = table.Column<Guid>(type: "TEXT", nullable: false),
                PlayerUuid = table.Column<string>(type: "TEXT", maxLength: 64, nullable: false),
                TokenHash = table.Column<string>(type: "TEXT", maxLength: 64, nullable: false),
                DeviceHash = table.Column<string>(type: "TEXT", maxLength: 64, nullable: false),
                DeviceLabel = table.Column<string>(type: "TEXT", maxLength: 96, nullable: false),
                CreatedAtUtc = table.Column<DateTime>(type: "TEXT", nullable: false),
                LastSeenAtUtc = table.Column<DateTime>(type: "TEXT", nullable: false),
                ExpiresAtUtc = table.Column<DateTime>(type: "TEXT", nullable: false),
                RevokedAtUtc = table.Column<DateTime>(type: "TEXT", nullable: true)
            },
            constraints: table => table.PrimaryKey("PK_PlayerLauncherSessions", x => x.Id));

        migrationBuilder.CreateIndex(
            name: "IX_PlayerLauncherSessions_TokenHash",
            table: "PlayerLauncherSessions", column: "TokenHash", unique: true);
        migrationBuilder.CreateIndex(
            name: "IX_PlayerLauncherSessions_PlayerUuid_RevokedAtUtc_ExpiresAtUtc",
            table: "PlayerLauncherSessions",
            columns: new[] { "PlayerUuid", "RevokedAtUtc", "ExpiresAtUtc" });
    }

    protected override void Down(MigrationBuilder migrationBuilder)
    {
        migrationBuilder.DropTable(name: "PlayerLauncherSessions");
    }
}
