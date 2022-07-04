using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace WebApplication1.Migrations
{
    public partial class CriaCamposRefreshToken : Migration
    {
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.AddColumn<string>(
                name: "refreshtoken",
                table: "AspNetUsers",
                type: "NVARCHAR(MAX)",
                nullable: true);

            migrationBuilder.AddColumn<DateTime>(
                name: "refreshtoken_expirytime",
                table: "AspNetUsers",
                type: "datetime2",
                nullable: true);
        }

        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropColumn(
                name: "refreshtoken",
                table: "AspNetUsers");

            migrationBuilder.DropColumn(
                name: "refreshtoken_expirytime",
                table: "AspNetUsers");
        }
    }
}
