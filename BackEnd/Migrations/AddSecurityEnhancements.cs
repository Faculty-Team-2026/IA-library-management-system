// Run this command to create this migration:
// dotnet ef migrations add AddSecurityEnhancements

using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace BackEnd.Migrations
{
    /// <inheritdoc />
    public partial class AddSecurityEnhancements : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            // Note: SSN and PhoneNumber fields are already StringLength fields in the User model
            // They will now store encrypted values instead of plaintext
            // 
            // If you need to migrate existing data, uncomment and modify the SQL below:
            /*
            migrationBuilder.Sql(@"
                -- This is a placeholder for data migration logic
                -- If you have existing unencrypted data, you would need to:
                -- 1. Create a temporary table with encrypted data
                -- 2. Copy and encrypt old data
                -- 3. Update the original table
                -- 4. Drop the temporary table
                
                -- WARNING: This requires the encryption service to be used at application level
                -- Do not attempt raw SQL encryption without proper key management
            ");
            */
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            // Rollback would require decryption of data, which should be handled at application level
        }
    }
}
