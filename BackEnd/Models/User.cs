using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;
using System.Collections.Generic;

namespace BackEnd.Models
{
    public class User
    {
        [Key]
        [DatabaseGenerated(DatabaseGeneratedOption.Identity)]
        public long Id { get; set; }

        [Required]
        [StringLength(50)]
        public string Username { get; set; }

        [Required]
        [StringLength(255)] // Adequate length for hashed passwords
        public string Password { get; set; }

        [Required]
        [StringLength(20)]
        public string Role { get; set; } = "User"; // Default to "User"

        public DateTime CreatedAt { get; set; } = DateTime.UtcNow;

        [EmailAddress]
        [StringLength(100)]
        public string? Email { get; set; }

        [Required]
        [StringLength(50)]
        public string FirstName { get; set; }

        [Required]
        [StringLength(50)]
        public string LastName { get; set; }

        [Required]
        //[StringLength(11)] // Format: XXX-XX-XXXX
        public string SSN { get; set; }

        [Phone]
        [StringLength(500)] // Increased to accommodate encrypted data
        public string? PhoneNumber { get; set; }

        // Navigation properties
        public virtual ICollection<BorrowRequest> BorrowRequests { get; set; } = new List<BorrowRequest>();
        public virtual ICollection<BorrowRecord> BorrowRecords { get; set; } = new List<BorrowRecord>();
        public virtual ICollection<LibrarianRequest> LibrarianRequests { get; set; } = new List<LibrarianRequest>();

        // Memberships where this user is the primary member
        public virtual ICollection<UserMembership> UserMemberships { get; set; } = new List<UserMembership>();

        // Family memberships where this user is the parent
        [InverseProperty("ParentUser")]
        public virtual ICollection<UserMembership> FamilyMembers { get; set; } = new List<UserMembership>();
    }

}