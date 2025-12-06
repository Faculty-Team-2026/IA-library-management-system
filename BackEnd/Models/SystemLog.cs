using System;
using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;

namespace BackEnd.Models
{
    public class SystemLog
    {
        [Key]
        [DatabaseGenerated(DatabaseGeneratedOption.Identity)]
        public long Id { get; set; }

        [Required]
        public DateTime Timestamp { get; set; } = DateTime.UtcNow;

        [Required]
        [StringLength(20)]
        public string Level { get; set; } // "error", "warning", "info", "debug"

        [Required]
        [StringLength(2000)]
        public string Message { get; set; }

        [StringLength(100)]
        public string Source { get; set; } // "Console", "API", "Error", etc.

        [StringLength(50)]
        public string UserId { get; set; } // Nullable for logs before user login

        [StringLength(100)]
        public string Username { get; set; } // For easier log reading

        public DateTime CreatedAt { get; set; } = DateTime.UtcNow;
    }
}
