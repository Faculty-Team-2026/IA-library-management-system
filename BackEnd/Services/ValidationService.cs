using System;
using System.Text.RegularExpressions;
using System.Web;

namespace BackEnd.Services
{
    public class ValidationService : IValidationService
    {
        /// <summary>
        /// Validates password strength
        /// Password must contain: min 8 chars, uppercase, lowercase, numbers, special chars
        /// </summary>
        public ValidationResult ValidatePassword(string password)
        {
            if (string.IsNullOrEmpty(password))
                return new ValidationResult { IsValid = false, Message = "Password is required" };

            if (password.Length < 8)
                return new ValidationResult { IsValid = false, Message = "Password must be at least 8 characters long" };

            if (!Regex.IsMatch(password, @"[A-Z]"))
                return new ValidationResult { IsValid = false, Message = "Password must contain at least one uppercase letter" };

            if (!Regex.IsMatch(password, @"[a-z]"))
                return new ValidationResult { IsValid = false, Message = "Password must contain at least one lowercase letter" };

            if (!Regex.IsMatch(password, @"[0-9]"))
                return new ValidationResult { IsValid = false, Message = "Password must contain at least one number" };

            if (!Regex.IsMatch(password, @"[!@#$%^&*()_+\-=\[\]{};':"",.<>?/\\|`~]"))
                return new ValidationResult { IsValid = false, Message = "Password must contain at least one special character" };

            return new ValidationResult { IsValid = true, Message = "Password is strong" };
        }

        /// <summary>
        /// Validates email format
        /// </summary>
        public ValidationResult ValidateEmail(string email)
        {
            if (string.IsNullOrEmpty(email))
                return new ValidationResult { IsValid = false, Message = "Email is required" };

            try
            {
                var addr = new System.Net.Mail.MailAddress(email);
                if (addr.Address != email)
                    throw new Exception();
                return new ValidationResult { IsValid = true, Message = "Email is valid" };
            }
            catch
            {
                return new ValidationResult { IsValid = false, Message = "Invalid email format" };
            }
        }

        /// <summary>
        /// Validates username format
        /// Alphanumeric and underscores only, 3-20 characters
        /// </summary>
        public ValidationResult ValidateUsername(string username)
        {
            if (string.IsNullOrEmpty(username))
                return new ValidationResult { IsValid = false, Message = "Username is required" };

            if (username.Length < 3 || username.Length > 20)
                return new ValidationResult { IsValid = false, Message = "Username must be between 3 and 20 characters" };

            if (!Regex.IsMatch(username, @"^[a-zA-Z0-9_]+$"))
                return new ValidationResult { IsValid = false, Message = "Username can only contain letters, numbers, and underscores" };

            return new ValidationResult { IsValid = true, Message = "Username is valid" };
        }

        /// <summary>
        /// Sanitizes HTML input to prevent XSS attacks
        /// </summary>
        public string SanitizeHtmlInput(string input)
        {
            if (string.IsNullOrEmpty(input))
                return input;

            // HTML encode to prevent XSS
            string encoded = HttpUtility.HtmlEncode(input);

            // Remove any script tags and event handlers
            encoded = Regex.Replace(encoded, @"<script[^>]*>.*?</script>", "", RegexOptions.IgnoreCase);
            encoded = Regex.Replace(encoded, @"on\w+\s*=", "", RegexOptions.IgnoreCase);

            return encoded.Trim();
        }

        /// <summary>
        /// Validates phone number format
        /// </summary>
        public ValidationResult ValidatePhoneNumber(string phoneNumber)
        {
            if (string.IsNullOrEmpty(phoneNumber))
                return new ValidationResult { IsValid = true, Message = "Phone number is optional" };

            // Remove common formatting characters
            string cleaned = Regex.Replace(phoneNumber, @"[\s\-\(\)\.]+", "");

            if (!Regex.IsMatch(cleaned, @"^[0-9]{10,15}$"))
                return new ValidationResult { IsValid = false, Message = "Phone number must be 10-15 digits" };

            return new ValidationResult { IsValid = true, Message = "Phone number is valid" };
        }

        /// <summary>
        /// Validates SSN format (14 digits)
        /// </summary>
        public ValidationResult ValidateSSN(string ssn)
        {
            if (string.IsNullOrEmpty(ssn))
                return new ValidationResult { IsValid = false, Message = "SSN is required" };

            // Remove hyphens
            string cleaned = ssn.Replace("-", "");

            if (!Regex.IsMatch(cleaned, @"^\d{14}$"))
                return new ValidationResult { IsValid = false, Message = "SSN must be exactly 14 digits" };

            return new ValidationResult { IsValid = true, Message = "SSN is valid" };
        }
    }

    public interface IValidationService
    {
        ValidationResult ValidatePassword(string password);
        ValidationResult ValidateEmail(string email);
        ValidationResult ValidateUsername(string username);
        ValidationResult ValidatePhoneNumber(string phoneNumber);
        ValidationResult ValidateSSN(string ssn);
        string SanitizeHtmlInput(string input);
    }

    public class ValidationResult
    {
        public bool IsValid { get; set; }
        public string Message { get; set; }
    }
}
