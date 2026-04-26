using System.Text.RegularExpressions;

namespace SafeVault.Helpers;

/// <summary>
/// Provides input validation and sanitization to prevent XSS and injection attacks.
/// All user-supplied text should pass through SanitizeInput before storage.
/// </summary>
public static class InputValidator
{
    /// <summary>
    /// Sanitizes input by stripping HTML/script tags and encoding special characters.
    /// FIXED: Previously vulnerable to XSS — user input was stored and rendered without sanitization.
    /// </summary>
    public static string SanitizeInput(string input)
    {
        if (string.IsNullOrWhiteSpace(input))
            return string.Empty;

        // Strip all HTML tags (prevents stored XSS)
        var sanitized = Regex.Replace(input, @"<[^>]*>", string.Empty);

        // Strip javascript: protocol (prevents XSS via links)
        sanitized = Regex.Replace(sanitized, @"javascript\s*:", string.Empty, RegexOptions.IgnoreCase);

        // Strip inline event handlers (e.g., onerror=, onclick=)
        sanitized = Regex.Replace(sanitized, @"on\w+\s*=", string.Empty, RegexOptions.IgnoreCase);

        // Strip SQL comment sequences (defense in depth)
        sanitized = sanitized.Replace("--", string.Empty);

        // Encode special characters to prevent injection
        sanitized = sanitized
            .Replace("&", "&amp;")
            .Replace("\"", "&quot;")
            .Replace("'", "&#x27;");

        return sanitized.Trim();
    }

    /// <summary>
    /// Validates that the provided string is a well-formed email address.
    /// </summary>
    public static bool ValidateEmail(string email)
    {
        if (string.IsNullOrWhiteSpace(email))
            return false;

        var pattern = @"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$";
        return Regex.IsMatch(email, pattern);
    }

    /// <summary>
    /// Validates password complexity: minimum 8 characters, must contain
    /// uppercase, lowercase, digit, and special character.
    /// </summary>
    public static bool ValidatePassword(string password)
    {
        if (string.IsNullOrWhiteSpace(password) || password.Length < 8)
            return false;

        bool hasUpper = Regex.IsMatch(password, @"[A-Z]");
        bool hasLower = Regex.IsMatch(password, @"[a-z]");
        bool hasDigit = Regex.IsMatch(password, @"\d");
        bool hasSpecial = Regex.IsMatch(password, @"[!@#$%^&*(),.?""{}|<>]");

        return hasUpper && hasLower && hasDigit && hasSpecial;
    }
}
