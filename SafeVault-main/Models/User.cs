using Microsoft.AspNetCore.Identity;

namespace SafeVault.Models;

/// <summary>
/// Application user extending ASP.NET Identity.
/// FIXED: Passwords are now hashed via Identity (PBKDF2) — previously stored in plain text.
/// </summary>
public class User : IdentityUser
{
    public string FullName { get; set; } = string.Empty;
}
