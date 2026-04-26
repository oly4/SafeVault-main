namespace SafeVault.Models;

/// <summary>
/// Request model for user login.
/// </summary>
public class LoginModel
{
    public string Email { get; set; } = string.Empty;
    public string Password { get; set; } = string.Empty;
}
