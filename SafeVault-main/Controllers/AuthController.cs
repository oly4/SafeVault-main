using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using SafeVault.Helpers;
using SafeVault.Models;

namespace SafeVault.Controllers;

/// <summary>
/// Handles user registration and login with JWT token generation.
/// All input is validated and sanitized before processing.
/// </summary>
[ApiController]
[Route("api/[controller]")]
public class AuthController : ControllerBase
{
    private readonly UserManager<User> _userManager;
    private readonly SignInManager<User> _signInManager;
    private readonly JwtHelper _jwtHelper;

    public AuthController(
        UserManager<User> userManager,
        SignInManager<User> signInManager,
        JwtHelper jwtHelper)
    {
        _userManager = userManager;
        _signInManager = signInManager;
        _jwtHelper = jwtHelper;
    }

    /// <summary>
    /// POST: api/auth/register
    /// Registers a new user with the specified role (default: "User").
    /// </summary>
    [HttpPost("register")]
    public async Task<IActionResult> Register([FromBody] RegisterModel model)
    {
        // Validate email format
        if (!InputValidator.ValidateEmail(model.Email))
            return BadRequest(new { error = "Invalid email format." });

        // Validate password complexity
        if (!InputValidator.ValidatePassword(model.Password))
            return BadRequest(new { error = "Password must be at least 8 characters with uppercase, lowercase, digit, and special character." });

        // FIXED: Previously vulnerable to XSS — user input was stored without sanitization
        var sanitizedName = InputValidator.SanitizeInput(model.FullName);

        var user = new User
        {
            UserName = model.Email,
            Email = model.Email,
            FullName = sanitizedName
        };

        // FIXED: Previously stored passwords in plain text
        // Now uses ASP.NET Identity's built-in PBKDF2 hashing
        var result = await _userManager.CreateAsync(user, model.Password);
        if (!result.Succeeded)
            return BadRequest(new { errors = result.Errors.Select(e => e.Description) });

        // Assign role — only "Admin" or "User" allowed
        var role = model.Role == "Admin" ? "Admin" : "User";
        await _userManager.AddToRoleAsync(user, role);

        return Ok(new { message = "User registered successfully.", role });
    }

    /// <summary>
    /// POST: api/auth/login
    /// Authenticates a user and returns a JWT token with role claims.
    /// </summary>
    [HttpPost("login")]
    public async Task<IActionResult> Login([FromBody] LoginModel model)
    {
        // Validate email format
        if (!InputValidator.ValidateEmail(model.Email))
            return BadRequest(new { error = "Invalid email format." });

        var user = await _userManager.FindByEmailAsync(model.Email);
        if (user == null)
            return Unauthorized(new { error = "Invalid credentials." });

        // FIXED: Previously used plain-text password comparison
        // Now uses ASP.NET Identity's secure password verification (PBKDF2)
        var result = await _signInManager.CheckPasswordSignInAsync(user, model.Password, lockoutOnFailure: false);
        if (!result.Succeeded)
            return Unauthorized(new { error = "Invalid credentials." });

        var roles = await _userManager.GetRolesAsync(user);
        var token = _jwtHelper.GenerateToken(user, roles);

        return Ok(new { token, roles });
    }
}
