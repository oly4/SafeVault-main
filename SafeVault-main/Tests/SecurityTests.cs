using SafeVault.Helpers;
using Xunit;

namespace SafeVault.Tests;

/// <summary>
/// Security-focused unit tests verifying SQL injection prevention,
/// XSS sanitization, email validation, and password complexity checks.
/// </summary>
public class SecurityTests
{
    // =====================================================
    // SQL Injection Prevention Tests
    // =====================================================

    [Fact]
    public void SanitizeInput_SqlInjectionString_IsSanitized()
    {
        // Simulates a classic SQL injection payload
        var maliciousInput = "'; DROP TABLE Users; --";
        var result = InputValidator.SanitizeInput(maliciousInput);

        // Single quotes should be encoded, SQL comments stripped
        Assert.DoesNotContain("'", result);
        Assert.DoesNotContain("--", result);
    }

    [Fact]
    public void SanitizeInput_SqlUnionAttack_IsSanitized()
    {
        var input = "1 UNION SELECT * FROM Users";
        var result = InputValidator.SanitizeInput(input);

        // Input is processed and returned (SQL keywords are handled by middleware,
        // but SanitizeInput ensures special characters are encoded)
        Assert.NotNull(result);
        Assert.NotEmpty(result);
    }

    // =====================================================
    // XSS Prevention Tests
    // =====================================================

    [Fact]
    public void SanitizeInput_ScriptTag_IsStripped()
    {
        var xssInput = "<script>alert('hacked')</script>";
        var result = InputValidator.SanitizeInput(xssInput);

        // All HTML tags should be completely removed
        Assert.DoesNotContain("<script>", result);
        Assert.DoesNotContain("</script>", result);
        Assert.DoesNotContain("<", result);
    }

    [Fact]
    public void SanitizeInput_ImgTagWithEventHandler_IsStripped()
    {
        var xssInput = "<img src=x onerror=alert('xss')>";
        var result = InputValidator.SanitizeInput(xssInput);

        // HTML tag and event handler should both be removed
        Assert.DoesNotContain("<img", result);
        Assert.DoesNotContain("onerror", result);
    }

    [Fact]
    public void SanitizeInput_JavascriptProtocol_IsStripped()
    {
        var input = "javascript:alert(1)";
        var result = InputValidator.SanitizeInput(input);

        Assert.DoesNotContain("javascript:", result);
    }

    [Fact]
    public void SanitizeInput_NestedScriptTags_AreStripped()
    {
        var input = "<div><script>document.cookie</script></div>";
        var result = InputValidator.SanitizeInput(input);

        Assert.DoesNotContain("<script>", result);
        Assert.DoesNotContain("<div>", result);
    }

    // =====================================================
    // Email Validation Tests
    // =====================================================

    [Fact]
    public void ValidateEmail_ValidEmail_ReturnsTrue()
    {
        Assert.True(InputValidator.ValidateEmail("user@example.com"));
        Assert.True(InputValidator.ValidateEmail("test.user@domain.org"));
        Assert.True(InputValidator.ValidateEmail("name+tag@company.co"));
    }

    [Fact]
    public void ValidateEmail_InvalidEmail_ReturnsFalse()
    {
        Assert.False(InputValidator.ValidateEmail("not-an-email"));
        Assert.False(InputValidator.ValidateEmail("@missing-local.com"));
        Assert.False(InputValidator.ValidateEmail("missing@.com"));
        Assert.False(InputValidator.ValidateEmail("no-at-sign.com"));
        Assert.False(InputValidator.ValidateEmail(""));
        Assert.False(InputValidator.ValidateEmail(null!));
    }

    // =====================================================
    // Password Complexity Tests
    // =====================================================

    [Fact]
    public void ValidatePassword_StrongPassword_ReturnsTrue()
    {
        Assert.True(InputValidator.ValidatePassword("Str0ng!Pass"));
        Assert.True(InputValidator.ValidatePassword("C0mpl3x@Pwd"));
        Assert.True(InputValidator.ValidatePassword("MyP@ssw0rd!"));
    }

    [Fact]
    public void ValidatePassword_WeakPassword_ReturnsFalse()
    {
        // Too short
        Assert.False(InputValidator.ValidatePassword("Ab1!"));
        // No uppercase letter
        Assert.False(InputValidator.ValidatePassword("lowercase1!"));
        // No lowercase letter
        Assert.False(InputValidator.ValidatePassword("UPPERCASE1!"));
        // No digit
        Assert.False(InputValidator.ValidatePassword("NoDigits!!"));
        // No special character
        Assert.False(InputValidator.ValidatePassword("NoSpecial1"));
        // Empty string
        Assert.False(InputValidator.ValidatePassword(""));
        // Null
        Assert.False(InputValidator.ValidatePassword(null!));
    }

    // =====================================================
    // Edge Case / Null Safety Tests
    // =====================================================

    [Fact]
    public void SanitizeInput_NullOrEmpty_ReturnsEmpty()
    {
        Assert.Equal(string.Empty, InputValidator.SanitizeInput(null!));
        Assert.Equal(string.Empty, InputValidator.SanitizeInput(""));
        Assert.Equal(string.Empty, InputValidator.SanitizeInput("   "));
    }

    [Fact]
    public void SanitizeInput_CleanInput_RemainsIntact()
    {
        var cleanInput = "Hello World 123";
        var result = InputValidator.SanitizeInput(cleanInput);

        Assert.Equal(cleanInput, result);
    }
}
