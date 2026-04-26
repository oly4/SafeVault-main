using System.Text.RegularExpressions;

namespace SafeVault.Middleware;

/// <summary>
/// Middleware that inspects incoming requests for common SQL injection patterns.
/// Returns HTTP 400 if a suspicious pattern is detected in query strings or request bodies.
/// Note: This is a defense-in-depth measure. Primary SQL injection prevention comes from
/// EF Core's parameterized queries — never use raw SQL with string concatenation.
/// </summary>
public class SqlInjectionMiddleware
{
    private readonly RequestDelegate _next;
    private readonly ILogger<SqlInjectionMiddleware> _logger;

    // Common SQL injection patterns to detect
    private static readonly string[] SqlPatterns =
    {
        @"(\b(SELECT|INSERT|UPDATE|DELETE|DROP|UNION|ALTER|CREATE|EXEC|EXECUTE)\b\s+\b(FROM|INTO|TABLE|DATABASE|SET)\b)",
        @"(\bDROP\s+TABLE\b)",
        @"(\bUNION\s+SELECT\b)",
        @"(--|;)\s*(DROP|ALTER|CREATE|EXEC)",
        @"(\bOR\b\s+\d+\s*=\s*\d+)",
        @"(\bOR\b\s+'[^']*'\s*=\s*'[^']*')",
        @"(xp_|sp_exec)"
    };

    public SqlInjectionMiddleware(RequestDelegate next, ILogger<SqlInjectionMiddleware> logger)
    {
        _next = next;
        _logger = logger;
    }

    public async Task InvokeAsync(HttpContext context)
    {
        // Check query string parameters
        var queryString = context.Request.QueryString.Value;
        if (!string.IsNullOrEmpty(queryString) && ContainsSqlInjection(queryString))
        {
            _logger.LogWarning("SQL injection attempt detected in query string");
            context.Response.StatusCode = 400;
            await context.Response.WriteAsJsonAsync(new { error = "Potentially dangerous input detected." });
            return;
        }

        // Check request body for POST and PUT requests
        if (context.Request.Method is "POST" or "PUT")
        {
            context.Request.EnableBuffering();
            using var reader = new StreamReader(context.Request.Body, leaveOpen: true);
            var body = await reader.ReadToEndAsync();
            context.Request.Body.Position = 0;

            if (!string.IsNullOrEmpty(body) && ContainsSqlInjection(body))
            {
                _logger.LogWarning("SQL injection attempt detected in request body");
                context.Response.StatusCode = 400;
                await context.Response.WriteAsJsonAsync(new { error = "Potentially dangerous input detected." });
                return;
            }
        }

        await _next(context);
    }

    /// <summary>
    /// Checks input against known SQL injection patterns.
    /// </summary>
    private static bool ContainsSqlInjection(string input)
    {
        foreach (var pattern in SqlPatterns)
        {
            if (Regex.IsMatch(input, pattern, RegexOptions.IgnoreCase))
                return true;
        }
        return false;
    }
}
