using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;
using SafeVault.Models;

namespace SafeVault.Data;

/// <summary>
/// Entity Framework Core database context with ASP.NET Identity support.
/// Uses SQLite for simplicity. All queries go through EF Core's parameterized query engine.
/// FIXED: Previously vulnerable to SQL injection via raw SQL string concatenation.
/// </summary>
public class AppDbContext : IdentityDbContext<User>
{
    public AppDbContext(DbContextOptions<AppDbContext> options) : base(options) { }

    public DbSet<VaultItem> VaultItems => Set<VaultItem>();
}
