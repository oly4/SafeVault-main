using System.Security.Claims;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using SafeVault.Data;
using SafeVault.Helpers;
using SafeVault.Models;

namespace SafeVault.Controllers;

/// <summary>
/// CRUD operations for vault items with role-based access control.
/// GET is available to all authenticated users; POST and DELETE require Admin role.
/// </summary>
[ApiController]
[Route("api/[controller]")]
[Authorize]
public class VaultController : ControllerBase
{
    private readonly AppDbContext _context;

    public VaultController(AppDbContext context)
    {
        _context = context;
    }

    /// <summary>
    /// GET: api/vault
    /// Returns all vault items owned by the authenticated user.
    /// </summary>
    [HttpGet]
    public async Task<IActionResult> GetAll()
    {
        var userId = User.FindFirstValue(ClaimTypes.NameIdentifier);

        // FIXED: Previously vulnerable to SQL injection using raw SQL:
        //   var items = _context.VaultItems
        //       .FromSqlRaw($"SELECT * FROM VaultItems WHERE OwnerId = '{userId}'");
        // Now uses EF Core LINQ — generates parameterized queries automatically
        var items = await _context.VaultItems
            .Where(v => v.OwnerId == userId)
            .OrderByDescending(v => v.CreatedAt)
            .ToListAsync();

        return Ok(items);
    }

    /// <summary>
    /// POST: api/vault
    /// Creates a new vault item. Restricted to Admin role.
    /// </summary>
    [HttpPost]
    [Authorize(Roles = "Admin")]
    public async Task<IActionResult> Create([FromBody] VaultItem item)
    {
        var userId = User.FindFirstValue(ClaimTypes.NameIdentifier);

        // FIXED: Previously vulnerable to XSS — stored raw user input directly
        // Now sanitizes all text fields before persisting to the database
        item.Title = InputValidator.SanitizeInput(item.Title);
        item.Content = InputValidator.SanitizeInput(item.Content);
        item.OwnerId = userId!;
        item.CreatedAt = DateTime.UtcNow;

        // EF Core uses parameterized queries internally — safe from SQL injection
        _context.VaultItems.Add(item);
        await _context.SaveChangesAsync();

        return CreatedAtAction(nameof(GetAll), new { id = item.Id }, item);
    }

    /// <summary>
    /// DELETE: api/vault/{id}
    /// Deletes a vault item by ID. Restricted to Admin role.
    /// </summary>
    [HttpDelete("{id}")]
    [Authorize(Roles = "Admin")]
    public async Task<IActionResult> Delete(int id)
    {
        // FIXED: Previously vulnerable to SQL injection:
        //   _context.Database.ExecuteSqlRaw($"DELETE FROM VaultItems WHERE Id = {id}");
        // Now uses EF Core's safe, parameterized approach
        var item = await _context.VaultItems.FindAsync(id);
        if (item == null)
            return NotFound(new { error = "Vault item not found." });

        _context.VaultItems.Remove(item);
        await _context.SaveChangesAsync();

        return Ok(new { message = "Vault item deleted." });
    }
}
