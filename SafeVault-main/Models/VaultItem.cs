namespace SafeVault.Models;

/// <summary>
/// Represents a secure item stored in the vault.
/// All text fields are sanitized before persistence to prevent XSS.
/// </summary>
public class VaultItem
{
    public int Id { get; set; }
    public string Title { get; set; } = string.Empty;
    public string Content { get; set; } = string.Empty;
    public string OwnerId { get; set; } = string.Empty;
    public DateTime CreatedAt { get; set; } = DateTime.UtcNow;
}
