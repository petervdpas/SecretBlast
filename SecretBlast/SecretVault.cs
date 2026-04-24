using SecretBlast.Interfaces;

namespace SecretBlast;

/// <summary>
/// Entry point for creating and opening <see cref="ISecretVault"/> instances.
/// </summary>
public static class SecretVault
{
    /// <summary>
    /// Initialize a brand-new vault at <paramref name="path"/> and return it
    /// already unlocked. Throws <see cref="VaultAlreadyExistsException"/> if
    /// the path already contains a vault header.
    /// </summary>
    public static ISecretVault Create(string path, string masterPassword, VaultOptions? options = null)
        => FileSecretVault.Create(path, masterPassword, options ?? new VaultOptions());

    /// <summary>
    /// Open an existing vault at <paramref name="path"/> in a locked state.
    /// The caller must call <see cref="ISecretVault.UnlockAsync"/> before
    /// performing any secret operation.
    /// </summary>
    public static ISecretVault Open(string path, VaultOptions? options = null)
        => FileSecretVault.Open(path, options ?? new VaultOptions());
}
