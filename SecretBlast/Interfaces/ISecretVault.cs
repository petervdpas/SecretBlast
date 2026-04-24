using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;

namespace SecretBlast.Interfaces;

/// <summary>
/// Encrypted secrets store. A vault is opened in a locked state and must be
/// unlocked with a master password before any secret can be read or written.
/// Implementations are expected to zero the derived key from memory on
/// <see cref="Lock"/> and <see cref="IDisposable.Dispose"/>.
/// </summary>
public interface ISecretVault : IDisposable
{
    /// <summary>True when no master key is cached and no secret operation can succeed.</summary>
    bool IsLocked { get; }

    /// <summary>
    /// Derive the master key from <paramref name="masterPassword"/> and cache it
    /// in memory. No-op if already unlocked. Throws
    /// <see cref="InvalidMasterPasswordException"/> if the derived key cannot
    /// decrypt the vault header.
    /// </summary>
    Task UnlockAsync(string masterPassword, CancellationToken ct = default);

    /// <summary>Drop the cached master key and zero its memory.</summary>
    void Lock();

    /// <summary>Read a secret by name. Throws if the vault is locked or the secret is unknown.</summary>
    Task<string> GetAsync(string name, CancellationToken ct = default);

    /// <summary>Create or overwrite a secret. Throws if the vault is locked.</summary>
    Task SetAsync(string name, string value, CancellationToken ct = default);

    /// <summary>Delete a secret. Throws if the vault is locked or the secret is unknown.</summary>
    Task DeleteAsync(string name, CancellationToken ct = default);

    /// <summary>List the names of all secrets in the vault. Does not require unlock.</summary>
    Task<IReadOnlyList<string>> ListAsync(CancellationToken ct = default);

    /// <summary>Raised when the vault transitions from unlocked to locked.</summary>
    event EventHandler? Locked;
}
