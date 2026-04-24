namespace SecretBlast;

/// <summary>
/// Argon2id work factors used to derive the master key from a password.
/// Stored in the vault header so they can be upgraded per-vault without
/// a format version bump.
/// </summary>
public sealed record Argon2Parameters(int MemoryKiB, int Iterations, int Parallelism)
{
    /// <summary>
    /// Modern interactive defaults: 64 MiB memory, 3 iterations, 4 lanes.
    /// Matches RFC 9106's "interactive" recommendation and common industry
    /// practice (Bitwarden, 1Password's published parameters). Parallelism of
    /// 4 assumes a multi-core CPU — safe on anything newer than about 2015.
    /// Callers with stronger requirements (e.g. high-value desktop vaults)
    /// should override via <see cref="VaultOptions.Kdf"/> — raise
    /// <see cref="MemoryKiB"/> to 256 MiB or higher for real offline-crack
    /// resistance.
    /// </summary>
    public static Argon2Parameters Default { get; } = new(MemoryKiB: 65536, Iterations: 3, Parallelism: 4);
}
