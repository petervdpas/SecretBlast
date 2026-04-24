namespace SecretBlast;

/// <summary>
/// Argon2id work factors used to derive the master key from a password.
/// Stored in the vault header so they can be upgraded per-vault without
/// a format version bump.
/// </summary>
public sealed record Argon2Parameters(int MemoryKiB, int Iterations, int Parallelism)
{
    /// <summary>
    /// Conservative starting defaults (64 MiB, 3 iterations, 1 lane). Re-benchmark
    /// on target hardware before a production release.
    /// </summary>
    public static Argon2Parameters Default { get; } = new(MemoryKiB: 65536, Iterations: 3, Parallelism: 1);
}
