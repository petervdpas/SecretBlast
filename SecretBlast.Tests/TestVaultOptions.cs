using System;
using SecretBlast;

namespace SecretBlast.Tests;

/// <summary>
/// Argon2 parameters fast enough for unit tests. Real vaults use
/// <see cref="Argon2Parameters.Default"/> — these values are NOT secure.
/// </summary>
internal static class TestVaultOptions
{
    internal static VaultOptions Fast() => new()
    {
        AutoLockIdle = TimeSpan.Zero, // disabled by default in tests
        Kdf = new Argon2Parameters(MemoryKiB: 1024, Iterations: 1, Parallelism: 1),
    };

    internal static VaultOptions FastWithAutoLock(TimeSpan idle) => new()
    {
        AutoLockIdle = idle,
        Kdf = new Argon2Parameters(MemoryKiB: 1024, Iterations: 1, Parallelism: 1),
    };
}
