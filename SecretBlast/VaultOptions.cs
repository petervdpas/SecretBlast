using System;
using System.Threading;

namespace SecretBlast;

/// <summary>
/// Runtime options for an <see cref="SecretBlast.Interfaces.ISecretVault"/>.
/// </summary>
public sealed class VaultOptions
{
    /// <summary>
    /// Idle time before the vault auto-locks. Set to <see cref="TimeSpan.Zero"/>
    /// or <see cref="Timeout.InfiniteTimeSpan"/> to disable the auto-lock timer.
    /// </summary>
    public TimeSpan AutoLockIdle { get; init; } = TimeSpan.FromMinutes(15);

    /// <summary>
    /// Argon2id parameters used when creating a new vault. Ignored by
    /// <c>Open</c> — opened vaults use whatever parameters are stored in their
    /// header.
    /// </summary>
    public Argon2Parameters Kdf { get; init; } = Argon2Parameters.Default;
}
