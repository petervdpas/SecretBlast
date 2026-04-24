using System;

namespace SecretBlast;

/// <summary>Base type for all exceptions thrown from SecretBlast.</summary>
public class SecretBlastException : Exception
{
    /// <summary>Create a new SecretBlast exception with a message.</summary>
    public SecretBlastException(string message) : base(message) { }

    /// <summary>Create a new SecretBlast exception wrapping an inner exception.</summary>
    public SecretBlastException(string message, Exception inner) : base(message, inner) { }
}

/// <summary>Thrown when a secret operation is attempted on a locked vault.</summary>
public sealed class VaultLockedException : SecretBlastException
{
    /// <summary>Create a new <see cref="VaultLockedException"/>.</summary>
    public VaultLockedException() : base("Vault is locked. Call UnlockAsync first.") { }
}

/// <summary>Thrown when the supplied master password cannot decrypt the vault header.</summary>
public sealed class InvalidMasterPasswordException : SecretBlastException
{
    /// <summary>Create a new <see cref="InvalidMasterPasswordException"/>.</summary>
    public InvalidMasterPasswordException() : base("Invalid master password.") { }
}

/// <summary>Thrown when a requested secret does not exist in the vault.</summary>
public sealed class SecretNotFoundException : SecretBlastException
{
    /// <summary>Create a new <see cref="SecretNotFoundException"/> for the given secret name.</summary>
    public SecretNotFoundException(string name)
        : base($"Secret '{name}' was not found in the vault.") { }
}

/// <summary>Thrown when <c>Create</c> is called on a path that already contains a vault.</summary>
public sealed class VaultAlreadyExistsException : SecretBlastException
{
    /// <summary>Create a new <see cref="VaultAlreadyExistsException"/> for the given path.</summary>
    public VaultAlreadyExistsException(string path)
        : base($"A vault already exists at '{path}'.") { }
}
