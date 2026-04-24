using System;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Konscious.Security.Cryptography;

namespace SecretBlast.Internal;

/// <summary>
/// Argon2id password-based key derivation via
/// <see cref="Konscious.Security.Cryptography.Argon2id"/>.
/// </summary>
internal static class Argon2Kdf
{
    /// <summary>Size of the derived master key, in bytes (AES-256 → 32).</summary>
    internal const int DerivedKeyLength = 32;

    /// <summary>Size of the random per-vault salt, in bytes.</summary>
    internal const int SaltLength = 16;

    /// <summary>
    /// Derive a 32-byte key from the given password and salt under the supplied
    /// parameters. Runs on a thread-pool thread so the caller's thread is not
    /// blocked. The cancellation token cancels the wait but not the in-flight
    /// derivation — Konscious does not expose a cancellable primitive.
    /// </summary>
    internal static Task<byte[]> DeriveAsync(
        string password,
        byte[] salt,
        Argon2Parameters parameters,
        CancellationToken ct)
    {
        if (password is null) throw new ArgumentNullException(nameof(password));
        if (salt is null) throw new ArgumentNullException(nameof(salt));
        if (salt.Length != SaltLength)
            throw new ArgumentException($"Salt must be {SaltLength} bytes.", nameof(salt));

        var pwBytes = Encoding.UTF8.GetBytes(password);

        return Task.Run(() =>
        {
            try
            {
                using var kdf = new Argon2id(pwBytes)
                {
                    Salt = salt,
                    MemorySize = parameters.MemoryKiB,
                    Iterations = parameters.Iterations,
                    DegreeOfParallelism = parameters.Parallelism,
                };
                return kdf.GetBytes(DerivedKeyLength);
            }
            finally
            {
                Array.Clear(pwBytes);
            }
        }, ct);
    }
}
