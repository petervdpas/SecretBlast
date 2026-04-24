using System;
using System.Text.Json.Serialization;

namespace SecretBlast.Internal;

/// <summary>
/// Plaintext on-disk representation of <c>vault.json</c>. The KDF parameters
/// and salt are deliberately in the clear — what protects the vault is the
/// master password + Argon2id work factor, not obscurity.
/// </summary>
internal sealed class VaultHeader
{
    /// <summary>Format version of this header. Bumped when the on-disk shape changes.</summary>
    [JsonPropertyName("version")]
    public int Version { get; set; } = 1;

    /// <summary>Per-vault identifier, baked into every secret record's AAD.</summary>
    [JsonPropertyName("vaultId")]
    public string VaultId { get; set; } = string.Empty;

    /// <summary>UTC timestamp the vault was created.</summary>
    [JsonPropertyName("createdUtc")]
    public DateTime CreatedUtc { get; set; }

    /// <summary>Argon2id parameters + salt used to derive the master key.</summary>
    [JsonPropertyName("kdf")]
    public KdfSection Kdf { get; set; } = new();

    /// <summary>AES-GCM record used to verify the derived key is correct.</summary>
    [JsonPropertyName("canary")]
    public CanarySection Canary { get; set; } = new();

    internal sealed class KdfSection
    {
        [JsonPropertyName("algorithm")]
        public string Algorithm { get; set; } = "argon2id";

        [JsonPropertyName("memoryKiB")]
        public int MemoryKiB { get; set; }

        [JsonPropertyName("iterations")]
        public int Iterations { get; set; }

        [JsonPropertyName("parallelism")]
        public int Parallelism { get; set; }

        /// <summary>Base64-encoded 16-byte salt.</summary>
        [JsonPropertyName("salt")]
        public string Salt { get; set; } = string.Empty;
    }

    internal sealed class CanarySection
    {
        /// <summary>Base64-encoded 12-byte AES-GCM nonce.</summary>
        [JsonPropertyName("nonce")]
        public string Nonce { get; set; } = string.Empty;

        /// <summary>Base64-encoded ciphertext of the canary plaintext.</summary>
        [JsonPropertyName("ciphertext")]
        public string Ciphertext { get; set; } = string.Empty;

        /// <summary>Base64-encoded 16-byte AES-GCM authentication tag.</summary>
        [JsonPropertyName("tag")]
        public string Tag { get; set; } = string.Empty;
    }
}
