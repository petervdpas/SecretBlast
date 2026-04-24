using System;
using System.Text.Json.Serialization;

namespace SecretBlast.Internal;

/// <summary>
/// On-disk representation of a single <c>*.secret</c> file.
/// </summary>
internal sealed class SecretRecord
{
    /// <summary>Format version of this record. Bumped when the on-disk shape changes.</summary>
    [JsonPropertyName("version")]
    public int Version { get; set; } = 1;

    /// <summary>Symmetric algorithm identifier. Always <c>aes-256-gcm</c> in v1.</summary>
    [JsonPropertyName("algorithm")]
    public string Algorithm { get; set; } = "aes-256-gcm";

    /// <summary>Base64-encoded 12-byte AES-GCM nonce. Fresh per write.</summary>
    [JsonPropertyName("nonce")]
    public string Nonce { get; set; } = string.Empty;

    /// <summary>Base64-encoded ciphertext of the secret value.</summary>
    [JsonPropertyName("ciphertext")]
    public string Ciphertext { get; set; } = string.Empty;

    /// <summary>Base64-encoded 16-byte AES-GCM authentication tag.</summary>
    [JsonPropertyName("tag")]
    public string Tag { get; set; } = string.Empty;

    /// <summary>UTC timestamp of the most recent write.</summary>
    [JsonPropertyName("updatedUtc")]
    public DateTime UpdatedUtc { get; set; }
}
