using System;
using System.Security.Cryptography;
using System.Text;

namespace SecretBlast.Internal;

/// <summary>
/// AES-256-GCM encrypt / decrypt primitives for vault records.
/// All ciphertexts are bound to their slot via additional authenticated data
/// (AAD): <c>"SecretBlast" || vaultId || name</c>. The <c>"SecretBlast"</c>
/// prefix is a domain separator; <c>vaultId</c> binds to the vault; <c>name</c>
/// binds to the specific record (<c>"canary"</c> for the header canary, the
/// secret name otherwise).
/// </summary>
internal static class VaultCrypto
{
    internal const int NonceLength = 12;
    internal const int TagLength = 16;

    private const string DomainSeparator = "SecretBlast";
    private const string CanarySlot = "canary";

    /// <summary>Plaintext stored in the header canary. Its exact bytes don't matter — only that decryption succeeds.</summary>
    private static readonly byte[] CanaryPlaintext = Encoding.UTF8.GetBytes("canary-v1");

    internal static (byte[] nonce, byte[] ciphertext, byte[] tag) Encrypt(
        byte[] key, string vaultId, string slot, byte[] plaintext)
    {
        var nonce = RandomNumberGenerator.GetBytes(NonceLength);
        var ciphertext = new byte[plaintext.Length];
        var tag = new byte[TagLength];
        var aad = BuildAad(vaultId, slot);

        using var gcm = new AesGcm(key, TagLength);
        gcm.Encrypt(nonce, plaintext, ciphertext, tag, aad);
        return (nonce, ciphertext, tag);
    }

    internal static byte[] Decrypt(
        byte[] key, string vaultId, string slot,
        byte[] nonce, byte[] ciphertext, byte[] tag)
    {
        var plaintext = new byte[ciphertext.Length];
        var aad = BuildAad(vaultId, slot);

        using var gcm = new AesGcm(key, TagLength);
        gcm.Decrypt(nonce, ciphertext, tag, plaintext, aad);
        return plaintext;
    }

    internal static VaultHeader.CanarySection BuildCanary(byte[] key, string vaultId)
    {
        var (nonce, ct, tag) = Encrypt(key, vaultId, CanarySlot, CanaryPlaintext);
        return new VaultHeader.CanarySection
        {
            Nonce = Convert.ToBase64String(nonce),
            Ciphertext = Convert.ToBase64String(ct),
            Tag = Convert.ToBase64String(tag),
        };
    }

    /// <summary>
    /// Attempt to decrypt the header canary. Returns true if the derived key is
    /// correct; false on authentication failure. Throws <see cref="VaultCorruptException"/>
    /// if the canary fields are malformed base64.
    /// </summary>
    internal static bool TryVerifyCanary(byte[] key, string vaultId, VaultHeader.CanarySection canary)
    {
        byte[] nonce, ct, tag;
        try
        {
            nonce = Convert.FromBase64String(canary.Nonce);
            ct    = Convert.FromBase64String(canary.Ciphertext);
            tag   = Convert.FromBase64String(canary.Tag);
        }
        catch (FormatException ex)
        {
            throw new VaultCorruptException("Vault header canary contains invalid base64.", ex);
        }

        try
        {
            _ = Decrypt(key, vaultId, CanarySlot, nonce, ct, tag);
            return true;
        }
        catch (AuthenticationTagMismatchException)
        {
            return false;
        }
    }

    private static byte[] BuildAad(string vaultId, string slot)
    {
        var sep = Encoding.UTF8.GetBytes(DomainSeparator);
        var vid = Encoding.UTF8.GetBytes(vaultId);
        var slt = Encoding.UTF8.GetBytes(slot);

        var aad = new byte[sep.Length + vid.Length + slt.Length];
        Buffer.BlockCopy(sep, 0, aad, 0, sep.Length);
        Buffer.BlockCopy(vid, 0, aad, sep.Length, vid.Length);
        Buffer.BlockCopy(slt, 0, aad, sep.Length + vid.Length, slt.Length);
        return aad;
    }
}
