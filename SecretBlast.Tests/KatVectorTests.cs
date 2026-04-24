using System;
using System.Linq;
using System.Security.Cryptography;
using Konscious.Security.Cryptography;
using Xunit;

namespace SecretBlast.Tests;

/// <summary>
/// Known-answer tests for the crypto primitives we rely on. If either
/// Konscious or BCL's <see cref="AesGcm"/> ever produced wrong outputs,
/// the rest of SecretBlast's tests (which only show round-trips) wouldn't
/// notice — these do.
/// </summary>
public sealed class KatVectorTests
{
    // -------------------------------------------------------------------
    // Argon2id — RFC 9106 §5.3
    // https://www.rfc-editor.org/rfc/rfc9106.html#section-5.3
    //
    //   Argon2id version 19 (0x13)
    //   Memory: 32 KiB, Iterations: 3, Parallelism: 4, Tag length: 32
    //   Password[32]: 0x01 × 32
    //   Salt[16]:     0x02 × 16
    //   Secret[8]:    0x03 × 8
    //   Associated data[12]: 0x04 × 12
    //
    //   Tag: 0d640df58d78766c08c037a34a8b53c9d01ef0452d75b65eb52520e96b01e659
    // -------------------------------------------------------------------

    [Fact]
    public void Argon2id_Rfc9106_Vector_MatchesExpectedTag()
    {
        var password = Enumerable.Repeat((byte)0x01, 32).ToArray();
        var salt     = Enumerable.Repeat((byte)0x02, 16).ToArray();
        var secret   = Enumerable.Repeat((byte)0x03,  8).ToArray();
        var ad       = Enumerable.Repeat((byte)0x04, 12).ToArray();

        using var kdf = new Argon2id(password)
        {
            Salt = salt,
            KnownSecret = secret,
            AssociatedData = ad,
            MemorySize = 32,
            Iterations = 3,
            DegreeOfParallelism = 4,
        };

        var tag = kdf.GetBytes(32);

        Assert.Equal(
            "0d640df58d78766c08c037a34a8b53c9d01ef0452d75b65eb52520e96b01e659",
            Convert.ToHexStringLower(tag));
    }

    // -------------------------------------------------------------------
    // AES-256-GCM — "The Galois/Counter Mode of Operation (GCM)" test cases
    // by McGrew & Viega (also reproduced in NIST SP 800-38D testing guidance).
    // SecretBlast uses AES-256-GCM; we verify BCL's AesGcm against the two
    // canonical 256-bit-key vectors: one empty, one with real data + AAD.
    // -------------------------------------------------------------------

    [Fact]
    public void AesGcm256_EmptyPlaintext_ProducesExpectedTag()
    {
        // GCM Test Case 13.
        var key   = Hex("0000000000000000000000000000000000000000000000000000000000000000");
        var nonce = Hex("000000000000000000000000");
        var plaintext  = Array.Empty<byte>();
        var ciphertext = new byte[0];
        var tag = new byte[16];

        using var gcm = new AesGcm(key, 16);
        gcm.Encrypt(nonce, plaintext, ciphertext, tag);

        Assert.Equal("530f8afbc74536b9a963b4f1c4cb738b", Convert.ToHexStringLower(tag));
    }

    [Fact]
    public void AesGcm256_WithAadAndPlaintext_MatchesExpectedCiphertextAndTag()
    {
        // GCM Test Case 17 (256-bit key + AAD + non-block-aligned plaintext).
        var key   = Hex("feffe9928665731c6d6a8f9467308308feffe9928665731c6d6a8f9467308308");
        var nonce = Hex("cafebabefacedbaddecaf888");
        var plaintext = Hex(
            "d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a72" +
            "1c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39");
        var aad = Hex("feedfacedeadbeeffeedfacedeadbeefabaddad2");
        var expectedCiphertext =
            "522dc1f099567d07f47f37a32a84427d643a8cdcbfe5c0c97598a2bd2555d1aa" +
            "8cb08e48590dbb3da7b08b1056828838c5f61e6393ba7a0abcc9f662";
        var expectedTag = "76fc6ece0f4e1768cddf8853bb2d551b";

        var ciphertext = new byte[plaintext.Length];
        var tag = new byte[16];

        using var gcm = new AesGcm(key, 16);
        gcm.Encrypt(nonce, plaintext, ciphertext, tag, aad);

        Assert.Equal(expectedCiphertext, Convert.ToHexStringLower(ciphertext));
        Assert.Equal(expectedTag,         Convert.ToHexStringLower(tag));

        // Round-trip: BCL must decrypt its own output back to the input.
        var recovered = new byte[plaintext.Length];
        gcm.Decrypt(nonce, ciphertext, tag, recovered, aad);
        Assert.Equal(plaintext, recovered);
    }

    [Fact]
    public void AesGcm256_AnyAadMismatch_FailsAuthentication()
    {
        // Same vector as above; flip one bit of the AAD and confirm
        // BCL throws AuthenticationTagMismatchException.
        var key   = Hex("feffe9928665731c6d6a8f9467308308feffe9928665731c6d6a8f9467308308");
        var nonce = Hex("cafebabefacedbaddecaf888");
        var ciphertext = Hex(
            "522dc1f099567d07f47f37a32a84427d643a8cdcbfe5c0c97598a2bd2555d1aa" +
            "8cb08e48590dbb3da7b08b1056828838c5f61e6393ba7a0abcc9f662");
        var tag  = Hex("76fc6ece0f4e1768cddf8853bb2d551b");
        var aad  = Hex("feedfacedeadbeeffeedfacedeadbeefabaddad2");
        aad[0] ^= 0x01;

        var recovered = new byte[ciphertext.Length];
        using var gcm = new AesGcm(key, 16);
        Assert.Throws<AuthenticationTagMismatchException>(
            () => gcm.Decrypt(nonce, ciphertext, tag, recovered, aad));
    }

    // -------------------------------------------------------------------

    private static byte[] Hex(string s) => Convert.FromHexString(s);
}
