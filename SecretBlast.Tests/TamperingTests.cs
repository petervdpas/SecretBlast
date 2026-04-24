using System;
using System.IO;
using System.Threading.Tasks;
using SecretBlast;
using Xunit;

namespace SecretBlast.Tests;

/// <summary>
/// Verifies AES-GCM authentication catches every flavour of tampering:
/// flipping a byte in the nonce / ciphertext / tag, renaming the file
/// (AAD binds to the secret name), and mutating the header canary.
/// </summary>
public sealed class TamperingTests : IDisposable
{
    private readonly string _root;

    public TamperingTests()
    {
        _root = Path.Combine(Path.GetTempPath(), "secretblast-tamper-" + Guid.NewGuid().ToString("N"));
    }

    public void Dispose()
    {
        try { Directory.Delete(_root, recursive: true); } catch { }
    }

    private string VaultPath => Path.Combine(_root, "v");

    private async Task SeedVault(string name = "a", string value = "payload")
    {
        using var v = SecretVault.Create(VaultPath, "pw", TestVaultOptions.Fast());
        await v.SetAsync(name, value);
    }

    [Theory]
    [InlineData("nonce")]
    [InlineData("ciphertext")]
    [InlineData("tag")]
    public async Task FlippingAByteInAnyBase64Field_CausesVaultCorruptException(string field)
    {
        await SeedVault();
        TestFiles.FlipFirstByteOfBase64Field(TestFiles.SecretFile(VaultPath, "a"), field);

        using var v = SecretVault.Open(VaultPath);
        await v.UnlockAsync("pw");
        await Assert.ThrowsAsync<VaultCorruptException>(() => v.GetAsync("a"));
    }

    [Fact]
    public async Task RenamingSecretFile_BreaksAadBinding()
    {
        // AAD includes the secret name — renaming the file on disk should
        // fail decryption even though the ciphertext is otherwise untouched.
        await SeedVault("alpha", "whisper");

        var src = TestFiles.SecretFile(VaultPath, "alpha");
        var dst = TestFiles.SecretFile(VaultPath, "beta");
        File.Move(src, dst);

        using var v = SecretVault.Open(VaultPath);
        await v.UnlockAsync("pw");
        await Assert.ThrowsAsync<VaultCorruptException>(() => v.GetAsync("beta"));
    }

    [Fact]
    public async Task ReplacingSecretFile_FromAnotherSlotInSameVault_Fails()
    {
        // Two secrets in the SAME vault (same vaultId, same key).
        // Overwriting one with the other must still fail — AAD differs by name.
        using (var v = SecretVault.Create(VaultPath, "pw", TestVaultOptions.Fast()))
        {
            await v.SetAsync("one", "first");
            await v.SetAsync("two", "second");
        }
        File.Copy(
            TestFiles.SecretFile(VaultPath, "two"),
            TestFiles.SecretFile(VaultPath, "one"),
            overwrite: true);

        using var v2 = SecretVault.Open(VaultPath);
        await v2.UnlockAsync("pw");
        await Assert.ThrowsAsync<VaultCorruptException>(() => v2.GetAsync("one"));
    }

    [Fact]
    public async Task TamperingHeaderCanaryCiphertext_RejectsCorrectPassword()
    {
        await SeedVault();
        FlipNestedBase64(TestFiles.VaultJson(VaultPath), parent: "canary", child: "ciphertext");

        using var v = SecretVault.Open(VaultPath);
        await Assert.ThrowsAsync<InvalidMasterPasswordException>(() => v.UnlockAsync("pw"));
    }

    [Fact]
    public async Task TamperingHeaderSalt_CausesWrongKeyDerivation()
    {
        // Flipping bits of the salt changes what key Argon2 derives, so the
        // canary MAC fails and we surface InvalidMasterPasswordException —
        // the user's reality is "my password no longer works", which is right.
        await SeedVault();
        FlipNestedBase64(TestFiles.VaultJson(VaultPath), parent: "kdf", child: "salt");

        using var v = SecretVault.Open(VaultPath);
        await Assert.ThrowsAsync<InvalidMasterPasswordException>(() => v.UnlockAsync("pw"));
    }

    private static void FlipNestedBase64(string path, string parent, string child)
    {
        var obj = TestFiles.ReadObject(path);
        var section = obj[parent]!.AsObject();
        var bytes = Convert.FromBase64String((string)section[child]!);
        bytes[0] ^= 0xFF;
        section[child] = Convert.ToBase64String(bytes);
        TestFiles.Write(path, obj);
    }
}
