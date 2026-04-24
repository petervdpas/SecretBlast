using System;
using System.IO;
using System.Linq;
using System.Threading.Tasks;
using SecretBlast;
using Xunit;

namespace SecretBlast.Tests;

/// <summary>
/// Value and password edge cases. Secret values are stored as UTF-8; passwords
/// are encoded as UTF-8 before Argon2 derivation. Both should survive any
/// input the string type can hold.
/// </summary>
public sealed class ValueAndPasswordTests : IDisposable
{
    private readonly string _root;

    public ValueAndPasswordTests()
    {
        _root = Path.Combine(Path.GetTempPath(), "secretblast-vp-" + Guid.NewGuid().ToString("N"));
    }

    public void Dispose()
    {
        try { Directory.Delete(_root, recursive: true); } catch { }
    }

    private string VaultPath => Path.Combine(_root, "v");

    // ---- value shapes ----

    [Fact]
    public async Task EmptyValue_Roundtrips()
    {
        using var v = SecretVault.Create(VaultPath, "pw", TestVaultOptions.Fast());
        await v.SetAsync("k", "");
        Assert.Equal("", await v.GetAsync("k"));
    }

    [Fact]
    public async Task LargeValue_Roundtrips()
    {
        var value = new string('x', 100_000); // 100 KB
        using var v = SecretVault.Create(VaultPath, "pw", TestVaultOptions.Fast());
        await v.SetAsync("k", value);
        Assert.Equal(value, await v.GetAsync("k"));
    }

    [Fact]
    public async Task UnicodeValue_Roundtrips()
    {
        // Emoji + combining characters + RTL text — all UTF-8 round-trip.
        var value = "🔐 Ω café مرحبا ́́ תל אביב";
        using var v = SecretVault.Create(VaultPath, "pw", TestVaultOptions.Fast());
        await v.SetAsync("k", value);
        Assert.Equal(value, await v.GetAsync("k"));
    }

    [Fact]
    public async Task ValueWithEmbeddedNulls_Roundtrips()
    {
        var value = "before\0middle\0after";
        using var v = SecretVault.Create(VaultPath, "pw", TestVaultOptions.Fast());
        await v.SetAsync("k", value);
        Assert.Equal(value, await v.GetAsync("k"));
    }

    [Fact]
    public async Task TwoSetsOfIdenticalValue_ProduceDifferentCiphertexts()
    {
        using var v = SecretVault.Create(VaultPath, "pw", TestVaultOptions.Fast());
        await v.SetAsync("k", "same-value");
        var firstCiphertext = ReadCiphertextField("k");

        await v.SetAsync("k", "same-value");
        var secondCiphertext = ReadCiphertextField("k");

        Assert.NotEqual(firstCiphertext, secondCiphertext);
    }

    [Fact]
    public async Task TwoSecretsWithIdenticalValues_HaveDifferentCiphertexts()
    {
        using var v = SecretVault.Create(VaultPath, "pw", TestVaultOptions.Fast());
        await v.SetAsync("a", "same-value");
        await v.SetAsync("b", "same-value");

        Assert.NotEqual(ReadCiphertextField("a"), ReadCiphertextField("b"));
    }

    // ---- password shapes ----

    [Fact]
    public async Task UnicodePassword_Roundtrips()
    {
        const string pw = "🔐 correct horse Ω 密碼";
        using (var v = SecretVault.Create(VaultPath, pw, TestVaultOptions.Fast()))
        {
            await v.SetAsync("k", "v");
        }
        using var v2 = SecretVault.Open(VaultPath);
        await v2.UnlockAsync(pw);
        Assert.Equal("v", await v2.GetAsync("k"));
    }

    [Fact]
    public async Task LongPassword_Roundtrips()
    {
        var pw = new string('p', 1024);
        using (var v = SecretVault.Create(VaultPath, pw, TestVaultOptions.Fast()))
        {
            await v.SetAsync("k", "v");
        }
        using var v2 = SecretVault.Open(VaultPath);
        await v2.UnlockAsync(pw);
        Assert.Equal("v", await v2.GetAsync("k"));
    }

    [Fact]
    public async Task WhitespaceInPasswordIsSignificant()
    {
        using (var v = SecretVault.Create(VaultPath, "pw", TestVaultOptions.Fast())) { }
        using var v2 = SecretVault.Open(VaultPath);
        await Assert.ThrowsAsync<InvalidMasterPasswordException>(() => v2.UnlockAsync("pw "));
        await Assert.ThrowsAsync<InvalidMasterPasswordException>(() => v2.UnlockAsync(" pw"));
    }

    [Fact]
    public async Task CaseMatters_InPasswords()
    {
        using (var v = SecretVault.Create(VaultPath, "Pw", TestVaultOptions.Fast())) { }
        using var v2 = SecretVault.Open(VaultPath);
        await Assert.ThrowsAsync<InvalidMasterPasswordException>(() => v2.UnlockAsync("pw"));
    }

    [Fact]
    public void CreateWithEmptyPassword_Throws()
    {
        Assert.Throws<ArgumentException>(
            () => SecretVault.Create(VaultPath, "", TestVaultOptions.Fast()));
    }

    [Fact]
    public async Task UnlockWithEmptyPassword_Throws()
    {
        using (var v = SecretVault.Create(VaultPath, "pw", TestVaultOptions.Fast())) { }
        using var v2 = SecretVault.Open(VaultPath);
        await Assert.ThrowsAsync<ArgumentException>(() => v2.UnlockAsync(""));
    }

    // ---- vault non-determinism ----

    [Fact]
    public void TwoVaultsCreatedWithSamePassword_HaveDifferentSaltsAndVaultIds()
    {
        var p1 = Path.Combine(_root, "v1");
        var p2 = Path.Combine(_root, "v2");

        using (var v1 = SecretVault.Create(p1, "pw", TestVaultOptions.Fast())) { }
        using (var v2 = SecretVault.Create(p2, "pw", TestVaultOptions.Fast())) { }

        var h1 = TestFiles.ReadObject(TestFiles.VaultJson(p1));
        var h2 = TestFiles.ReadObject(TestFiles.VaultJson(p2));

        Assert.NotEqual((string)h1["vaultId"]!,             (string)h2["vaultId"]!);
        Assert.NotEqual((string)h1["kdf"]!["salt"]!,        (string)h2["kdf"]!["salt"]!);
        Assert.NotEqual((string)h1["canary"]!["nonce"]!,    (string)h2["canary"]!["nonce"]!);
    }

    // ---- helpers ----

    private string ReadCiphertextField(string secretName)
    {
        var obj = TestFiles.ReadObject(TestFiles.SecretFile(VaultPath, secretName));
        return (string)obj["ciphertext"]!;
    }
}
