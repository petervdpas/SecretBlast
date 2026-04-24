using System;
using System.IO;
using System.Threading.Tasks;
using SecretBlast;
using Xunit;

namespace SecretBlast.Tests;

/// <summary>
/// Vault-file corruption cases: malformed <c>vault.json</c> on Open,
/// malformed or unexpected <c>*.secret</c> on Get.
/// Everything here must surface as <see cref="VaultCorruptException"/> or
/// a clearly-named exception — never an opaque crash.
/// </summary>
public sealed class MalformedVaultTests : IDisposable
{
    private readonly string _root;

    public MalformedVaultTests()
    {
        _root = Path.Combine(Path.GetTempPath(), "secretblast-malf-" + Guid.NewGuid().ToString("N"));
    }

    public void Dispose()
    {
        try { Directory.Delete(_root, recursive: true); } catch { }
    }

    private string VaultPath => Path.Combine(_root, "v");

    private async Task SeedWithOneSecret()
    {
        using var v = SecretVault.Create(VaultPath, "pw", TestVaultOptions.Fast());
        await v.SetAsync("a", "hello");
    }

    // ---- vault.json ----

    [Fact]
    public void Open_OnNonJsonHeader_ThrowsVaultCorruptException()
    {
        Directory.CreateDirectory(VaultPath);
        File.WriteAllText(TestFiles.VaultJson(VaultPath), "this is not json");
        Assert.Throws<VaultCorruptException>(() => SecretVault.Open(VaultPath));
    }

    [Fact]
    public async Task Open_OnUnknownHeaderVersion_ThrowsVaultCorruptException()
    {
        await SeedWithOneSecret();
        TestFiles.SetNumberField(TestFiles.VaultJson(VaultPath), "version", 999);
        Assert.Throws<VaultCorruptException>(() => SecretVault.Open(VaultPath));
    }

    [Fact]
    public async Task Open_WhenVaultIdMissing_ThrowsVaultCorruptException()
    {
        await SeedWithOneSecret();
        TestFiles.SetField(TestFiles.VaultJson(VaultPath), "vaultId", "");
        Assert.Throws<VaultCorruptException>(() => SecretVault.Open(VaultPath));
    }

    [Fact]
    public async Task Open_OnUnknownKdfAlgorithm_ThrowsVaultCorruptException()
    {
        await SeedWithOneSecret();
        var obj = TestFiles.ReadObject(TestFiles.VaultJson(VaultPath));
        obj["kdf"]!.AsObject()["algorithm"] = "scrypt";
        TestFiles.Write(TestFiles.VaultJson(VaultPath), obj);

        Assert.Throws<VaultCorruptException>(() => SecretVault.Open(VaultPath));
    }

    [Fact]
    public async Task Open_WhenSaltMissing_ThrowsVaultCorruptException()
    {
        await SeedWithOneSecret();
        var obj = TestFiles.ReadObject(TestFiles.VaultJson(VaultPath));
        obj["kdf"]!.AsObject()["salt"] = "";
        TestFiles.Write(TestFiles.VaultJson(VaultPath), obj);

        Assert.Throws<VaultCorruptException>(() => SecretVault.Open(VaultPath));
    }

    [Fact]
    public async Task Unlock_WhenSaltNotBase64_ThrowsVaultCorruptException()
    {
        await SeedWithOneSecret();
        var obj = TestFiles.ReadObject(TestFiles.VaultJson(VaultPath));
        obj["kdf"]!.AsObject()["salt"] = "!!!not base64!!!";
        TestFiles.Write(TestFiles.VaultJson(VaultPath), obj);

        using var v = SecretVault.Open(VaultPath);
        await Assert.ThrowsAsync<VaultCorruptException>(() => v.UnlockAsync("pw"));
    }

    [Fact]
    public async Task Unlock_WhenCanaryNonceNotBase64_ThrowsVaultCorruptException()
    {
        await SeedWithOneSecret();
        var obj = TestFiles.ReadObject(TestFiles.VaultJson(VaultPath));
        obj["canary"]!.AsObject()["nonce"] = "###";
        TestFiles.Write(TestFiles.VaultJson(VaultPath), obj);

        using var v = SecretVault.Open(VaultPath);
        await Assert.ThrowsAsync<VaultCorruptException>(() => v.UnlockAsync("pw"));
    }

    // ---- *.secret ----

    [Fact]
    public async Task Get_OnNonJsonRecord_ThrowsVaultCorruptException()
    {
        await SeedWithOneSecret();
        File.WriteAllText(TestFiles.SecretFile(VaultPath, "a"), "this is not json");

        using var v = SecretVault.Open(VaultPath);
        await v.UnlockAsync("pw");
        await Assert.ThrowsAsync<VaultCorruptException>(() => v.GetAsync("a"));
    }

    [Fact]
    public async Task Get_OnUnknownRecordVersion_ThrowsVaultCorruptException()
    {
        await SeedWithOneSecret();
        TestFiles.SetNumberField(TestFiles.SecretFile(VaultPath, "a"), "version", 42);

        using var v = SecretVault.Open(VaultPath);
        await v.UnlockAsync("pw");
        await Assert.ThrowsAsync<VaultCorruptException>(() => v.GetAsync("a"));
    }

    [Fact]
    public async Task Get_OnUnknownRecordAlgorithm_ThrowsVaultCorruptException()
    {
        await SeedWithOneSecret();
        TestFiles.SetField(TestFiles.SecretFile(VaultPath, "a"), "algorithm", "chacha20-poly1305");

        using var v = SecretVault.Open(VaultPath);
        await v.UnlockAsync("pw");
        await Assert.ThrowsAsync<VaultCorruptException>(() => v.GetAsync("a"));
    }

    [Fact]
    public async Task Get_WhenNonceIsEmpty_ThrowsVaultCorruptException()
    {
        await SeedWithOneSecret();
        TestFiles.SetField(TestFiles.SecretFile(VaultPath, "a"), "nonce", "");

        using var v = SecretVault.Open(VaultPath);
        await v.UnlockAsync("pw");
        await Assert.ThrowsAsync<VaultCorruptException>(() => v.GetAsync("a"));
    }

    [Fact]
    public async Task Get_WhenNonceHasWrongLength_ThrowsVaultCorruptException()
    {
        // A 16-byte base64 value (wrong length — AES-GCM needs 12).
        await SeedWithOneSecret();
        var wrongNonce = Convert.ToBase64String(new byte[16]);
        TestFiles.SetField(TestFiles.SecretFile(VaultPath, "a"), "nonce", wrongNonce);

        using var v = SecretVault.Open(VaultPath);
        await v.UnlockAsync("pw");
        await Assert.ThrowsAsync<VaultCorruptException>(() => v.GetAsync("a"));
    }

    [Fact]
    public async Task Get_WhenTagHasWrongLength_ThrowsVaultCorruptException()
    {
        await SeedWithOneSecret();
        var wrongTag = Convert.ToBase64String(new byte[8]);
        TestFiles.SetField(TestFiles.SecretFile(VaultPath, "a"), "tag", wrongTag);

        using var v = SecretVault.Open(VaultPath);
        await v.UnlockAsync("pw");
        await Assert.ThrowsAsync<VaultCorruptException>(() => v.GetAsync("a"));
    }

    [Fact]
    public async Task Get_WhenCiphertextNotBase64_ThrowsVaultCorruptException()
    {
        await SeedWithOneSecret();
        TestFiles.SetField(TestFiles.SecretFile(VaultPath, "a"), "ciphertext", "###not b64###");

        using var v = SecretVault.Open(VaultPath);
        await v.UnlockAsync("pw");
        await Assert.ThrowsAsync<VaultCorruptException>(() => v.GetAsync("a"));
    }
}
