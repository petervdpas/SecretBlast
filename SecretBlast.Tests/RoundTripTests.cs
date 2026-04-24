using System;
using System.IO;
using System.Linq;
using System.Text.Json;
using System.Threading.Tasks;
using SecretBlast;
using SecretBlast.Interfaces;
using Xunit;

namespace SecretBlast.Tests;

/// <summary>
/// End-to-end Create / Set / Close / Open / Unlock / Get / Delete tests.
/// Uses cheap Argon2 parameters (<see cref="TestVaultOptions.Fast"/>) so the
/// suite stays fast — real vaults should use defaults.
/// </summary>
public sealed class RoundTripTests : IDisposable
{
    private readonly string _root;

    public RoundTripTests()
    {
        _root = Path.Combine(Path.GetTempPath(), "secretblast-rt-" + Guid.NewGuid().ToString("N"));
    }

    public void Dispose()
    {
        try { Directory.Delete(_root, recursive: true); }
        catch { /* best-effort */ }
    }

    private string VaultPath => Path.Combine(_root, "vault");

    [Fact]
    public async Task CreateSetCloseOpenUnlockGet_Roundtrips()
    {
        using (var v = SecretVault.Create(VaultPath, "correct horse battery staple", TestVaultOptions.Fast()))
        {
            Assert.False(v.IsLocked);
            await v.SetAsync("azure-prod-sql", "Server=tcp:prod.sql;Database=app;");
            await v.SetAsync("github-token",   "ghp_fake_token_xyz");
        }

        using var v2 = SecretVault.Open(VaultPath);
        Assert.True(v2.IsLocked);
        await v2.UnlockAsync("correct horse battery staple");

        Assert.Equal("Server=tcp:prod.sql;Database=app;", await v2.GetAsync("azure-prod-sql"));
        Assert.Equal("ghp_fake_token_xyz",               await v2.GetAsync("github-token"));
    }

    [Fact]
    public async Task List_ReturnsAllSecretNames()
    {
        using var v = SecretVault.Create(VaultPath, "pw", TestVaultOptions.Fast());
        await v.SetAsync("a", "1");
        await v.SetAsync("b", "2");
        await v.SetAsync("c", "3");

        var names = await v.ListAsync();
        Assert.Equal(new[] { "a", "b", "c" }, names.OrderBy(n => n).ToArray());
    }

    [Fact]
    public async Task Delete_RemovesSecret()
    {
        using var v = SecretVault.Create(VaultPath, "pw", TestVaultOptions.Fast());
        await v.SetAsync("a", "one");
        await v.SetAsync("b", "two");

        await v.DeleteAsync("a");

        var names = await v.ListAsync();
        Assert.Equal(new[] { "b" }, names.ToArray());
        await Assert.ThrowsAsync<SecretNotFoundException>(() => v.GetAsync("a"));
    }

    [Fact]
    public async Task Delete_OnMissingSecret_Throws()
    {
        using var v = SecretVault.Create(VaultPath, "pw", TestVaultOptions.Fast());
        await Assert.ThrowsAsync<SecretNotFoundException>(() => v.DeleteAsync("nope"));
    }

    [Fact]
    public async Task Get_OnMissingSecret_Throws()
    {
        using var v = SecretVault.Create(VaultPath, "pw", TestVaultOptions.Fast());
        await Assert.ThrowsAsync<SecretNotFoundException>(() => v.GetAsync("nope"));
    }

    [Fact]
    public async Task Set_Overwrites_ExistingSecret()
    {
        using var v = SecretVault.Create(VaultPath, "pw", TestVaultOptions.Fast());
        await v.SetAsync("k", "v1");
        await v.SetAsync("k", "v2");
        Assert.Equal("v2", await v.GetAsync("k"));
    }

    [Fact]
    public async Task Unlock_WithWrongPassword_ThrowsInvalidMasterPasswordException()
    {
        using (var v = SecretVault.Create(VaultPath, "right", TestVaultOptions.Fast())) { }
        using var v2 = SecretVault.Open(VaultPath);
        await Assert.ThrowsAsync<InvalidMasterPasswordException>(
            () => v2.UnlockAsync("wrong"));
        Assert.True(v2.IsLocked);
    }

    [Fact]
    public async Task Unlock_WhileAlreadyUnlocked_IsNoOp()
    {
        using var v = SecretVault.Create(VaultPath, "pw", TestVaultOptions.Fast());
        Assert.False(v.IsLocked);
        await v.UnlockAsync("pw");   // no-op, must not throw
        await v.UnlockAsync("anything-else-does-not-matter");
        Assert.False(v.IsLocked);
        await v.SetAsync("k", "v");
        Assert.Equal("v", await v.GetAsync("k"));
    }

    [Fact]
    public async Task Lock_Raises_LockedEvent_And_BlocksSubsequentOps()
    {
        using var v = SecretVault.Create(VaultPath, "pw", TestVaultOptions.Fast());
        await v.SetAsync("k", "v");

        var fired = 0;
        v.Locked += (_, _) => fired++;

        v.Lock();
        Assert.True(v.IsLocked);
        Assert.Equal(1, fired);

        v.Lock();   // second Lock is a no-op, must not fire again
        Assert.Equal(1, fired);

        await Assert.ThrowsAsync<VaultLockedException>(() => v.GetAsync("k"));
    }

    [Fact]
    public async Task TamperedCiphertext_FailsWithVaultCorrupt()
    {
        using (var v = SecretVault.Create(VaultPath, "pw", TestVaultOptions.Fast()))
        {
            await v.SetAsync("a", "hello");
        }

        var recordPath = Path.Combine(VaultPath, "secrets", "a.secret");
        var json = File.ReadAllText(recordPath);
        using (var doc = JsonDocument.Parse(json))
        {
            // Flip the first byte of the ciphertext to trigger an auth failure.
            var original = doc.RootElement.GetProperty("ciphertext").GetString()!;
            var bytes = Convert.FromBase64String(original);
            bytes[0] ^= 0xFF;
            var tampered = Convert.ToBase64String(bytes);

            using var ms = new MemoryStream();
            using (var w = new Utf8JsonWriter(ms, new JsonWriterOptions { Indented = true }))
            {
                w.WriteStartObject();
                foreach (var p in doc.RootElement.EnumerateObject())
                {
                    if (p.NameEquals("ciphertext")) w.WriteString("ciphertext", tampered);
                    else p.WriteTo(w);
                }
                w.WriteEndObject();
            }
            File.WriteAllBytes(recordPath, ms.ToArray());
        }

        using var v2 = SecretVault.Open(VaultPath);
        await v2.UnlockAsync("pw");
        await Assert.ThrowsAsync<VaultCorruptException>(() => v2.GetAsync("a"));
    }

    [Fact]
    public async Task SwappedSecretFromAnotherVault_FailsWithVaultCorrupt()
    {
        var otherVault = Path.Combine(_root, "other");

        // Two separate vaults with the SAME password and the SAME secret name,
        // but different vault ids. Swapping "a.secret" between them must fail.
        using (var v1 = SecretVault.Create(VaultPath,  "same-pw", TestVaultOptions.Fast()))
        using (var v2 = SecretVault.Create(otherVault, "same-pw", TestVaultOptions.Fast()))
        {
            await v1.SetAsync("a", "from-vault-1");
            await v2.SetAsync("a", "from-vault-2");
        }

        var victim   = Path.Combine(VaultPath,  "secrets", "a.secret");
        var intruder = Path.Combine(otherVault, "secrets", "a.secret");
        File.Copy(intruder, victim, overwrite: true);

        using var v = SecretVault.Open(VaultPath);
        await v.UnlockAsync("same-pw");
        await Assert.ThrowsAsync<VaultCorruptException>(() => v.GetAsync("a"));
    }

    [Fact]
    public async Task List_DoesNotRequire_Unlock()
    {
        using (var v = SecretVault.Create(VaultPath, "pw", TestVaultOptions.Fast()))
        {
            await v.SetAsync("a", "1");
        }

        using var v2 = SecretVault.Open(VaultPath);
        Assert.True(v2.IsLocked);
        var names = await v2.ListAsync();
        Assert.Equal(new[] { "a" }, names.ToArray());
    }

    [Fact]
    public async Task AutoLock_FiresAfterIdle()
    {
        using var v = SecretVault.Create(
            VaultPath, "pw", TestVaultOptions.FastWithAutoLock(TimeSpan.FromMilliseconds(150)));
        Assert.False(v.IsLocked);
        await Task.Delay(400);
        Assert.True(v.IsLocked);
    }

    [Fact]
    public async Task AtomicWrite_DoesNotLeaveTmpFile()
    {
        using var v = SecretVault.Create(VaultPath, "pw", TestVaultOptions.Fast());
        await v.SetAsync("a", "v");

        var secretsDir = Path.Combine(VaultPath, "secrets");
        Assert.Empty(Directory.EnumerateFiles(secretsDir, "*.tmp"));
    }

    [Fact]
    public async Task HeaderOnDisk_IsPlaintextJson_WithExpectedShape()
    {
        using (var v = SecretVault.Create(VaultPath, "pw", TestVaultOptions.Fast())) { }

        var json = File.ReadAllText(Path.Combine(VaultPath, "vault.json"));
        using var doc = JsonDocument.Parse(json);
        var root = doc.RootElement;

        Assert.Equal(1, root.GetProperty("version").GetInt32());
        Assert.False(string.IsNullOrEmpty(root.GetProperty("vaultId").GetString()));
        Assert.Equal("argon2id", root.GetProperty("kdf").GetProperty("algorithm").GetString());
        Assert.False(string.IsNullOrEmpty(root.GetProperty("kdf").GetProperty("salt").GetString()));
        Assert.False(string.IsNullOrEmpty(root.GetProperty("canary").GetProperty("nonce").GetString()));
    }
}
