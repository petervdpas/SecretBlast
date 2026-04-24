using System;
using System.IO;
using System.Linq;
using System.Threading.Tasks;
using SecretBlast;
using Xunit;

namespace SecretBlast.Tests;

/// <summary>
/// Secret-name validation + KDF-parameter edge cases.
/// </summary>
public sealed class NamingAndKdfTests : IDisposable
{
    private readonly string _root;

    public NamingAndKdfTests()
    {
        _root = Path.Combine(Path.GetTempPath(), "secretblast-nm-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(_root);
    }

    public void Dispose()
    {
        try { Directory.Delete(_root, recursive: true); } catch { }
    }

    private string VaultPath => Path.Combine(_root, "v");

    // ---- valid names ----

    [Theory]
    [InlineData("a")]
    [InlineData("simple")]
    [InlineData("with-dash")]
    [InlineData("with_underscore")]
    [InlineData("with.dots.and.more")]
    [InlineData("123numeric-start")]
    [InlineData("mixed_Case-And.Digits123")]
    public async Task ValidNames_Roundtrip(string name)
    {
        using var v = SecretVault.Create(VaultPath, "pw", TestVaultOptions.Fast());
        await v.SetAsync(name, "value");
        Assert.Equal("value", await v.GetAsync(name));
    }

    [Fact]
    public async Task UnicodeLetterNames_AreAllowed()
    {
        // char.IsLetterOrDigit is Unicode-aware; Greek/Cyrillic/Arabic letters pass.
        using var v = SecretVault.Create(VaultPath, "pw", TestVaultOptions.Fast());
        await v.SetAsync("αβγ", "greek");
        await v.SetAsync("密碼", "zh");
        await v.SetAsync("секрет", "ru");

        Assert.Equal("greek", await v.GetAsync("αβγ"));
        Assert.Equal("zh",    await v.GetAsync("密碼"));
        Assert.Equal("ru",    await v.GetAsync("секрет"));
    }

    [Fact]
    public async Task NamesDifferingOnlyInCase_AreDistinct_OnCaseSensitiveFs()
    {
        // Linux filesystems are case-sensitive; "Foo" and "foo" are two files.
        // Skip on case-insensitive platforms so we don't get a false negative.
        if (!IsCaseSensitiveFilesystem(_root)) return;

        using var v = SecretVault.Create(VaultPath, "pw", TestVaultOptions.Fast());
        await v.SetAsync("foo", "lower");
        await v.SetAsync("Foo", "upper");
        Assert.Equal("lower", await v.GetAsync("foo"));
        Assert.Equal("upper", await v.GetAsync("Foo"));
    }

    // ---- invalid names ----

    [Theory]
    [InlineData("")]
    [InlineData(" ")]
    [InlineData("has space")]
    [InlineData("has/slash")]
    [InlineData("has\\backslash")]
    [InlineData("has\nnewline")]
    [InlineData("has\ttab")]
    [InlineData("has:colon")]
    [InlineData("has*wildcard")]
    [InlineData("has?question")]
    public async Task InvalidNames_Rejected(string name)
    {
        using var v = SecretVault.Create(VaultPath, "pw", TestVaultOptions.Fast());
        await Assert.ThrowsAsync<ArgumentException>(() => v.SetAsync(name, "v"));
        await Assert.ThrowsAsync<ArgumentException>(() => v.GetAsync(name));
        await Assert.ThrowsAsync<ArgumentException>(() => v.DeleteAsync(name));
    }

    [Fact]
    public async Task VeryLongName_Roundtrips()
    {
        // 150 is safely under the 255-char NAME_MAX on most filesystems,
        // accounting for the ".secret" suffix.
        var name = new string('a', 150);
        using var v = SecretVault.Create(VaultPath, "pw", TestVaultOptions.Fast());
        await v.SetAsync(name, "payload");
        Assert.Equal("payload", await v.GetAsync(name));
    }

    // ---- KDF algorithm ----

    [Fact]
    public async Task KdfAlgorithmComparison_IsCaseInsensitive()
    {
        // Hand-upgrade a vault's header algorithm casing and ensure Open accepts it.
        using (var v = SecretVault.Create(VaultPath, "pw", TestVaultOptions.Fast())) { }
        var obj = TestFiles.ReadObject(TestFiles.VaultJson(VaultPath));
        obj["kdf"]!.AsObject()["algorithm"] = "ARGON2ID";
        TestFiles.Write(TestFiles.VaultJson(VaultPath), obj);

        using var v2 = SecretVault.Open(VaultPath);
        await v2.UnlockAsync("pw"); // must not throw
    }

    [Theory]
    [InlineData(256, 1, 1)]
    [InlineData(512, 2, 1)]
    [InlineData(1024, 1, 2)]
    public async Task Argon2_WithVaryingParameters_Roundtrips(int memoryKiB, int iters, int lanes)
    {
        var options = new VaultOptions
        {
            AutoLockIdle = TimeSpan.Zero,
            Kdf = new Argon2Parameters(memoryKiB, iters, lanes),
        };
        using (var v = SecretVault.Create(VaultPath, "pw", options))
        {
            await v.SetAsync("k", "v");
        }
        using var v2 = SecretVault.Open(VaultPath);
        await v2.UnlockAsync("pw");
        Assert.Equal("v", await v2.GetAsync("k"));
    }

    [Fact]
    public async Task Argon2Parameters_PersistedInHeader_AreUsedOnUnlock()
    {
        // Create with one set of params. Open with default options (different params).
        // Header params must win — unlock must still succeed.
        var tight = new VaultOptions
        {
            AutoLockIdle = TimeSpan.Zero,
            Kdf = new Argon2Parameters(256, 1, 1),
        };
        using (var v = SecretVault.Create(VaultPath, "pw", tight))
        {
            await v.SetAsync("k", "v");
        }

        using var v2 = SecretVault.Open(VaultPath, new VaultOptions()); // Argon2Parameters.Default
        await v2.UnlockAsync("pw");
        Assert.Equal("v", await v2.GetAsync("k"));
    }

    // ---- helpers ----

    private static bool IsCaseSensitiveFilesystem(string dir)
    {
        var probe = Path.Combine(dir, "CaseProbe");
        File.WriteAllText(probe, "");
        try { return !File.Exists(Path.Combine(dir, "caseprobe")); }
        finally { File.Delete(probe); }
    }
}
