using System;
using System.IO;
using System.Threading.Tasks;
using SecretBlast;
using SecretBlast.Interfaces;
using Xunit;

namespace SecretBlast.Tests;

/// <summary>
/// Covers the parts of <c>FileSecretVault</c> that don't require real crypto:
/// guard ordering, validation, and filesystem-level behaviour.
/// </summary>
public sealed class FileSecretVaultStateMachineTests : IDisposable
{
    private readonly string _tempRoot;

    public FileSecretVaultStateMachineTests()
    {
        _tempRoot = Path.Combine(Path.GetTempPath(), "secretblast-tests-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(_tempRoot);
    }

    public void Dispose()
    {
        try { Directory.Delete(_tempRoot, recursive: true); }
        catch { /* best-effort cleanup */ }
    }

    [Fact]
    public void Open_OnEmptyDirectory_ThrowsVaultNotFoundException()
    {
        Assert.Throws<VaultNotFoundException>(() => SecretVault.Open(_tempRoot));
    }

    [Fact]
    public void Create_OverExistingVault_ThrowsVaultAlreadyExistsException()
    {
        using (var vault = SecretVault.Create(_tempRoot, "pw", TestVaultOptions.Fast())) { }
        Assert.Throws<VaultAlreadyExistsException>(
            () => SecretVault.Create(_tempRoot, "pw", TestVaultOptions.Fast()));
    }

    [Fact]
    public async Task GetAsync_OnFreshlyOpenedLockedVault_ThrowsVaultLockedException()
    {
        using (var v = SecretVault.Create(_tempRoot, "pw", TestVaultOptions.Fast())) { }
        using var vault = SecretVault.Open(_tempRoot);
        Assert.True(vault.IsLocked);
        await Assert.ThrowsAsync<VaultLockedException>(() => vault.GetAsync("anything"));
    }

    [Fact]
    public async Task SetAsync_OnLockedVault_ThrowsVaultLockedException()
    {
        using (var v = SecretVault.Create(_tempRoot, "pw", TestVaultOptions.Fast())) { }
        using var vault = SecretVault.Open(_tempRoot);
        await Assert.ThrowsAsync<VaultLockedException>(() => vault.SetAsync("anything", "value"));
    }

    [Fact]
    public async Task DeleteAsync_OnLockedVault_ThrowsVaultLockedException()
    {
        using (var v = SecretVault.Create(_tempRoot, "pw", TestVaultOptions.Fast())) { }
        using var vault = SecretVault.Open(_tempRoot);
        await Assert.ThrowsAsync<VaultLockedException>(() => vault.DeleteAsync("anything"));
    }

    [Fact]
    public async Task ListAsync_OnFreshVault_ReturnsEmpty()
    {
        using var vault = SecretVault.Create(_tempRoot, "pw", TestVaultOptions.Fast());
        var names = await vault.ListAsync();
        Assert.Empty(names);
    }

    [Fact]
    public async Task Dispose_ThenGetAsync_ThrowsObjectDisposedException()
    {
        using (var v = SecretVault.Create(_tempRoot, "pw", TestVaultOptions.Fast())) { }
        var vault = SecretVault.Open(_tempRoot);
        vault.Dispose();
        await Assert.ThrowsAsync<ObjectDisposedException>(() => vault.GetAsync("x"));
    }

    [Theory]
    [InlineData("")]
    [InlineData("   ")]
    [InlineData("has/slash")]
    [InlineData("has\\backslash")]
    [InlineData("has space")]
    public async Task SetAsync_RejectsInvalidNames(string badName)
    {
        using var vault = SecretVault.Create(_tempRoot, "pw", TestVaultOptions.Fast());
        await Assert.ThrowsAsync<ArgumentException>(() => vault.SetAsync(badName, "v"));
    }
}
