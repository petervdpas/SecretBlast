using System;
using System.IO;
using System.Threading.Tasks;
using SecretBlast;
using Xunit;

namespace SecretBlast.Tests;

/// <summary>
/// Dispose, Locked event, and auto-lock lifecycle. No crypto-payload assertions
/// here — these exercises target the state machine and timer only.
/// </summary>
public sealed class LifecycleTests : IDisposable
{
    private readonly string _root;

    public LifecycleTests()
    {
        _root = Path.Combine(Path.GetTempPath(), "secretblast-lc-" + Guid.NewGuid().ToString("N"));
    }

    public void Dispose()
    {
        try { Directory.Delete(_root, recursive: true); } catch { }
    }

    private string VaultPath => Path.Combine(_root, "v");

    // ---- dispose ----

    [Fact]
    public void Dispose_IsIdempotent()
    {
        var vault = SecretVault.Create(VaultPath, "pw", TestVaultOptions.Fast());
        vault.Dispose();
        vault.Dispose();   // must not throw
    }

    [Fact]
    public async Task Dispose_RaisesLockedOnce_WhenWasUnlocked()
    {
        var vault = SecretVault.Create(VaultPath, "pw", TestVaultOptions.Fast());
        var fired = 0;
        vault.Locked += (_, _) => fired++;
        vault.Dispose();
        Assert.Equal(1, fired);
        await Task.CompletedTask;
    }

    [Fact]
    public void Dispose_DoesNotRaiseLocked_WhenAlreadyLocked()
    {
        using (var v = SecretVault.Create(VaultPath, "pw", TestVaultOptions.Fast())) { }
        var vault = SecretVault.Open(VaultPath);
        var fired = 0;
        vault.Locked += (_, _) => fired++;
        vault.Dispose();
        Assert.Equal(0, fired);
    }

    [Fact]
    public async Task AllOpsAfterDispose_ThrowObjectDisposedException()
    {
        var vault = SecretVault.Create(VaultPath, "pw", TestVaultOptions.Fast());
        vault.Dispose();

        await Assert.ThrowsAsync<ObjectDisposedException>(() => vault.GetAsync("k"));
        await Assert.ThrowsAsync<ObjectDisposedException>(() => vault.SetAsync("k", "v"));
        await Assert.ThrowsAsync<ObjectDisposedException>(() => vault.DeleteAsync("k"));
        await Assert.ThrowsAsync<ObjectDisposedException>(() => vault.ListAsync());
        await Assert.ThrowsAsync<ObjectDisposedException>(() => vault.UnlockAsync("pw"));

        // Lock() after Dispose is a no-op (key is already null) — not a throw.
        vault.Lock();
    }

    // ---- Locked event ----

    [Fact]
    public async Task Lock_AfterUnlock_FiresEventOnce()
    {
        using (var v = SecretVault.Create(VaultPath, "pw", TestVaultOptions.Fast())) { }
        using var vault = SecretVault.Open(VaultPath);
        await vault.UnlockAsync("pw");

        var fired = 0;
        vault.Locked += (_, _) => fired++;
        vault.Lock();
        vault.Lock();   // second call is no-op

        Assert.Equal(1, fired);
    }

    [Fact]
    public async Task InvalidPasswordDuringUnlock_DoesNotFireLockedEvent()
    {
        // Failing Unlock must not leave the observer thinking a lock transition occurred.
        using (var v = SecretVault.Create(VaultPath, "pw", TestVaultOptions.Fast())) { }
        using var vault = SecretVault.Open(VaultPath);

        var fired = 0;
        vault.Locked += (_, _) => fired++;
        await Assert.ThrowsAsync<InvalidMasterPasswordException>(() => vault.UnlockAsync("wrong"));

        Assert.Equal(0, fired);
        Assert.True(vault.IsLocked);
    }

    // ---- auto-lock ----

    [Fact]
    public async Task AutoLock_FiresLockedEvent()
    {
        using var vault = SecretVault.Create(
            VaultPath, "pw", TestVaultOptions.FastWithAutoLock(TimeSpan.FromMilliseconds(100)));
        var fired = 0;
        vault.Locked += (_, _) => fired++;

        await Task.Delay(400);
        Assert.True(vault.IsLocked);
        Assert.Equal(1, fired);
    }

    [Fact]
    public async Task AutoLock_IsResetByActivity()
    {
        using var vault = SecretVault.Create(
            VaultPath, "pw", TestVaultOptions.FastWithAutoLock(TimeSpan.FromMilliseconds(250)));

        // Bump the timer twice while it's still counting down; the vault must
        // remain unlocked until ~250 ms AFTER the last op.
        await vault.SetAsync("k", "v1");
        await Task.Delay(150);
        Assert.False(vault.IsLocked);

        await vault.SetAsync("k", "v2");
        await Task.Delay(150);
        Assert.False(vault.IsLocked);

        // Now go idle past the timeout.
        await Task.Delay(400);
        Assert.True(vault.IsLocked);
    }

    [Fact]
    public async Task AutoLockZero_NeverLocks()
    {
        using var vault = SecretVault.Create(
            VaultPath, "pw", TestVaultOptions.FastWithAutoLock(TimeSpan.Zero));
        await Task.Delay(300);
        Assert.False(vault.IsLocked);
    }

    [Fact]
    public async Task AutoLockInfinite_NeverLocks()
    {
        using var vault = SecretVault.Create(
            VaultPath, "pw", TestVaultOptions.FastWithAutoLock(System.Threading.Timeout.InfiniteTimeSpan));
        await Task.Delay(300);
        Assert.False(vault.IsLocked);
    }

    [Fact]
    public async Task ReUnlockAfterAutoLock_Works()
    {
        using var vault = SecretVault.Create(
            VaultPath, "pw", TestVaultOptions.FastWithAutoLock(TimeSpan.FromMilliseconds(100)));
        await vault.SetAsync("k", "hello");

        await Task.Delay(400);
        Assert.True(vault.IsLocked);

        await vault.UnlockAsync("pw");
        Assert.Equal("hello", await vault.GetAsync("k"));
    }
}
