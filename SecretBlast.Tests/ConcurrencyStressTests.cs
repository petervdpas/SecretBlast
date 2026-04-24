using System;
using System.Collections.Concurrent;
using System.IO;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using SecretBlast;
using Xunit;

namespace SecretBlast.Tests;

/// <summary>
/// Stress the vault from multiple tasks at once and assert nothing bad
/// happens: no unhandled exceptions outside the known set, and the vault
/// is still openable / readable after the storm.
///
/// These tests are intentionally short-duration (a few hundred ms) so the
/// suite stays fast. They can't prove correctness of every race — but they
/// reliably catch "NullReference under concurrent Lock" /
/// "AesGcm on a half-zeroed key" regressions that the single-threaded tests
/// can't see.
/// </summary>
public sealed class ConcurrencyStressTests : IDisposable
{
    private readonly string _root;

    public ConcurrencyStressTests()
    {
        _root = Path.Combine(Path.GetTempPath(), "secretblast-stress-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(_root);
    }

    public void Dispose()
    {
        try { Directory.Delete(_root, recursive: true); } catch { }
    }

    private string VaultPath => Path.Combine(_root, "v");

    [Fact]
    public async Task ConcurrentSetAndGet_SameSecret_NeverCrashes()
    {
        using var v = SecretVault.Create(VaultPath, "pw", TestVaultOptions.Fast());
        await v.SetAsync("k", "initial");

        var unexpected = new ConcurrentBag<Exception>();
        var writerCount = 4;
        var readerCount = 4;
        var iterations = 50;

        var writers = Enumerable.Range(0, writerCount).Select(wId => Task.Run(async () =>
        {
            for (var i = 0; i < iterations; i++)
            {
                try { await v.SetAsync("k", $"w{wId}-{i}"); }
                catch (VaultLockedException) { /* acceptable — a Lock raced us */ }
                catch (Exception ex) { unexpected.Add(ex); }
            }
        }));

        var readers = Enumerable.Range(0, readerCount).Select(rId => Task.Run(async () =>
        {
            for (var i = 0; i < iterations; i++)
            {
                try { var _discard = await v.GetAsync("k"); }
                catch (VaultLockedException) { /* acceptable */ }
                catch (SecretNotFoundException) { /* Set may not have run yet */ }
                catch (VaultCorruptException) { /* acceptable: read saw a partially-written file */ }
                catch (Exception ex) { unexpected.Add(ex); }
            }
        }));

        await Task.WhenAll(writers.Concat(readers));

        Assert.True(unexpected.IsEmpty,
            "Unexpected exception types: " +
            string.Join(", ", unexpected.Select(e => e.GetType().Name).Distinct()));

        // Vault should still be functional.
        var final = await v.GetAsync("k");
        Assert.StartsWith("w", final);
    }

    [Fact]
    public async Task ConcurrentSet_DifferentSecrets_AllPersist()
    {
        // Each writer owns its own secret name; after the storm we expect
        // every secret to exist and decrypt. This would surface corruption
        // in the file I/O layer if writes were interfering with each other.
        using var v = SecretVault.Create(VaultPath, "pw", TestVaultOptions.Fast());

        const int writerCount = 8;
        const int perWriter = 20;

        var writers = Enumerable.Range(0, writerCount).Select(wId => Task.Run(async () =>
        {
            for (var i = 0; i < perWriter; i++)
                await v.SetAsync($"w{wId}_{i}", $"value-{wId}-{i}");
        }));

        await Task.WhenAll(writers);

        for (var w = 0; w < writerCount; w++)
        for (var i = 0; i < perWriter; i++)
        {
            Assert.Equal($"value-{w}-{i}", await v.GetAsync($"w{w}_{i}"));
        }
    }

    [Fact]
    public async Task LockRacingWithOps_NeverCorruptsInFlightOp()
    {
        // Repeatedly Lock() while reads / writes are in flight. Because we
        // clone the key per op (TakeKeyCopyAndResetTimer), the in-flight
        // op must always see a valid key — it cannot observe a zeroed one.
        using var v = SecretVault.Create(VaultPath, "pw", TestVaultOptions.Fast());
        await v.SetAsync("k", "hello");

        var stop = new CancellationTokenSource(TimeSpan.FromMilliseconds(500));
        var unexpected = new ConcurrentBag<Exception>();

        var locker = Task.Run(async () =>
        {
            while (!stop.IsCancellationRequested)
            {
                v.Lock();
                try { await v.UnlockAsync("pw", stop.Token); }
                catch (OperationCanceledException) { break; }
                catch (Exception ex) { unexpected.Add(ex); }
            }
        });

        var reader = Task.Run(async () =>
        {
            while (!stop.IsCancellationRequested)
            {
                try { var _discard = await v.GetAsync("k", stop.Token); }
                catch (VaultLockedException)     { /* OK */ }
                catch (OperationCanceledException) { break; }
                catch (Exception ex) { unexpected.Add(ex); }
            }
        });

        await Task.WhenAll(locker, reader);

        var badTypes = unexpected.Select(e => e.GetType().Name).Distinct().ToArray();
        Assert.True(!badTypes.Any(),
            $"Unexpected exceptions during Lock/Unlock/Get storm: {string.Join(", ", badTypes)}");
    }

    [Fact]
    public async Task ConcurrentDispose_IsSafe()
    {
        // N threads race to Dispose the same vault. Only one real dispose
        // happens; the rest are no-ops. Nothing should crash.
        var vault = SecretVault.Create(VaultPath, "pw", TestVaultOptions.Fast());

        var tasks = Enumerable.Range(0, 16).Select(_ => Task.Run(() => vault.Dispose()));
        await Task.WhenAll(tasks);

        // Further ops must all say "disposed".
        await Assert.ThrowsAsync<ObjectDisposedException>(() => vault.GetAsync("k"));
    }

    [Fact]
    public async Task VaultRemainsReadable_AfterStorm()
    {
        // After a mixed write/read/lock/unlock storm, re-open the vault and
        // check the last seen secret still decrypts. Validates that the
        // atomic-write invariant (*.tmp → rename) survives concurrency.
        string vaultPath = VaultPath;
        using (var v = SecretVault.Create(vaultPath, "pw", TestVaultOptions.Fast()))
        {
            var stop = new CancellationTokenSource(TimeSpan.FromMilliseconds(400));

            var writer = Task.Run(async () =>
            {
                var i = 0;
                while (!stop.IsCancellationRequested)
                {
                    try { await v.SetAsync("k", $"value-{i++}", stop.Token); }
                    catch (OperationCanceledException) { break; }
                    catch (VaultLockedException) { }
                }
            });

            var locker = Task.Run(async () =>
            {
                while (!stop.IsCancellationRequested)
                {
                    v.Lock();
                    try { await v.UnlockAsync("pw", stop.Token); }
                    catch (OperationCanceledException) { break; }
                    await Task.Delay(25);
                }
            });

            await Task.WhenAll(writer, locker);
        }

        // Re-open fresh; vault.json and secrets/ must both still be sane.
        using var reopened = SecretVault.Open(vaultPath);
        await reopened.UnlockAsync("pw");
        var names = await reopened.ListAsync();
        Assert.Contains("k", names);
        var finalValue = await reopened.GetAsync("k");
        Assert.StartsWith("value-", finalValue);
    }
}
