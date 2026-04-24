using System;
using System.IO;
using System.Threading.Tasks;
using SecretBlast;
using Xunit;

namespace SecretBlast.Tests;

/// <summary>
/// Property-style fuzz pass. Not a real fuzzer — just a large deterministic
/// pool of malformed inputs, designed to catch the one parser path that
/// throws NullReferenceException / JsonException / IndexOutOfRangeException
/// instead of our <see cref="VaultCorruptException"/>.
///
/// The invariant: no matter what junk sits on disk at <c>vault.json</c> or
/// <c>*.secret</c>, the public API must only ever surface
/// <see cref="VaultCorruptException"/>, <see cref="VaultNotFoundException"/>,
/// or <see cref="InvalidMasterPasswordException"/>.
/// </summary>
public sealed class FuzzTests : IDisposable
{
    private readonly string _root;

    public FuzzTests()
    {
        _root = Path.Combine(Path.GetTempPath(), "secretblast-fuzz-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(_root);
    }

    public void Dispose()
    {
        try { Directory.Delete(_root, recursive: true); } catch { }
    }

    private string VaultPath => Path.Combine(_root, "v");

    /// <summary>
    /// Known shapes: not JSON, empty, arrays, scalars, BOMs, UTF-16,
    /// giant strings, partial headers. These are the edge cases that
    /// real malformed files tend to look like.
    /// </summary>
    public static TheoryData<string, byte[]> AdversarialHeaderPayloads()
    {
        static byte[] Utf8(string s) => System.Text.Encoding.UTF8.GetBytes(s);
        static byte[] Utf16(string s) => System.Text.Encoding.Unicode.GetBytes(s);

        var data = new TheoryData<string, byte[]>();
        data.Add("empty",                 Array.Empty<byte>());
        data.Add("whitespace only",       Utf8("   \n\t  "));
        data.Add("plain text",            Utf8("hello, world"));
        data.Add("non-object: array",     Utf8("[1,2,3]"));
        data.Add("non-object: scalar",    Utf8("42"));
        data.Add("non-object: string",    Utf8("\"just a string\""));
        data.Add("non-object: null",      Utf8("null"));
        data.Add("object: empty",         Utf8("{}"));
        data.Add("object: partial",       Utf8("{ \"version\": 1, "));
        data.Add("object: truncated",     Utf8("{ \"version\": 1, \"vaultId\": \"abc\""));
        data.Add("object: unterminated",  Utf8("{ \"version\": 1"));
        data.Add("nested wrong shape",    Utf8("{ \"kdf\": \"oops\" }"));
        data.Add("kdf as array",          Utf8("{ \"version\": 1, \"kdf\": [] }"));
        data.Add("version as string",     Utf8("{ \"version\": \"one\" }"));
        data.Add("huge version",          Utf8("{ \"version\": 99999999999999999999 }"));
        data.Add("utf16",                 Utf16("{\"version\": 1}"));
        data.Add("bom + nonsense",        new byte[] { 0xEF, 0xBB, 0xBF, 0xFF, 0xFE, 0x00, 0x01 });
        data.Add("all zeros",             new byte[1024]);
        data.Add("random-ish bytes",      RandomBytes(seed: 1, length: 4096));
        data.Add("random-ish bytes x2",   RandomBytes(seed: 2, length: 4096));
        data.Add("random-ish bytes x3",   RandomBytes(seed: 3, length: 4096));
        return data;
    }

    [Theory]
    [MemberData(nameof(AdversarialHeaderPayloads))]
    public void Open_OnAdversarialHeader_SurfacesKnownException(string label, byte[] bytes)
    {
        Directory.CreateDirectory(VaultPath);
        File.WriteAllBytes(TestFiles.VaultJson(VaultPath), bytes);

        try
        {
            SecretVault.Open(VaultPath).Dispose();
            // Valid JSON that happens to parse into a header object with
            // version 0 / empty strings is still invalid — our validator
            // rejects it. Reaching this line would mean Open silently
            // accepted adversarial bytes, which is the bug we're testing for.
            Assert.Fail($"[{label}] Open unexpectedly succeeded — validator too permissive.");
        }
        catch (VaultCorruptException)   { /* expected */ }
        catch (VaultNotFoundException)  { /* expected */ }
        catch (Exception ex)
        {
            Assert.Fail($"[{label}] Unexpected exception type: {ex.GetType().Name}: {ex.Message}");
        }
    }

    [Theory]
    [MemberData(nameof(AdversarialHeaderPayloads))]
    public async Task Get_OnAdversarialRecord_SurfacesKnownException(string label, byte[] bytes)
    {
        // Start from a real vault so Open / Unlock succeed; then corrupt the
        // secret file with the adversarial payload.
        using (var v = SecretVault.Create(VaultPath, "pw", TestVaultOptions.Fast()))
        {
            await v.SetAsync("a", "ok");
        }
        File.WriteAllBytes(TestFiles.SecretFile(VaultPath, "a"), bytes);

        using var v2 = SecretVault.Open(VaultPath);
        await v2.UnlockAsync("pw");

        try
        {
            var value = await v2.GetAsync("a");
            // A fuzz payload should never decrypt to a valid plaintext.
            Assert.Fail($"[{label}] Get unexpectedly succeeded with value '{value}'.");
        }
        catch (VaultCorruptException) { /* expected */ }
        catch (Exception ex)
        {
            Assert.Fail($"[{label}] Unexpected exception type: {ex.GetType().Name}: {ex.Message}");
        }
    }

    [Fact]
    public async Task RandomFlipInSecretFile_OnlySurfacesVaultCorrupt()
    {
        // Deterministic: seed RNG, create one vault, perform 200 random
        // byte flips on its single secret, and confirm every Get either
        // throws VaultCorruptException or returns "ok" unchanged (the flip
        // might have landed on whitespace outside a JSON-significant byte,
        // which is fine — we only care that we never crash).
        using (var v = SecretVault.Create(VaultPath, "pw", TestVaultOptions.Fast()))
        {
            await v.SetAsync("a", "ok");
        }

        var path = TestFiles.SecretFile(VaultPath, "a");
        var original = File.ReadAllBytes(path);
        var rng = new Random(Seed: 42);

        for (var iter = 0; iter < 200; iter++)
        {
            var mutated = (byte[])original.Clone();
            var idx = rng.Next(mutated.Length);
            mutated[idx] ^= (byte)(rng.Next(1, 256));
            File.WriteAllBytes(path, mutated);

            using var v = SecretVault.Open(VaultPath);
            await v.UnlockAsync("pw");

            try
            {
                var value = await v.GetAsync("a");
                // Rare but legal: the flip hit whitespace/formatting and
                // decryption still works. Only accept the original plaintext.
                Assert.Equal("ok", value);
            }
            catch (VaultCorruptException) { /* expected */ }
            catch (Exception ex)
            {
                Assert.Fail($"Iteration {iter}, byte {idx}: unexpected exception {ex.GetType().Name}: {ex.Message}");
            }
        }
    }

    private static byte[] RandomBytes(int seed, int length)
    {
        var rng = new Random(seed);
        var bytes = new byte[length];
        rng.NextBytes(bytes);
        return bytes;
    }
}
