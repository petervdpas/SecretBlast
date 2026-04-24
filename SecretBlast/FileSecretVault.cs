using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using SecretBlast.Interfaces;
using SecretBlast.Internal;

namespace SecretBlast;

/// <summary>
/// On-disk <see cref="ISecretVault"/>. One directory per vault, one file per
/// secret, one plaintext header in <c>vault.json</c>. All crypto runs in-process;
/// no OS keychain is touched.
/// </summary>
internal sealed class FileSecretVault : ISecretVault
{
    private const string HeaderFileName = "vault.json";
    private const string SecretsDirName = "secrets";
    private const string SecretExtension = ".secret";

    private readonly string _vaultPath;
    private readonly VaultOptions _options;
    private readonly VaultHeader _header;
    private readonly object _stateLock = new();

    private byte[]? _key;
    private Timer? _autoLockTimer;
    private bool _disposed;

    public bool IsLocked
    {
        get { lock (_stateLock) return _key is null; }
    }

    public event EventHandler? Locked;

    private FileSecretVault(string vaultPath, VaultOptions options, VaultHeader header, byte[]? initialKey)
    {
        _vaultPath = vaultPath;
        _options = options;
        _header = header;
        _key = initialKey;
        if (initialKey is not null) StartOrResetAutoLock();
    }

    // =============================================================
    // Create / Open
    // =============================================================

    internal static ISecretVault Create(string path, string masterPassword, VaultOptions options)
    {
        if (string.IsNullOrWhiteSpace(path)) throw new ArgumentException("Path is required.", nameof(path));
        if (string.IsNullOrEmpty(masterPassword)) throw new ArgumentException("Master password is required.", nameof(masterPassword));

        Directory.CreateDirectory(path);
        var headerPath = Path.Combine(path, HeaderFileName);
        if (File.Exists(headerPath)) throw new VaultAlreadyExistsException(path);

        var vaultId = Guid.NewGuid().ToString("N");
        var salt = RandomNumberGenerator.GetBytes(Argon2Kdf.SaltLength);

        // Derive the key synchronously during Create — the caller wants a ready vault.
        var key = Argon2Kdf
            .DeriveAsync(masterPassword, salt, options.Kdf, CancellationToken.None)
            .GetAwaiter().GetResult();

        var header = new VaultHeader
        {
            Version = 1,
            VaultId = vaultId,
            CreatedUtc = DateTime.UtcNow,
            Kdf = new VaultHeader.KdfSection
            {
                Algorithm = "argon2id",
                MemoryKiB = options.Kdf.MemoryKiB,
                Iterations = options.Kdf.Iterations,
                Parallelism = options.Kdf.Parallelism,
                Salt = Convert.ToBase64String(salt),
            },
            Canary = VaultCrypto.BuildCanary(key, vaultId),
        };

        JsonIo.WriteAtomic(headerPath, header);
        Directory.CreateDirectory(Path.Combine(path, SecretsDirName));

        return new FileSecretVault(path, options, header, initialKey: key);
    }

    internal static ISecretVault Open(string path, VaultOptions options)
    {
        if (string.IsNullOrWhiteSpace(path)) throw new ArgumentException("Path is required.", nameof(path));
        var headerPath = Path.Combine(path, HeaderFileName);
        if (!File.Exists(headerPath)) throw new VaultNotFoundException(path);

        var header = JsonIo.Read<VaultHeader>(headerPath);
        ValidateHeader(header, headerPath);

        return new FileSecretVault(path, options, header, initialKey: null);
    }

    private static void ValidateHeader(VaultHeader header, string path)
    {
        if (header.Version != 1)
            throw new VaultCorruptException($"Unsupported vault version {header.Version} at '{path}'.");
        if (string.IsNullOrEmpty(header.VaultId))
            throw new VaultCorruptException($"Vault header at '{path}' has no vaultId.");
        if (!string.Equals(header.Kdf.Algorithm, "argon2id", StringComparison.OrdinalIgnoreCase))
            throw new VaultCorruptException($"Unsupported KDF algorithm '{header.Kdf.Algorithm}' at '{path}'.");
        if (string.IsNullOrEmpty(header.Kdf.Salt))
            throw new VaultCorruptException($"Vault header at '{path}' has no KDF salt.");
    }

    // =============================================================
    // Unlock / Lock
    // =============================================================

    public async Task UnlockAsync(string masterPassword, CancellationToken ct = default)
    {
        ThrowIfDisposed();
        if (!IsLocked) return;
        if (string.IsNullOrEmpty(masterPassword))
            throw new ArgumentException("Master password is required.", nameof(masterPassword));

        byte[] salt;
        try
        {
            salt = Convert.FromBase64String(_header.Kdf.Salt);
        }
        catch (FormatException ex)
        {
            throw new VaultCorruptException("Vault header salt is not valid base64.", ex);
        }

        var parameters = new Argon2Parameters(
            _header.Kdf.MemoryKiB, _header.Kdf.Iterations, _header.Kdf.Parallelism);

        var derived = await Argon2Kdf.DeriveAsync(masterPassword, salt, parameters, ct).ConfigureAwait(false);

        if (!VaultCrypto.TryVerifyCanary(derived, _header.VaultId, _header.Canary))
        {
            CryptographicOperations.ZeroMemory(derived);
            throw new InvalidMasterPasswordException();
        }

        lock (_stateLock)
        {
            if (_disposed)
            {
                CryptographicOperations.ZeroMemory(derived);
                throw new ObjectDisposedException(nameof(FileSecretVault));
            }
            // If another thread raced us to unlock, drop ours and keep theirs.
            if (_key is not null)
            {
                CryptographicOperations.ZeroMemory(derived);
                StartOrResetAutoLock();
                return;
            }
            _key = derived;
            StartOrResetAutoLock();
        }
    }

    public void Lock()
    {
        byte[]? toZero;
        lock (_stateLock)
        {
            if (_key is null) return;
            toZero = _key;
            _key = null;
            _autoLockTimer?.Dispose();
            _autoLockTimer = null;
        }
        CryptographicOperations.ZeroMemory(toZero);
        Locked?.Invoke(this, EventArgs.Empty);
    }

    private void StartOrResetAutoLock()
    {
        // Caller holds _stateLock.
        var idle = _options.AutoLockIdle;
        if (idle <= TimeSpan.Zero || idle == Timeout.InfiniteTimeSpan)
        {
            _autoLockTimer?.Dispose();
            _autoLockTimer = null;
            return;
        }

        if (_autoLockTimer is null)
        {
            _autoLockTimer = new Timer(OnAutoLockElapsed, state: null, dueTime: idle, period: Timeout.InfiniteTimeSpan);
        }
        else
        {
            _autoLockTimer.Change(dueTime: idle, period: Timeout.InfiniteTimeSpan);
        }
    }

    private void OnAutoLockElapsed(object? _) => Lock();

    // =============================================================
    // Secret operations
    // =============================================================

    public async Task<string> GetAsync(string name, CancellationToken ct = default)
    {
        ValidateName(name);
        var (key, vaultId) = TakeKeySnapshotAndResetTimer();

        var recordPath = GetRecordPath(name);
        if (!File.Exists(recordPath)) throw new SecretNotFoundException(name);

        var record = await Task.Run(() => JsonIo.Read<SecretRecord>(recordPath), ct).ConfigureAwait(false);
        var (nonce, cipher, tag) = DecodeRecord(record, recordPath);

        byte[] plaintext;
        try
        {
            plaintext = VaultCrypto.Decrypt(key, vaultId, name, nonce, cipher, tag);
        }
        catch (AuthenticationTagMismatchException ex)
        {
            throw new VaultCorruptException($"Secret '{name}' failed authentication — file tampered or from another vault.", ex);
        }

        try { return Encoding.UTF8.GetString(plaintext); }
        finally { CryptographicOperations.ZeroMemory(plaintext); }
    }

    public async Task SetAsync(string name, string value, CancellationToken ct = default)
    {
        ValidateName(name);
        if (value is null) throw new ArgumentNullException(nameof(value));
        var (key, vaultId) = TakeKeySnapshotAndResetTimer();

        var plaintext = Encoding.UTF8.GetBytes(value);
        SecretRecord record;
        try
        {
            var (nonce, cipher, tag) = VaultCrypto.Encrypt(key, vaultId, name, plaintext);
            record = new SecretRecord
            {
                Version = 1,
                Algorithm = "aes-256-gcm",
                Nonce = Convert.ToBase64String(nonce),
                Ciphertext = Convert.ToBase64String(cipher),
                Tag = Convert.ToBase64String(tag),
                UpdatedUtc = DateTime.UtcNow,
            };
        }
        finally
        {
            CryptographicOperations.ZeroMemory(plaintext);
        }

        var recordPath = GetRecordPath(name);
        await Task.Run(() => JsonIo.WriteAtomic(recordPath, record), ct).ConfigureAwait(false);
    }

    public Task DeleteAsync(string name, CancellationToken ct = default)
    {
        ValidateName(name);
        _ = TakeKeySnapshotAndResetTimer(); // enforce unlock + reset idle timer

        var recordPath = GetRecordPath(name);
        if (!File.Exists(recordPath)) throw new SecretNotFoundException(name);

        File.Delete(recordPath);
        return Task.CompletedTask;
    }

    public Task<IReadOnlyList<string>> ListAsync(CancellationToken ct = default)
    {
        ThrowIfDisposed();
        var secretsDir = Path.Combine(_vaultPath, SecretsDirName);
        if (!Directory.Exists(secretsDir))
            return Task.FromResult<IReadOnlyList<string>>(Array.Empty<string>());

        var names = Directory
            .EnumerateFiles(secretsDir, "*" + SecretExtension)
            .Select(Path.GetFileNameWithoutExtension)
            .Where(n => !string.IsNullOrEmpty(n))
            .Select(n => n!)
            .ToArray();
        return Task.FromResult<IReadOnlyList<string>>(names);
    }

    // =============================================================
    // Helpers
    // =============================================================

    private (byte[] key, string vaultId) TakeKeySnapshotAndResetTimer()
    {
        lock (_stateLock)
        {
            ThrowIfDisposedLocked();
            if (_key is null) throw new VaultLockedException();
            StartOrResetAutoLock();
            return (_key, _header.VaultId);
        }
    }

    private string GetRecordPath(string name) =>
        Path.Combine(_vaultPath, SecretsDirName, name + SecretExtension);

    private static (byte[] nonce, byte[] cipher, byte[] tag) DecodeRecord(SecretRecord record, string path)
    {
        try
        {
            return (
                Convert.FromBase64String(record.Nonce),
                Convert.FromBase64String(record.Ciphertext),
                Convert.FromBase64String(record.Tag));
        }
        catch (FormatException ex)
        {
            throw new VaultCorruptException($"Secret record at '{path}' contains invalid base64.", ex);
        }
    }

    private static void ValidateName(string name)
    {
        if (string.IsNullOrWhiteSpace(name))
            throw new ArgumentException("Secret name is required.", nameof(name));
        foreach (var ch in name)
        {
            if (char.IsLetterOrDigit(ch)) continue;
            if (ch == '-' || ch == '_' || ch == '.') continue;
            throw new ArgumentException(
                $"Secret name '{name}' contains invalid character '{ch}'. Allowed: letters, digits, '-', '_', '.'.",
                nameof(name));
        }
    }

    // =============================================================
    // Dispose / guards
    // =============================================================

    public void Dispose()
    {
        lock (_stateLock)
        {
            if (_disposed) return;
            _disposed = true;
        }
        Lock();
    }

    private void ThrowIfDisposed()
    {
        lock (_stateLock) ThrowIfDisposedLocked();
    }

    private void ThrowIfDisposedLocked()
    {
        if (_disposed) throw new ObjectDisposedException(nameof(FileSecretVault));
    }
}
