# SecretBlast — Design & Threat Model

Status: **v0.1 implemented.** Argon2id KDF + AES-256-GCM records + header
canary + atomic writes + auto-lock all live; 27 tests pass. Remaining
post-v0.1 items are listed at the bottom.

## Goals

1. Cross-platform encrypted secrets vault — the same vault file works on
   Windows, macOS, and Linux.
2. No dependency on OS-provided secret stores (DPAPI, Keychain, libsecret,
   kwallet).
3. Git-trackable: each secret is its own file so diffs, merges, and selective
   sharing are meaningful.
4. Auditable format: versioned, inspectable, documented. An attacker who
   obtains the ciphertext cannot decrypt it without the master password;
   but anyone with the password can open and inspect the structure.
5. Small, focused library. No cloud, no network, no opinions about who the
   caller is.

## Non-goals

* Hardware-token / YubiKey support (possibly later).
* Multi-user vaults with per-user keys (later; v1 is single-password).
* Anything that persists the unlocked key to disk.
* Replacing full secret-management products (Vault, Doppler, Key Vault).
  SecretBlast is for developer / operator convenience, not enterprise
  policy enforcement.

## Threat model

### Defended

* **Local file snooping.** Files on disk or in Git are ciphertext;
  reading them yields nothing without the master password.
* **Shared / multi-user machines.** Unlike DPAPI (Windows-account-bound)
  or Keychain (login-keychain-bound), the vault is portable — any user
  with the password can open it, any user without can't.
* **Git leak.** A vault committed to a public repo is protected by the
  master password + Argon2id work factor. Strong password → real
  time-to-crack.
* **File tampering / swap.** Each ciphertext is authenticated via AES-GCM
  with AAD bound to the vault id and secret name; swapping a file in from
  another vault fails authentication loudly.

### Not defended

* **Memory scraping while unlocked.** The derived key lives in a
  `byte[]` in process memory while the vault is unlocked. Auto-lock
  narrows the window but can't close it.
* **Keylogger / clipboard scraping.** Out of scope.
* **Weak master passwords.** Argon2id buys time; it does not make a
  4-character password safe.
* **Malicious host OS.** If the kernel is compromised, no user-space
  crypto helps.

## Vault layout

```
my-vault/
  vault.json              # header (plaintext): vault-id, kdf params, salt, created
  secrets/
    azure-prod-sql.secret
    azure-dev-kv.secret
```

### `vault.json`

```json
{
  "version": 1,
  "vaultId": "7a1d...guid...",
  "created": "2026-04-24T12:00:00Z",
  "kdf": {
    "algorithm": "argon2id",
    "memoryKiB": 65536,
    "iterations": 3,
    "parallelism": 1,
    "salt": "base64-16-bytes"
  }
}
```

The salt and KDF parameters are plaintext. That is fine: the salt is meant
to be known; parameters are meant to be inspectable and upgradable.

### `*.secret` records

```json
{
  "version": 1,
  "algorithm": "aes-256-gcm",
  "nonce":      "base64-12-bytes",
  "ciphertext": "base64",
  "tag":        "base64-16-bytes",
  "updatedUtc": "2026-04-24T12:34:56Z"
}
```

Writes are atomic (write to `*.secret.tmp`, then rename).

### Filename convention — decision log

v1 stores the secret **name as the filename** (plaintext). Trade-off:

* + Diffs, Git history, and manual inspection are intuitive.
* + Selective sharing = copying one file.
* − The set of secret *names* is visible to anyone with filesystem access.
  The values are not.

This is the chosen trade-off. If name-privacy is ever required, that's
a separate feature (encrypted index file) and a format version bump.

## Crypto

* **KDF**: Argon2id via `Konscious.Security.Cryptography.Argon2`.
  Defaults: `m=65536 KiB, t=3, p=1`. Re-benchmark on target hardware
  before 1.0. Parameters live in `vault.json` → upgradable per-vault.
* **Symmetric**: AES-256-GCM (`System.Security.Cryptography.AesGcm`).
  Fresh 12-byte nonce per write. 16-byte tag. Re-encrypting always
  writes a new nonce, which is safe because a secret file is rewritten
  in full on every update.
* **AAD** (Additional Authenticated Data): `vaultId || secretName`.
  Binds a ciphertext to its slot. Swapping an `azure-prod-sql.secret`
  file in from another vault fails decryption.
* **Versioning**: a `version` byte / field in every on-disk record so
  algorithms can rotate without a flag day. Reading an older version
  can lazy-migrate on next write.

### Why not {...}

* **PBKDF2** — memory-hard KDFs (Argon2id, scrypt) are the current
  best practice for password-derived keys.
* **AES-CBC + HMAC** — AES-GCM does the same thing in one primitive
  and is what BCL exposes cleanly. Less to get wrong.
* **Derive per-secret keys** — unnecessary for the threat model and
  complicates key rotation. One vault key, random nonces per write.
* **Custom crypto primitives** — absolutely not.

## Unlock model

* **Unlock per session.** Master password prompt on first access;
  derived key cached in process memory until lock.
* **Auto-lock.** Configurable idle timeout; default **15 minutes**.
  Also lock on `Dispose`.
* **No persistence of the unlocked key.** Not to disk, not to another
  process, not to the OS keychain.
* **Wiping.** `CryptographicOperations.ZeroMemory(key)` on lock. This
  is best-effort — the JIT, GC, and paging can all defeat it — but it's
  the right thing to do and costs nothing.

## Public API (v1)

```csharp
namespace SecretBlast;

public interface ISecretVault : IDisposable
{
    bool IsLocked { get; }

    Task UnlockAsync(string masterPassword, CancellationToken ct = default);
    void Lock();

    Task<string>                GetAsync(string name, CancellationToken ct = default);
    Task                        SetAsync(string name, string value, CancellationToken ct = default);
    Task                        DeleteAsync(string name, CancellationToken ct = default);
    Task<IReadOnlyList<string>> ListAsync(CancellationToken ct = default);

    event EventHandler? Locked;
}

public sealed class VaultOptions
{
    public TimeSpan         AutoLockIdle { get; init; } = TimeSpan.FromMinutes(15);
    public Argon2Parameters Kdf          { get; init; } = Argon2Parameters.Default;
}

public sealed record Argon2Parameters(int MemoryKiB, int Iterations, int Parallelism)
{
    public static Argon2Parameters Default { get; } = new(65536, 3, 1);
}

public static class SecretVault
{
    public static ISecretVault Create(string path, string masterPassword, VaultOptions? options = null);
    public static ISecretVault Open(string path, VaultOptions? options = null);
}
```

Exceptions:

* `SecretBlastException` — base type.
* `VaultLockedException` — any data op on a locked vault.
* `InvalidMasterPasswordException` — decryption of the vault header fails.
* `SecretNotFoundException` — `GetAsync` / `DeleteAsync` on an unknown name.
* `VaultAlreadyExistsException` — `Create` on a non-empty path.

## Integration notes

### TaskBlaster

* Registered as a singleton `ISecretVault` in the DI container.
* First secret access in a session triggers the `IPromptService`
  master-password dialog.
* Config adds a `VaultFolder` setting (single vault in v1).

### AzureBlast

AzureBlast remains **pure** — it does not reference SecretBlast.
Named-connection resolution goes via a caller-supplied delegate:

```csharp
Func<string, CancellationToken, Task<string>> secretResolver
```

TaskBlaster is the thing that adapts `ISecretVault.GetAsync` into that
delegate. AzureBlast never depends on crypto code.

## Decisions taken in v0.1

* **Canary format.** Header contains an AES-GCM record encrypting the
  fixed string `canary-v1` with AAD = `"SecretBlast" || vaultId || "canary"`.
  A wrong password fails the GCM tag check → `InvalidMasterPasswordException`.
* **`Create` over non-empty directory.** Allowed as long as no `vault.json`
  exists. We do not inspect other files in the directory.
* **`Create` over existing vault.** Throws `VaultAlreadyExistsException`.
* **`Open` with no `vault.json`.** Throws `VaultNotFoundException` eagerly,
  so bad paths surface before the unlock dialog.
* **`UnlockAsync` on an already-unlocked vault.** No-op. Does not re-derive,
  does not validate the supplied password. Rationale: callers who hold the
  vault reference have already proven the password once.
* **Auto-lock.** `System.Threading.Timer` reset on every op. Fires `Lock()`
  on elapse. `TimeSpan.Zero` / `Timeout.InfiniteTimeSpan` disables it.
* **Cancellation during Argon2id.** The `CancellationToken` accepted by
  `UnlockAsync` cancels the *wait* but not the in-flight derivation —
  Konscious does not expose a cancellable primitive. Acceptable for v0.1
  given derivation takes a few hundred ms at default parameters.
* **Key zeroing on lock.** `CryptographicOperations.ZeroMemory(_key)`.
  Best-effort — GC/JIT/paging can still leave copies — but free and correct.

## Open items (post-v0.1)

* Benchmark Argon2id defaults on typical hardware; tune.
* KDF / algorithm migration: a vault created at `version: 1` should be
  readable by a future `version: 2` without a manual export/import.
* Concurrent writers (multiple processes on the same vault directory).
  Today: no cross-process lock; last writer wins for a given secret file.
* CLI (`secretblast unlock | get | set | list`)?
* `SecretBlast.Extensions.DependencyInjection` companion package with
  `AddSecretBlast(path)` helper?
* Optional encrypted-names mode (format version bump) if ever needed.
