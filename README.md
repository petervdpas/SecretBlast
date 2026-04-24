# SecretBlast 🔐

[![NuGet](https://img.shields.io/nuget/v/SecretBlast.svg)](https://www.nuget.org/packages/SecretBlast)
[![NuGet Downloads](https://img.shields.io/nuget/dt/SecretBlast.svg)](https://www.nuget.org/packages/SecretBlast)
[![License](https://img.shields.io/github/license/petervdpas/SecretBlast.svg)](https://opensource.org/licenses/MIT)

![RoadWarrior](https://raw.githubusercontent.com/petervdpas/SecretBlast/master/assets/icon.png)

**SecretBlast** is a cross-platform **encrypted secrets vault** for .NET.
It deliberately **does not** use OS-provided secret stores (DPAPI / Keychain / libsecret / kwallet).
The vault is a plain directory of files, encrypted with a master password, portable between machines, and safe to track in Git.

---

> ✅ **Status:** v0.1 implemented. Crypto paths are live (Argon2id + AES-256-GCM),
> full round-trip tested. See [DESIGN.md](DESIGN.md) for the format spec and threat model.

---

## ✨ Features

* 🔹 **Cross-platform** — the same vault file works on Windows, macOS, Linux
* 🔹 **No OS keychain** — portable, not bound to any user account
* 🔹 **Git-friendly** — one file per secret, meaningful diffs, selective sharing
* 🔹 **Auditable format** — versioned, inspectable ciphertext records
* 🔹 **Argon2id** password-derived master key, with upgradable work factors
* 🔹 **AES-256-GCM** per-secret encryption with AAD binding
* 🔹 **Auto-lock** on idle; derived key is zeroed from memory on lock / dispose

---

## 📦 Installation

```bash
dotnet add package SecretBlast
```

Or install from the [NuGet Gallery](https://www.nuget.org/packages/SecretBlast).

---

## 🚀 Quick Example (target API)

```csharp
using SecretBlast;

// Create a new vault
using (var vault = SecretVault.Create("/path/to/my-vault", "correct horse battery staple"))
{
    await vault.SetAsync("azure-prod-sql", "Server=...;");
    await vault.SetAsync("github-token",   "ghp_...");
} // auto-locks on Dispose

// Re-open later
using var reopened = SecretVault.Open("/path/to/my-vault");
await reopened.UnlockAsync("correct horse battery staple");

var conn  = await reopened.GetAsync("azure-prod-sql");
var names = await reopened.ListAsync();   // ["azure-prod-sql", "github-token"]
```

---

## 🔐 Why not the OS keychain?

Each OS-native option has real limitations:

* **Portability** — DPAPI secrets don't leave a Windows account.
  Keychain items don't leave a macOS user. A SecretBlast vault is `rsync`-able.
* **Shared machines** — DPAPI / Keychain bind to the OS account.
  SecretBlast binds to a password, so any user on any machine with the right
  password can open the vault and no one else can.
* **Auditability** — opaque OS blobs vs. an inspectable, versioned
  ciphertext file format.
* **Team sharing** — a Git-tracked vault directory lets a team share
  environment secrets without a central secrets service.

---

## 🗂 Vault Layout

```
my-vault/
  vault.json              # header (plaintext): vault-id, kdf params, salt
  secrets/
    azure-prod-sql.secret
    github-token.secret
```

Each `.secret` file is a small JSON record with `version`, `nonce`,
`ciphertext`, `tag`, and `updatedUtc`. Writes are atomic (`*.secret.tmp` → rename).

Secret **names are plaintext** (the filename); secret **values are always ciphertext**.
If hiding the names themselves is required, that's a future feature
(encrypted index file + format version bump).

---

## 🔒 Crypto

* **KDF:** Argon2id — defaults `m=64 MiB, t=3, p=1`. Parameters live in
  `vault.json` so they can be raised per-vault without a format bump.
* **Symmetric:** AES-256-GCM, fresh 12-byte nonce per write, 16-byte tag.
* **AAD:** `vaultId || secretName` — swapping a `*.secret` file in from
  another vault fails authentication loudly.
* **Versioning:** a `version` field in every on-disk record so algorithms
  can rotate without a flag day.

Full threat model (defended / not defended) and format spec in [DESIGN.md](DESIGN.md).

---

## 🧪 Unlock Model

* Master password prompt on first access; derived key cached in process memory.
* Configurable idle auto-lock — default **15 minutes**. Also locks on `Dispose`.
* **No "remember me" to disk.** Not to disk, not to another process, not to the OS keychain.
* `CryptographicOperations.ZeroMemory(key)` on lock — best-effort, but the
  right thing to do.

---

## 📖 API Surface

```csharp
namespace SecretBlast;

public interface ISecretVault : IDisposable
{
    bool IsLocked { get; }

    Task UnlockAsync(string masterPassword, CancellationToken ct = default);
    void Lock();

    Task<string>                GetAsync   (string name, CancellationToken ct = default);
    Task                        SetAsync   (string name, string value, CancellationToken ct = default);
    Task                        DeleteAsync(string name, CancellationToken ct = default);
    Task<IReadOnlyList<string>> ListAsync  (CancellationToken ct = default);

    event EventHandler? Locked;
}

public static class SecretVault
{
    public static ISecretVault Create(string path, string masterPassword, VaultOptions? options = null);
    public static ISecretVault Open  (string path, VaultOptions? options = null);
}
```

Exceptions: `SecretBlastException` (base), `VaultLockedException`,
`InvalidMasterPasswordException`, `SecretNotFoundException`,
`VaultAlreadyExistsException`.

---

## 📦 Why SecretBlast?

* One NuGet, one concern — crypto for secrets, nothing else.
* No OS dependency, no cloud dependency, no network calls.
* Small, auditable surface. No code paths hidden behind platform branches.
* Plays nicely with DI containers; lives happily behind your own interfaces.

---

## 📜 License

[MIT](https://opensource.org/licenses/MIT)
