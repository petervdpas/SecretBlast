# SecretBlast 🔐

**SecretBlast** is a cross-platform encrypted secrets vault for .NET.

It deliberately **does not** use OS-provided secret stores (DPAPI / Keychain /
libsecret / kwallet). The vault is a plain directory of files on disk, encrypted
with a master password, portable between machines, and safe to track in Git.

## Why not the OS keychain?

Each has real limitations:

* **Portability** — DPAPI secrets don't leave a Windows account. Keychain items
  don't leave a macOS user. A SecretBlast vault is `rsync`-able.
* **Shared machines** — DPAPI / Keychain bind to the OS account. SecretBlast
  binds to a password, so any user on any machine with the right password can
  open the vault and no one else can.
* **Auditability** — opaque OS blobs vs. an inspectable ciphertext file format
  with a versioned header.
* **Team sharing** — a Git-tracked vault directory lets a team share
  environment secrets without a central secrets service.

## Status

🚧 **Stub.** The API surface is defined; crypto paths throw
`NotImplementedException`. See [`DESIGN.md`](DESIGN.md) for the full design and
threat model.

## Install

```bash
dotnet add package SecretBlast
```

## Usage (target API)

```csharp
using SecretBlast;

var vault = SecretVault.Open("/path/to/my-vault");
await vault.UnlockAsync("correct horse battery staple");

await vault.SetAsync("azure-prod-sql", "Server=...;");
var conn = await vault.GetAsync("azure-prod-sql");

vault.Lock();
```

## License

MIT — see [LICENSE.txt](assets/LICENSE.txt).
