using System;
using System.IO;
using System.Text.Json;

namespace SecretBlast.Internal;

/// <summary>
/// Shared System.Text.Json options and atomic write helper for on-disk vault files.
/// </summary>
internal static class JsonIo
{
    internal static readonly JsonSerializerOptions Options = new()
    {
        WriteIndented = true,
    };

    internal static T Read<T>(string path) where T : class
    {
        var json = File.ReadAllText(path);
        try
        {
            return JsonSerializer.Deserialize<T>(json, Options)
                ?? throw new VaultCorruptException($"File '{path}' deserialized to null.");
        }
        catch (JsonException ex)
        {
            throw new VaultCorruptException($"File '{path}' is not valid JSON: {ex.Message}", ex);
        }
    }

    /// <summary>
    /// Atomic write: serialize to a per-call temp file, then rename over the
    /// target. A crash between the temp write and the rename leaves the
    /// original (if any) intact. The temp name embeds a GUID so concurrent
    /// writers to the same path don't collide on the temp file itself
    /// (rename over the final path is still the linearization point; last
    /// writer wins).
    /// </summary>
    internal static void WriteAtomic<T>(string path, T value)
    {
        var dir = Path.GetDirectoryName(path);
        if (!string.IsNullOrEmpty(dir)) Directory.CreateDirectory(dir);

        var tmp = path + "." + Guid.NewGuid().ToString("N") + ".tmp";
        var json = JsonSerializer.Serialize(value, Options);
        try
        {
            File.WriteAllText(tmp, json);
            File.Move(tmp, path, overwrite: true);
        }
        catch
        {
            try { File.Delete(tmp); } catch { /* best-effort cleanup */ }
            throw;
        }
    }
}
