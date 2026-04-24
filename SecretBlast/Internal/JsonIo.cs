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
    /// Atomic write: serialize to <paramref name="path"/>.tmp, flush, and rename
    /// over the target. A crash between the tmp write and the rename leaves the
    /// original file (if any) intact.
    /// </summary>
    internal static void WriteAtomic<T>(string path, T value)
    {
        var dir = Path.GetDirectoryName(path);
        if (!string.IsNullOrEmpty(dir)) Directory.CreateDirectory(dir);

        var tmp = path + ".tmp";
        var json = JsonSerializer.Serialize(value, Options);
        File.WriteAllText(tmp, json);
        File.Move(tmp, path, overwrite: true);
    }
}
