using System;
using System.IO;
using System.Text.Json;
using System.Text.Json.Nodes;

namespace SecretBlast.Tests;

/// <summary>
/// Shared helpers for tests that need to read, mutate, or corrupt the
/// on-disk files of a vault. Keeps the test bodies focused on the
/// scenario they're asserting, not on JSON gymnastics.
/// </summary>
internal static class TestFiles
{
    internal static string VaultJson(string vaultPath) =>
        Path.Combine(vaultPath, "vault.json");

    internal static string SecretFile(string vaultPath, string name) =>
        Path.Combine(vaultPath, "secrets", name + ".secret");

    /// <summary>Read a JSON file as a mutable <see cref="JsonObject"/>.</summary>
    internal static JsonObject ReadObject(string path)
    {
        var json = File.ReadAllText(path);
        var node = JsonNode.Parse(json) ?? throw new InvalidOperationException($"{path} is not JSON.");
        return node.AsObject();
    }

    /// <summary>Write a <see cref="JsonObject"/> back to disk (no atomic rename — tests don't need it).</summary>
    internal static void Write(string path, JsonObject obj)
    {
        File.WriteAllText(path, obj.ToJsonString(new JsonSerializerOptions { WriteIndented = true }));
    }

    /// <summary>
    /// Flip the first byte of the named base64-encoded field of a JSON file.
    /// The decoded length is preserved, so only the authenticator can detect it.
    /// </summary>
    internal static void FlipFirstByteOfBase64Field(string path, string fieldName)
    {
        var obj = ReadObject(path);
        var original = (string)obj[fieldName]!;
        var bytes = Convert.FromBase64String(original);
        bytes[0] ^= 0xFF;
        obj[fieldName] = Convert.ToBase64String(bytes);
        Write(path, obj);
    }

    /// <summary>Replace a JSON field with an arbitrary string value.</summary>
    internal static void SetField(string path, string fieldName, string newValue)
    {
        var obj = ReadObject(path);
        obj[fieldName] = newValue;
        Write(path, obj);
    }

    /// <summary>Replace a JSON field with an arbitrary number.</summary>
    internal static void SetNumberField(string path, string fieldName, int newValue)
    {
        var obj = ReadObject(path);
        obj[fieldName] = newValue;
        Write(path, obj);
    }

    /// <summary>Remove a JSON field.</summary>
    internal static void RemoveField(string path, string fieldName)
    {
        var obj = ReadObject(path);
        obj.Remove(fieldName);
        Write(path, obj);
    }
}
