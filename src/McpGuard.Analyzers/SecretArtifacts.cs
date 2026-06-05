using System;

namespace McpGuard.Analyzers;

/// <summary>
/// Catalog of sensitive credential artifacts — private key files, credential stores, and system
/// password files — that have no legitimate reason to appear in a tool description. A reference to
/// one is a hallmark of a data-exfiltration / tool-poisoning payload.
/// </summary>
internal static class SecretArtifacts
{
    // Matched case-insensitively as a substring. Deliberately specific (exact filenames / paths)
    // rather than generic terms like "password" or "api key", which have legitimate uses and are
    // left to the exfiltration rule's verb+destination gate.
    private static readonly string[] Artifacts =
    {
        "id_rsa",
        "id_ed25519",
        "id_dsa",
        "id_ecdsa",
        "~/.ssh",
        ".aws/credentials",
        ".pgpass",
        ".git-credentials",
        "/etc/shadow",
        "/etc/passwd",
    };

    /// <summary>Returns the first secret artifact referenced in <paramref name="description"/>, if any.</summary>
    public static bool TryFind(string description, out string match)
    {
        match = string.Empty;
        if (string.IsNullOrWhiteSpace(description))
        {
            return false;
        }

        string lowered = description.ToLowerInvariant();
        foreach (string artifact in Artifacts)
        {
            if (lowered.IndexOf(artifact, StringComparison.Ordinal) >= 0)
            {
                match = artifact;
                return true;
            }
        }

        return false;
    }
}