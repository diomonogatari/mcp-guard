using System;

namespace McpGuard.Analyzers;

/// <summary>
/// Detects a description that claims a high-privilege capability — shell/command execution, arbitrary
/// file access, subprocess spawning. Used by MCPG007 together with a benign tool name to flag a
/// capability ⇄ name mismatch.
/// </summary>
internal static class CapabilityClaims
{
    private static readonly string[] DangerousCapabilities =
    {
        "arbitrary command",
        "arbitrary code",
        "arbitrary file",
        "shell command",
        "execute arbitrary",
        "run any command",
        "run arbitrary",
        "read any file",
        "delete any file",
        "any file on the system",
        "system command",
        "subprocess",
        "spawn a shell",
        "os.system",
        "exec(",
    };

    public static bool ClaimsDangerousCapability(string description)
    {
        if (string.IsNullOrWhiteSpace(description))
        {
            return false;
        }

        string normalized = TextNormalization.Collapse(description);
        foreach (string capability in DangerousCapabilities)
        {
            if (normalized.IndexOf(capability, StringComparison.Ordinal) >= 0)
            {
                return true;
            }
        }

        return false;
    }
}