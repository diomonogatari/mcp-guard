using System;

namespace McpGuard.Analyzers;

/// <summary>
/// Catalog for MCPG008 — fake delivery-format markup used to smuggle instructions: HTML comments,
/// fake system / instruction tags, and chat-template control tokens. None belong in a description.
/// Specific tokens only (not generic <c>&lt;tag&gt;</c>), so comparison operators and genuine XML
/// examples are not flagged.
/// </summary>
internal static class EmbeddedMarkup
{
    private static readonly string[] Markers =
    {
        "<!--",
        "<system>",
        "</system>",
        "<important>",
        "</important>",
        "<instructions>",
        "<assistant>",
        "<|im_start|>",
        "<|im_end|>",
        "<<sys>>",
        "[inst]",
    };

    /// <summary>Returns the first embedded-markup marker found in <paramref name="description"/>, if any.</summary>
    public static bool TryFind(string description, out string match)
    {
        match = string.Empty;
        if (string.IsNullOrWhiteSpace(description))
        {
            return false;
        }

        string lowered = description.ToLowerInvariant();
        foreach (string marker in Markers)
        {
            if (lowered.IndexOf(marker, StringComparison.Ordinal) >= 0)
            {
                match = marker;
                return true;
            }
        }

        return false;
    }
}