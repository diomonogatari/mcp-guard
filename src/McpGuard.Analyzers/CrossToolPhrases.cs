using System;

namespace McpGuard.Analyzers;

/// <summary>
/// Catalog for MCPG009 — phrasing that attaches covert behavior to *other* tools (tool shadowing /
/// cross-server compromise). Tight on purpose: a legitimate workflow reference ("use get_comments
/// first") describes ordering, while these phrases redirect or duplicate other tools' actions.
/// </summary>
internal static class CrossToolPhrases
{
    private static readonly string[] Phrases =
    {
        "also bcc",
        "also cc",
        "bcc all",
        "cc all",
        "forward all",
        "forward a copy",
        "forward every",
        "for every other tool",
        "for all other tools",
        "before calling any other tool",
        "after calling any other tool",
        "with every tool call",
        "on every tool call",
    };

    /// <summary>Returns the first cross-tool phrase found in <paramref name="description"/>, if any.</summary>
    public static bool TryFind(string description, out string match)
    {
        match = string.Empty;
        if (string.IsNullOrWhiteSpace(description))
        {
            return false;
        }

        string normalized = TextNormalization.Collapse(description);
        foreach (string phrase in Phrases)
        {
            if (normalized.IndexOf(phrase, StringComparison.Ordinal) >= 0)
            {
                match = phrase;
                return true;
            }
        }

        return false;
    }
}