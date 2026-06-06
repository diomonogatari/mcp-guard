using System;

namespace McpGuard.Analyzers;

/// <summary>
/// Catalog for MCPG006 — phrasing that coerces the model or suppresses other tools. Kept ultra-tight
/// on purpose: every entry has essentially no legitimate use in a tool description, so normal workflow
/// hints ("call list_projects first", "always returns UTC") are not flagged.
/// </summary>
internal static class ManipulationPhrases
{
    private static readonly string[] Phrases =
    {
        "do not use other tools",
        "do not use any other tool",
        "do not use any other tools",
        "instead of other tools",
        "you must comply",
        "you have no choice",
        "you must obey",
        "you are not allowed to refuse",
        "i am the developer",
        "i am authorized to",
        "as an ai, you must",
        "as an ai assistant, you must",
        "as the assistant, you must",
    };

    /// <summary>Returns the first manipulative phrase found in <paramref name="description"/>, if any.</summary>
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