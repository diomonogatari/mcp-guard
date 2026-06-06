using System;

namespace McpGuard.Analyzers;

/// <summary>
/// The seed phrase catalog for MCPG001. Deliberately small and high-confidence — precision beats
/// recall for a security analyzer. Matched case-insensitively against whitespace-normalized text.
/// </summary>
internal static class ToolDescriptionPhrases
{
    private static readonly string[] InjectionPhrases =
    {
        "ignore previous instructions",
        "ignore all previous instructions",
        "ignore the above",
        "disregard previous instructions",
        "disregard all previous instructions",
        "disregard the above",
        "do not tell the user",
        "don't tell the user",
        "do not mention this to the user",
        "without telling the user",
        "before answering",
        "before responding",
        "before you answer",
        "system prompt",
    };

    /// <summary>Returns the first injection phrase found in <paramref name="description"/>, if any.</summary>
    public static bool TryFindInjectionPhrase(string description, out string match)
    {
        match = string.Empty;
        if (string.IsNullOrWhiteSpace(description))
        {
            return false;
        }

        string normalized = TextNormalization.Collapse(description);
        foreach (string phrase in InjectionPhrases)
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