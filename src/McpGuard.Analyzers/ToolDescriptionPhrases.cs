using System;
using System.Text;

namespace McpGuard.Analyzers;

/// <summary>
/// The seed phrase catalog for MCPG001. Deliberately small and high-confidence — precision beats
/// recall for a security analyzer, and the corpus (the stash-mcp dogfood loop plus the poisoned
/// fixtures) drives which phrases earn their place here.
/// </summary>
internal static class ToolDescriptionPhrases
{
    // Matched case-insensitively against whitespace-normalized description text. Every entry is a
    // phrase that has no legitimate reason to appear in a field whose only job is to describe a tool.
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

    /// <summary>
    /// Returns the first injection phrase found in <paramref name="description"/>, or <see langword="false"/>
    /// if none is present. Matching is whitespace-tolerant so phrasing split across lines still trips.
    /// </summary>
    public static bool TryFindInjectionPhrase(string description, out string match)
    {
        match = string.Empty;
        if (string.IsNullOrWhiteSpace(description))
        {
            return false;
        }

        string normalized = Normalize(description);
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

    // Lower-case and collapse runs of whitespace to single spaces so that descriptions which pad or
    // wrap a payload ("ignore   previous\n  instructions") still match the canonical phrase.
    private static string Normalize(string value)
    {
        var builder = new StringBuilder(value.Length);
        bool previousWasSpace = false;
        foreach (char ch in value)
        {
            if (char.IsWhiteSpace(ch))
            {
                if (!previousWasSpace && builder.Length > 0)
                {
                    builder.Append(' ');
                }

                previousWasSpace = true;
            }
            else
            {
                builder.Append(char.ToLowerInvariant(ch));
                previousWasSpace = false;
            }
        }

        if (builder.Length > 0 && builder[builder.Length - 1] == ' ')
        {
            builder.Length--;
        }

        return builder.ToString();
    }
}