using System;

namespace McpGuard.Analyzers;

/// <summary>
/// Detects a data-exfiltration directive in a description using a three-signal pattern: a transmit
/// verb, an external destination, and a sensitivity-or-covert cue together. Requiring all three keeps
/// legitimate "upload to the configured endpoint" tools from being flagged.
/// </summary>
internal static class ExfiltrationCues
{
    private static readonly string[] TransmitVerbs =
    {
        "send",
        "upload",
        "transmit",
        "exfiltrate",
        "forward",
        "email",
    };

    private static readonly string[] ExternalDestinations =
    {
        "http://",
        "https://",
        "ftp://",
        "www.",
        "webhook",
    };

    // The data is sensitive, or the act is covert — either turns "send X to a URL" (often legitimate)
    // into a likely exfiltration directive.
    private static readonly string[] SensitiveOrCovertCues =
    {
        "secret", "credential", "password", "api key", "access token", "auth token",
        "private key", "ssh key", "conversation", "chat history", "message history",
        "system prompt", "environment variable", "session token", "cookie", ".env",
        "without telling", "without the user", "without informing", "do not tell",
        "don't tell", "do not mention", "secretly", "silently", "in the background",
    };

    /// <summary>
    /// Returns the transmit verb when a description directs sensitive (or covert) data to an external
    /// destination. All three signals must be present.
    /// </summary>
    public static bool TryFind(string description, out string verb)
    {
        verb = string.Empty;
        if (string.IsNullOrWhiteSpace(description))
        {
            return false;
        }

        string lowered = description.ToLowerInvariant();

        if (!ContainsAny(lowered, ExternalDestinations))
        {
            return false;
        }

        if (!ContainsAny(lowered, SensitiveOrCovertCues) && !SecretArtifacts.TryFind(lowered, out _))
        {
            return false;
        }

        foreach (string candidate in TransmitVerbs)
        {
            if (ContainsWord(lowered, candidate))
            {
                verb = candidate;
                return true;
            }
        }

        return false;
    }

    private static bool ContainsAny(string text, string[] needles)
    {
        foreach (string needle in needles)
        {
            if (text.IndexOf(needle, StringComparison.Ordinal) >= 0)
            {
                return true;
            }
        }

        return false;
    }

    // Matches the verb stem at a left word boundary so conjugations (send / sends / sending) trip,
    // but the stem appearing mid-word does not anchor a false positive.
    private static bool ContainsWord(string text, string stem)
    {
        int index = 0;
        while ((index = text.IndexOf(stem, index, StringComparison.Ordinal)) >= 0)
        {
            if (index == 0 || !char.IsLetterOrDigit(text[index - 1]))
            {
                return true;
            }

            index += stem.Length;
        }

        return false;
    }
}