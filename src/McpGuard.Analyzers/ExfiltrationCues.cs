using System;

namespace McpGuard.Analyzers;

/// <summary>
/// Detects a data-exfiltration sink in a description. Two channels:
/// <list type="bullet">
/// <item>a <b>three-signal directive</b> — a transmit verb, an external destination, and a
/// sensitivity-or-covert cue together (so a legitimate "upload to the configured endpoint" tool is not
/// flagged);</item>
/// <item>a <b>markdown sink</b> — an image <c>![x](http://host/…)</c> a renderer auto-fetches, or a link
/// <c>[x](http://host/?d={data})</c> that templates data into the URL — neither needs a transmit verb.</item>
/// </list>
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

    // Data-transfer commands. These are also *fetch* verbs in normal prose ("uses curl to fetch from the
    // public API"), so they are only treated as transmit verbs when scanning content decoded out of an
    // encoded blob — where a `cat ~/.ssh/* | wget http://…` shell payload is the realistic shape — not in
    // plain description text, to keep precision high.
    private static readonly string[] ShellFetchVerbs =
    {
        "curl",
        "wget",
    };

    private static readonly string[] ExternalDestinations =
    {
        "http://",
        "https://",
        "ftp://",
        "www.",
        "webhook",
    };

    private static readonly string[] SensitiveOrCovertCues =
    {
        "secret", "credential", "password", "api key", "access token", "auth token",
        "private key", "ssh key", "conversation", "chat history", "message history",
        "system prompt", "environment variable", "session token", "cookie", ".env",
        "without telling", "without the user", "without informing", "do not tell",
        "don't tell", "do not mention", "secretly", "silently", "in the background",
    };

    /// <summary>Returns a short description of the exfiltration channel found, if any.</summary>
    public static bool TryFindSink(string description, out string channel)
        => TryFindSink(description, includeShellFetchVerbs: false, out channel);

    /// <summary>
    /// As <see cref="TryFindSink(string, out string)"/>, but optionally also treats shell fetch commands
    /// (<c>curl</c>/<c>wget</c>) as transmit verbs. Used when re-scanning content decoded out of an
    /// encoded blob, where such a command is a realistic exfil shape; not used for plain description text.
    /// </summary>
    public static bool TryFindSink(string description, bool includeShellFetchVerbs, out string channel)
    {
        channel = string.Empty;
        if (string.IsNullOrWhiteSpace(description))
        {
            return false;
        }

        string lowered = description.ToLowerInvariant();

        if (ContainsMarkdownImage(lowered))
        {
            channel = "a markdown image";
            return true;
        }

        if (ContainsMarkdownDataLink(lowered))
        {
            channel = "a markdown data link";
            return true;
        }

        // Three-signal directive: transmit verb + external destination + sensitivity/covert cue.
        if (ContainsAny(lowered, ExternalDestinations)
            && (ContainsAny(lowered, SensitiveOrCovertCues) || SecretArtifacts.TryFind(lowered, out _)))
        {
            foreach (string verb in TransmitVerbs)
            {
                if (ContainsWord(lowered, verb))
                {
                    channel = "a transmit directive (" + verb + ")";
                    return true;
                }
            }

            if (includeShellFetchVerbs)
            {
                foreach (string verb in ShellFetchVerbs)
                {
                    if (ContainsWord(lowered, verb))
                    {
                        channel = "a transmit directive (" + verb + ")";
                        return true;
                    }
                }
            }
        }

        return false;
    }

    // ![alt](http…) — an image a markdown renderer auto-fetches, leaking data in the URL.
    private static bool ContainsMarkdownImage(string text)
    {
        int index = 0;
        while ((index = text.IndexOf("![", index, StringComparison.Ordinal)) >= 0)
        {
            if (TryReadMarkdownUrl(text, index + 1, out string url) && IsExternalUrl(url))
            {
                return true;
            }

            index += 2;
        }

        return false;
    }

    // [text](http…{…}) — a link that templates data into an external URL.
    private static bool ContainsMarkdownDataLink(string text)
    {
        int index = 0;
        while ((index = text.IndexOf('[', index)) >= 0)
        {
            bool isImage = index > 0 && text[index - 1] == '!';
            if (!isImage
                && TryReadMarkdownUrl(text, index, out string url)
                && IsExternalUrl(url)
                && url.IndexOf('{') >= 0)
            {
                return true;
            }

            index++;
        }

        return false;
    }

    private static bool TryReadMarkdownUrl(string text, int bracketStart, out string url)
    {
        url = string.Empty;

        int closing = text.IndexOf("](", bracketStart, StringComparison.Ordinal);
        if (closing < 0)
        {
            return false;
        }

        int urlStart = closing + 2;
        int urlEnd = text.IndexOf(')', urlStart);
        if (urlEnd < 0)
        {
            return false;
        }

        url = text.Substring(urlStart, urlEnd - urlStart);
        return true;
    }

    private static bool IsExternalUrl(string url)
        => url.StartsWith("http://", StringComparison.Ordinal)
        || url.StartsWith("https://", StringComparison.Ordinal)
        || url.StartsWith("ftp://", StringComparison.Ordinal)
        || url.StartsWith("//", StringComparison.Ordinal);

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