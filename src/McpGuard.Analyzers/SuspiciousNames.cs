using System;
using System.Collections.Generic;
using System.Text;

namespace McpGuard.Analyzers;

/// <summary>
/// Recognizes a secret-file reference smuggled into an identifier the model reads (a parameter name or
/// an enum-member name) — the CyberArk full-schema-poisoning pattern, e.g.
/// <c>content_from_reading_ssh_id_rsa</c>. An identifier is high false-positive surface: it legitimately
/// uses artifact-like tokens as documentation (<c>id_rsa_compat_mode</c>, <c>id_rsa_key_format</c>), so a
/// bare artifact substring is not enough. The artifact must co-occur with an access / transfer verb among
/// the identifier's words, which is what turns a documentary name into a directive.
/// </summary>
internal static class SuspiciousNames
{
    // Exfiltration-flavored verbs only. Ambiguous, common-in-benign-names verbs (get, load, access,
    // provide, format) are deliberately excluded to keep precision high.
    private static readonly string[] AccessVerbs =
    {
        "read", "send", "upload", "fetch", "exfiltrate", "exfil", "leak", "dump", "steal",
        "transmit", "forward", "post", "grab", "capture", "copy", "download", "export",
        "transfer", "expose", "smuggle",
    };

    /// <summary>
    /// Returns the secret artifact referenced by <paramref name="identifier"/> when it also reads as a
    /// directive (an access/transfer verb among its words). False for a benign documentary name.
    /// </summary>
    public static bool TryFindSecretDirective(string identifier, out string artifact)
    {
        artifact = string.Empty;
        if (string.IsNullOrEmpty(identifier))
        {
            return false;
        }

        // Check the raw identifier (snake_case: id_rsa) and an underscore-joined tokenized form, so a
        // camelCase name (contentFromReadingIdRsa -> "...id_rsa") — the conventional C# casing — is also
        // covered for the underscore-style artifacts (id_rsa, id_ed25519, ...).
        var words = new List<string>(Tokenize(identifier));
        if (!SecretArtifacts.TryFind(identifier, out artifact)
            && !SecretArtifacts.TryFind(string.Join("_", words), out artifact))
        {
            return false;
        }

        foreach (string word in words)
        {
            foreach (string verb in AccessVerbs)
            {
                if (word.StartsWith(verb, StringComparison.Ordinal))
                {
                    return true;
                }
            }
        }

        artifact = string.Empty;
        return false;
    }

    // Splits an identifier into lower-cased words on non-alphanumeric separators and camelCase humps,
    // so "content_from_reading_ssh_id_rsa" and "contentFromReading" both yield a "reading" token.
    private static IEnumerable<string> Tokenize(string identifier)
    {
        var word = new StringBuilder();
        for (int i = 0; i < identifier.Length; i++)
        {
            char c = identifier[i];
            bool separator = !char.IsLetterOrDigit(c);
            bool camelHump = !separator && i > 0 && char.IsUpper(c)
                && (char.IsLower(identifier[i - 1]) || char.IsDigit(identifier[i - 1]));

            if ((separator || camelHump) && word.Length > 0)
            {
                yield return word.ToString();
                word.Clear();
            }

            if (!separator)
            {
                word.Append(char.ToLowerInvariant(c));
            }
        }

        if (word.Length > 0)
        {
            yield return word.ToString();
        }
    }
}