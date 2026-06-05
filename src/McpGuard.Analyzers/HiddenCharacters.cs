using System.Globalization;

namespace McpGuard.Analyzers;

/// <summary>
/// Detects hidden or non-printable characters in description text — zero-width spaces, bidirectional
/// control codes, byte-order marks, Unicode "tag" characters, and stray control codes. None of these
/// belong in a tool description; all are known carriers for instructions a human reviewer cannot see.
/// </summary>
internal static class HiddenCharacters
{
    /// <summary>
    /// Returns the first hidden / non-printable code point in <paramref name="text"/>, or
    /// <see langword="false"/> if the text is clean. Surrogate pairs are decoded so tag characters
    /// (U+E0000–U+E007F) are caught.
    /// </summary>
    public static bool TryFind(string text, out int codePoint)
    {
        codePoint = 0;
        for (int i = 0; i < text.Length; i++)
        {
            char current = text[i];
            int candidate;
            UnicodeCategory category;

            if (char.IsHighSurrogate(current) && i + 1 < text.Length && char.IsLowSurrogate(text[i + 1]))
            {
                candidate = char.ConvertToUtf32(current, text[i + 1]);
                category = CharUnicodeInfo.GetUnicodeCategory(text, i);
                i++;
            }
            else
            {
                candidate = current;
                category = CharUnicodeInfo.GetUnicodeCategory(current);
            }

            if (IsHidden(candidate, category))
            {
                codePoint = candidate;
                return true;
            }
        }

        return false;
    }

    private static bool IsHidden(int codePoint, UnicodeCategory category)
    {
        // Format characters: zero-width spaces/joiners, bidi overrides/isolates, BOM, soft hyphen,
        // word joiner, and the Unicode tag block (U+E0000–U+E007F).
        if (category == UnicodeCategory.Format)
        {
            return true;
        }

        // Control characters, except the ordinary whitespace that legitimately appears in prose.
        if (category == UnicodeCategory.Control)
        {
            return codePoint != '\t' && codePoint != '\n' && codePoint != '\r';
        }

        return false;
    }
}