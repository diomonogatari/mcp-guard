using System.Globalization;
using System.Text;

namespace McpGuard.Analyzers;

/// <summary>
/// Detects hidden or smuggled content in description text and describes what it found. It recognizes
/// (a) Unicode-tag hidden text — and decodes the ASCII it carries into the message, (b) runs of
/// variation selectors used for byte-smuggling, and (c) other invisible format / control characters.
/// ZWJ / ZWNJ (legitimate in emoji and Indic scripts) and ESC (owned by the ANSI rule, MCPG005) are
/// excluded so the rule stays precise.
/// </summary>
internal static class HiddenCharacters
{
    /// <summary>
    /// Returns a human-readable description of the first hidden content in <paramref name="text"/>, or
    /// <see langword="false"/> if the text is clean.
    /// </summary>
    public static bool TryFind(string text, out string detail)
    {
        detail = string.Empty;

        for (int i = 0; i < text.Length; i++)
        {
            int codePoint = CodePointAt(text, i, out int width);

            // (a) Unicode tag block — decode the hidden text it carries.
            if (IsTagCharacter(codePoint))
            {
                detail = DescribeTagRun(text, i);
                return true;
            }

            // (b) A variation selector is legitimate singly (emoji); a run is byte-smuggling.
            if (IsVariationSelector(codePoint))
            {
                if (VariationSelectorRunLength(text, i) >= 2)
                {
                    detail = "a run of Unicode variation selectors (possible byte-smuggling)";
                    return true;
                }

                i += width - 1;
                continue;
            }

            // (c) Other invisibles, excluding legitimate joiners and ESC.
            if (IsHidden(codePoint))
            {
                detail = "a hidden or non-printable character (U+" + codePoint.ToString("X4") + ")";
                return true;
            }

            i += width - 1;
        }

        return false;
    }

    private static int CodePointAt(string text, int index, out int width)
    {
        char c = text[index];
        if (char.IsHighSurrogate(c) && index + 1 < text.Length && char.IsLowSurrogate(text[index + 1]))
        {
            width = 2;
            return char.ConvertToUtf32(c, text[index + 1]);
        }

        width = 1;
        return c;
    }

    private static bool IsHidden(int codePoint)
    {
        // ZWNJ / ZWJ are legitimate in emoji ZWJ sequences and Indic scripts, so they are not flagged
        // on their own.
        if (codePoint is 0x200C or 0x200D)
        {
            return false;
        }

        UnicodeCategory category = GetCategory(codePoint);
        if (category == UnicodeCategory.Format)
        {
            return true;
        }

        // Control characters, except ordinary whitespace and ESC (U+001B, owned by MCPG005).
        if (category == UnicodeCategory.Control)
        {
            return codePoint != '\t' && codePoint != '\n' && codePoint != '\r' && codePoint != 0x1B;
        }

        return false;
    }

    private static UnicodeCategory GetCategory(int codePoint)
        => codePoint <= 0xFFFF
            ? CharUnicodeInfo.GetUnicodeCategory((char)codePoint)
            : CharUnicodeInfo.GetUnicodeCategory(char.ConvertFromUtf32(codePoint), 0);

    private static bool IsTagCharacter(int codePoint) => codePoint is >= 0xE0000 and <= 0xE007F;

    private static bool IsVariationSelector(int codePoint)
        => codePoint is (>= 0xFE00 and <= 0xFE0F) or (>= 0xE0100 and <= 0xE01EF);

    private static int VariationSelectorRunLength(string text, int index)
    {
        int count = 0;
        for (int i = index; i < text.Length;)
        {
            int codePoint = CodePointAt(text, i, out int width);
            if (!IsVariationSelector(codePoint))
            {
                break;
            }

            count++;
            i += width;
        }

        return count;
    }

    // Decode a run of Unicode tag characters into the ASCII it hides, e.g. "Ignore previous instructions".
    private static string DescribeTagRun(string text, int index)
    {
        var builder = new StringBuilder();
        for (int i = index; i < text.Length;)
        {
            int codePoint = CodePointAt(text, i, out int width);
            if (!IsTagCharacter(codePoint))
            {
                break;
            }

            // Tag characters U+E0020..U+E007E mirror printable ASCII U+0020..U+007E.
            if (codePoint is >= 0xE0020 and <= 0xE007E)
            {
                builder.Append((char)(codePoint - 0xE0000));
            }

            i += width;
        }

        return builder.Length > 0
            ? "hidden text encoded in Unicode tag characters that reads \"" + builder.ToString() + "\""
            : "a hidden Unicode tag character";
    }
}