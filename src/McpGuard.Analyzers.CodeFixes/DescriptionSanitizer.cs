using System.Globalization;
using System.Text;

namespace McpGuard.Analyzers;

/// <summary>Cleanup transforms for the code fixes — each removes exactly what its rule flagged.</summary>
internal static class DescriptionSanitizer
{
    private const char Escape = (char)0x1B;
    private const char Bell = (char)0x07;
    private const char Backslash = (char)0x5C;

    /// <summary>MCPG002 — remove hidden / non-printable characters (ZWJ / ZWNJ and ESC are kept).</summary>
    public static string RemoveHidden(string text)
    {
        var builder = new StringBuilder(text.Length);
        for (int i = 0; i < text.Length; i++)
        {
            char c = text[i];
            int width = 1;
            int codePoint = c;
            if (char.IsHighSurrogate(c) && i + 1 < text.Length && char.IsLowSurrogate(text[i + 1]))
            {
                codePoint = char.ConvertToUtf32(c, text[i + 1]);
                width = 2;
            }

            if (!IsHidden(codePoint))
            {
                builder.Append(text, i, width);
            }

            i += width - 1;
        }

        return builder.ToString();
    }

    /// <summary>MCPG005 — remove ANSI / terminal escape sequences (ESC plus its CSI/OSC body).</summary>
    public static string RemoveAnsi(string text)
    {
        var builder = new StringBuilder(text.Length);
        int i = 0;
        while (i < text.Length)
        {
            if (text[i] == Escape)
            {
                i = EndOfAnsiSequence(text, i);
            }
            else
            {
                builder.Append(text[i]);
                i++;
            }
        }

        return builder.ToString();
    }

    /// <summary>MCPG010 — collapse each run of horizontal whitespace to a single space.</summary>
    public static string CollapseWhitespacePadding(string text)
    {
        var builder = new StringBuilder(text.Length);
        bool inRun = false;
        foreach (char c in text)
        {
            if (char.IsWhiteSpace(c) && c != '\n' && c != '\r')
            {
                inRun = true;
            }
            else
            {
                if (inRun)
                {
                    builder.Append(' ');
                    inRun = false;
                }

                builder.Append(c);
            }
        }

        if (inRun)
        {
            builder.Append(' ');
        }

        return builder.ToString();
    }

    private static bool IsHidden(int codePoint)
    {
        if (codePoint is 0x200C or 0x200D)
        {
            return false;
        }

        if (codePoint is >= 0xE0000 and <= 0xE007F)
        {
            return true;
        }

        if (codePoint is (>= 0xFE00 and <= 0xFE0F) or (>= 0xE0100 and <= 0xE01EF))
        {
            return true;
        }

        UnicodeCategory category = codePoint <= 0xFFFF
            ? CharUnicodeInfo.GetUnicodeCategory((char)codePoint)
            : CharUnicodeInfo.GetUnicodeCategory(char.ConvertFromUtf32(codePoint), 0);

        if (category == UnicodeCategory.Format)
        {
            return true;
        }

        if (category == UnicodeCategory.Control)
        {
            return codePoint != '\t' && codePoint != '\n' && codePoint != '\r' && codePoint != Escape;
        }

        return false;
    }

    // Returns the index just past the ANSI sequence that starts at the ESC byte at escIndex.
    private static int EndOfAnsiSequence(string text, int escIndex)
    {
        int i = escIndex + 1;
        if (i >= text.Length)
        {
            return i;
        }

        char introducer = text[i];
        if (introducer == '[')
        {
            i++;
            while (i < text.Length && text[i] >= ' ' && text[i] <= '?')
            {
                i++;
            }

            if (i < text.Length && text[i] >= '@' && text[i] <= '~')
            {
                i++;
            }

            return i;
        }

        if (introducer == ']')
        {
            i++;
            while (i < text.Length && text[i] != Bell && !(text[i] == Escape && i + 1 < text.Length && text[i + 1] == Backslash))
            {
                i++;
            }

            if (i < text.Length && text[i] == Bell)
            {
                return i + 1;
            }

            if (i + 1 < text.Length && text[i] == Escape && text[i + 1] == Backslash)
            {
                return i + 2;
            }

            return i;
        }

        return i + 1;
    }
}