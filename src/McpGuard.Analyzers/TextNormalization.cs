using System.Text;

namespace McpGuard.Analyzers;

/// <summary>
/// Shared text normalization for phrase matching: lower-case and collapse runs of whitespace to single
/// spaces, so phrasing padded or wrapped across lines ("ignore   previous\n instructions") still
/// matches the canonical phrase.
/// </summary>
internal static class TextNormalization
{
    public static string Collapse(string value)
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