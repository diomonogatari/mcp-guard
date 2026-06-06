namespace McpGuard.Analyzers;

/// <summary>
/// Detects whitespace padding for MCPG010 — a long run of spaces/tabs used to push content off-screen
/// so a human reviewer never scrolls to it (visible whitespace, distinct from MCPG002's hidden
/// characters). Newlines break the run, so ordinary multi-line indentation is not flagged.
/// </summary>
internal static class WhitespacePadding
{
    private const int Threshold = 20;

    /// <summary>Returns the offending whitespace run if one is at least <see cref="Threshold"/> long.</summary>
    public static bool TryFind(string description, out string run)
    {
        run = string.Empty;
        if (string.IsNullOrEmpty(description))
        {
            return false;
        }

        int runStart = -1;
        for (int i = 0; i < description.Length; i++)
        {
            if (IsHorizontalWhitespace(description[i]))
            {
                if (runStart < 0)
                {
                    runStart = i;
                }

                if (i - runStart + 1 >= Threshold)
                {
                    int end = i + 1;
                    while (end < description.Length && IsHorizontalWhitespace(description[end]))
                    {
                        end++;
                    }

                    run = description.Substring(runStart, end - runStart);
                    return true;
                }
            }
            else
            {
                runStart = -1;
            }
        }

        return false;
    }

    private static bool IsHorizontalWhitespace(char c) => char.IsWhiteSpace(c) && c != '\n' && c != '\r';
}