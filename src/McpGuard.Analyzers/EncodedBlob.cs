namespace McpGuard.Analyzers;

/// <summary>
/// Detects an encoded payload blob for MCPG011 — a long contiguous run of base64 / hex characters
/// (40+, containing at least one digit). This is an obfuscation channel for a hidden payload. It is
/// higher false-positive risk than the other rules (a hash, a long token), so MCPG011 is Info-level.
/// URLs and paths do not trip it: <c>:</c>, <c>.</c>, and <c>?</c> are not base64 characters and break
/// the run.
/// </summary>
internal static class EncodedBlob
{
    private const int Threshold = 40;

    /// <summary>Returns the first qualifying base64/hex blob in <paramref name="description"/>, if any.</summary>
    public static bool TryFind(string description, out string blob)
    {
        blob = string.Empty;
        if (string.IsNullOrEmpty(description))
        {
            return false;
        }

        int runStart = -1;
        bool hasDigit = false;
        for (int i = 0; i <= description.Length; i++)
        {
            bool isBase64 = i < description.Length && IsBase64Char(description[i]);
            if (isBase64)
            {
                if (runStart < 0)
                {
                    runStart = i;
                    hasDigit = false;
                }

                if (description[i] >= '0' && description[i] <= '9')
                {
                    hasDigit = true;
                }
            }
            else
            {
                if (runStart >= 0)
                {
                    int length = i - runStart;
                    if (length >= Threshold && hasDigit)
                    {
                        blob = description.Substring(runStart, length);
                        return true;
                    }
                }

                runStart = -1;
            }
        }

        return false;
    }

    private static bool IsBase64Char(char c)
        => (c is >= 'A' and <= 'Z') || (c is >= 'a' and <= 'z') || (c is >= '0' and <= '9') || c is '+' or '/' or '=';
}