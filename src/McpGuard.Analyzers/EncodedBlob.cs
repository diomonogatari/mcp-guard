using System;
using System.Text;

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

    /// <summary>
    /// Attempts to decode a blob to readable text — base64 first, then hex — so a secret reference or
    /// exfil sink hidden inside it can be re-scanned (MCPG003/MCPG004). Returns false when neither decoding
    /// yields text (a hash or random token decodes to control-char gibberish that no rule matches). Hex is
    /// tried because hex digits are a subset of the base64 alphabet, so a hex-encoded payload would
    /// otherwise pass detection but fail to decode.
    /// </summary>
    public static bool TryDecode(string blob, out string decoded)
    {
        decoded = string.Empty;
        if (string.IsNullOrEmpty(blob))
        {
            return false;
        }

        if (TryBase64(blob, out string fromBase64) && IsMostlyPrintable(fromBase64))
        {
            decoded = fromBase64;
            return true;
        }

        if (TryHex(blob, out string fromHex) && IsMostlyPrintable(fromHex))
        {
            decoded = fromHex;
            return true;
        }

        return false;
    }

    private static bool TryBase64(string blob, out string text)
    {
        text = string.Empty;
        string normalized = blob.Replace("=", string.Empty);
        int remainder = normalized.Length % 4;
        if (remainder == 1)
        {
            return false; // never a valid base64 length
        }

        if (remainder != 0)
        {
            normalized += new string('=', 4 - remainder);
        }

        try
        {
            text = Encoding.UTF8.GetString(Convert.FromBase64String(normalized));
            return true;
        }
        catch (FormatException)
        {
            return false;
        }
    }

    private static bool TryHex(string blob, out string text)
    {
        text = string.Empty;
        if (blob.Length < 2 || blob.Length % 2 != 0)
        {
            return false;
        }

        var bytes = new byte[blob.Length / 2];
        for (int i = 0; i < bytes.Length; i++)
        {
            int hi = HexValue(blob[2 * i]);
            int lo = HexValue(blob[(2 * i) + 1]);
            if (hi < 0 || lo < 0)
            {
                return false;
            }

            bytes[i] = (byte)((hi << 4) | lo);
        }

        text = Encoding.UTF8.GetString(bytes);
        return true;
    }

    private static int HexValue(char c) => c switch
    {
        >= '0' and <= '9' => c - '0',
        >= 'a' and <= 'f' => c - 'a' + 10,
        >= 'A' and <= 'F' => c - 'A' + 10,
        _ => -1,
    };

    private static bool IsMostlyPrintable(string text)
    {
        if (text.Length == 0)
        {
            return false;
        }

        int printable = 0;
        foreach (char c in text)
        {
            if (c is '\t' or '\n' or '\r' || (c >= ' ' && c <= '~'))
            {
                printable++;
            }
        }

        return printable >= text.Length * 0.85;
    }
}