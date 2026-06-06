using System.Collections.Immutable;
using System.Text;

namespace McpGuard.Analyzers;

/// <summary>
/// Recognizes tool names that promise a narrow, harmless scope (a math / string / formatting helper).
/// MCPG007 fires when such a tool's description claims a dangerous capability. The name is normalized
/// (lower-cased, non-alphanumerics stripped) so <c>format_date</c>, <c>FormatDate</c>, and
/// <c>formatDate</c> all match.
/// </summary>
internal static class BenignToolNames
{
    private static readonly ImmutableHashSet<string> Benign = ImmutableHashSet.Create(
        "add", "sum", "subtract", "minus", "multiply", "divide", "increment", "decrement",
        "format", "formatdate", "formattime", "parse", "echo", "greet", "hello", "ping",
        "count", "length", "reverse", "uppercase", "lowercase", "capitalize", "concat",
        "concatenate", "trim", "round", "abs", "max", "min", "now", "today", "uuid", "guid",
        "random", "slugify", "wordcount");

    public static bool IsBenign(string toolName) => !string.IsNullOrEmpty(toolName) && Benign.Contains(Normalize(toolName));

    private static string Normalize(string name)
    {
        var builder = new StringBuilder(name.Length);
        foreach (char c in name)
        {
            if (char.IsLetterOrDigit(c))
            {
                builder.Append(char.ToLowerInvariant(c));
            }
        }

        return builder.ToString();
    }
}