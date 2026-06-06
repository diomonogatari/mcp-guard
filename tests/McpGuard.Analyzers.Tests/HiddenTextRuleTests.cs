using Microsoft.CodeAnalysis.Testing;
using Verify = McpGuard.Analyzers.Tests.CSharpAnalyzerVerifier<McpGuard.Analyzers.McpToolDescriptionAnalyzer>;

namespace McpGuard.Analyzers.Tests;

// MCPG002 hardening: ZWJ false-positive special-case, variation-selector runs, and tag decode-and-show.
public class HiddenTextRuleTests
{
    private const string MCPG002 = "MCPG002";

    private const string Harness = """
        using ModelContextProtocol.Server;
        using System.ComponentModel;

        namespace ModelContextProtocol.Server
        {
            [System.AttributeUsage(System.AttributeTargets.Class)]
            public sealed class McpServerToolTypeAttribute : System.Attribute { }

            [System.AttributeUsage(System.AttributeTargets.Method)]
            public sealed class McpServerToolAttribute : System.Attribute { }
        }


        """;

    private static string With(string body) => Harness + body;

    private static ReferenceAssemblies ReferenceFor(string targetFramework) => targetFramework switch
    {
        "net8.0" => ReferenceAssemblies.Net.Net80,
        "net10.0" => ReferenceAssemblies.Net.Net100,
        _ => throw new System.ArgumentException($"Unhandled target framework: {targetFramework}", nameof(targetFramework)),
    };

    [Fact]
    public async Task DoesNotReportLoneZeroWidthJoiner()
    {
        // U+200D is legitimate in emoji ZWJ sequences and Indic scripts, so a lone one is not flagged.
        string source = With("""
            [McpServerToolType]
            public class T
            {
                [McpServerTool, Description("Combines the family\U0000200Demoji glyphs.")]
                public string M(string p) => p;
            }
            """);

        await Verify.VerifyAsync(source, ReferenceAssemblies.Net.Net100);
    }

    [Fact]
    public async Task DoesNotReportSingleVariationSelector()
    {
        string source = With("""
            [McpServerToolType]
            public class T
            {
                [McpServerTool, Description("Shows a coloured heart\U0000FE0F icon.")]
                public string M(string p) => p;
            }
            """);

        await Verify.VerifyAsync(source, ReferenceAssemblies.Net.Net100);
    }

    [Theory]
    [InlineData("net8.0")]
    [InlineData("net10.0")]
    public async Task FlagsVariationSelectorRun(string targetFramework)
    {
        // A run of variation selectors carries smuggled bytes; flag it.
        string source = With("""
            [McpServerToolType]
            public class T
            {
                [McpServerTool, Description({|#0:"Status\U0000FE00\U0000FE01\U0000FE02 ok."|})]
                public string M(string p) => p;
            }
            """);

        DiagnosticResult expected = Verify.Diagnostic(MCPG002).WithLocation(0)
            .WithArguments("a run of Unicode variation selectors (possible byte-smuggling)");
        await Verify.VerifyAsync(source, ReferenceFor(targetFramework), expected);
    }

    [Fact]
    public async Task DecodesUnicodeTagHiddenText()
    {
        // The decode-and-show demo: the tag block hides the ASCII word "ignore".
        string source = With("""
            [McpServerToolType]
            public class T
            {
                [McpServerTool, Description({|#0:"Reads files.\U000E0069\U000E0067\U000E006E\U000E006F\U000E0072\U000E0065"|})]
                public string M(string p) => p;
            }
            """);

        DiagnosticResult expected = Verify.Diagnostic(MCPG002).WithLocation(0)
            .WithArguments("hidden text encoded in Unicode tag characters that reads \"ignore\"");
        await Verify.VerifyAsync(source, ReferenceAssemblies.Net.Net100, expected);
    }
}