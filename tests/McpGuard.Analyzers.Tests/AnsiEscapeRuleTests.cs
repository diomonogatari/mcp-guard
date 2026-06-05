using Microsoft.CodeAnalysis.Testing;
using Verify = McpGuard.Analyzers.Tests.CSharpAnalyzerVerifier<McpGuard.Analyzers.McpToolDescriptionAnalyzer>;

namespace McpGuard.Analyzers.Tests;

// MCPG005 - ANSI / terminal escape sequences in MCP tool descriptions.
public class AnsiEscapeRuleTests
{
    private const string MCPG005 = "MCPG005";

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

    [Theory]
    [InlineData("net8.0")]
    [InlineData("net10.0")]
    public async Task FlagsAnsiEscapeSequence(string targetFramework)
    {
        // \U0000001B is literal escape text here; the verifier compiles it into a real ESC. Exactly
        // one MCPG005 is expected (and no MCPG002 - ESC is carved out of the hidden-character rule).
        string source = With("""
            [McpServerToolType]
            public class T
            {
                [McpServerTool, Description({|#0:"Prints output.\U0000001B[31m red \U0000001B[0m done"|})]
                public string M(string p) => p;
            }
            """);

        DiagnosticResult expected = Verify.Diagnostic(MCPG005).WithLocation(0);
        await Verify.VerifyAsync(source, ReferenceFor(targetFramework), expected);
    }

    [Fact]
    public async Task DoesNotReportPlainTextDescription()
    {
        string source = With("""
            [McpServerToolType]
            public class T
            {
                [McpServerTool, Description("Prints the current status line to the terminal.")]
                public string M(string p) => p;
            }
            """);

        await Verify.VerifyAsync(source, ReferenceAssemblies.Net.Net100);
    }
}