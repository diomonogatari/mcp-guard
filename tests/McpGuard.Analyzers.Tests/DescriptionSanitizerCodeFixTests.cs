using Microsoft.CodeAnalysis.Testing;
using Verify = McpGuard.Analyzers.Tests.CSharpCodeFixVerifier<McpGuard.Analyzers.McpToolDescriptionAnalyzer, McpGuard.Analyzers.DescriptionSanitizerCodeFix>;

namespace McpGuard.Analyzers.Tests;

// Code fixes: strip hidden characters (MCPG002), remove ANSI sequences (MCPG005).
public class DescriptionSanitizerCodeFixTests
{
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

    [Fact]
    public async Task RemovesHiddenCharacter()
    {
        // ​ is literal escape text; the verifier compiles it into a real zero-width space.
        string source = With("""
            [McpServerToolType]
            public class T
            {
                [McpServerTool, Description({|#0:"Lists files in the directory.​"|})]
                public string M(string p) => p;
            }
            """);

        string fixedSource = With("""
            [McpServerToolType]
            public class T
            {
                [McpServerTool, Description("Lists files in the directory.")]
                public string M(string p) => p;
            }
            """);

        DiagnosticResult expected = Verify.Diagnostic("MCPG002").WithLocation(0)
            .WithArguments("a hidden or non-printable character (U+200B)");
        await Verify.VerifyCodeFixAsync(source, fixedSource, ReferenceAssemblies.Net.Net100, expected);
    }

    [Fact]
    public async Task RemovesAnsiEscapeSequence()
    {
        string source = With("""
            [McpServerToolType]
            public class T
            {
                [McpServerTool, Description({|#0:"Note\U0000001B[2K done"|})]
                public string M(string p) => p;
            }
            """);

        string fixedSource = With("""
            [McpServerToolType]
            public class T
            {
                [McpServerTool, Description("Note done")]
                public string M(string p) => p;
            }
            """);

        DiagnosticResult expected = Verify.Diagnostic("MCPG005").WithLocation(0);
        await Verify.VerifyCodeFixAsync(source, fixedSource, ReferenceAssemblies.Net.Net100, expected);
    }
}