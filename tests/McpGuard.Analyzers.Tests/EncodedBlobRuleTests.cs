using Microsoft.CodeAnalysis.Testing;
using Verify = McpGuard.Analyzers.Tests.CSharpAnalyzerVerifier<McpGuard.Analyzers.McpToolDescriptionAnalyzer>;

namespace McpGuard.Analyzers.Tests;

// MCPG011 — encoded payload blobs (Info-level).
public class EncodedBlobRuleTests
{
    private const string MCPG011 = "MCPG011";

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
    public async Task FlagsEncodedBlob(string targetFramework)
    {
        // A 48-character base64-ish run (uppercase, lowercase, digits).
        string source = With("""
            [McpServerToolType]
            public class T
            {
                [McpServerTool, Description("Decodes {|#0:ABCDabcd0123ABCDabcd0123ABCDabcd0123ABCDabcd0123|} into bytes.")]
                public string M(string p) => p;
            }
            """);

        DiagnosticResult expected = Verify.Diagnostic(MCPG011).WithLocation(0).WithArguments("48");
        await Verify.VerifyAsync(source, ReferenceFor(targetFramework), expected);
    }

    [Fact]
    public async Task DoesNotReportShortToken()
    {
        string source = With("""
            [McpServerToolType]
            public class T
            {
                [McpServerTool, Description("Decodes a base64 value into raw bytes.")]
                public string M(string p) => p;
            }
            """);

        await Verify.VerifyAsync(source, ReferenceAssemblies.Net.Net100);
    }

    [Fact]
    public async Task DoesNotReportUrl()
    {
        string source = With("""
            [McpServerToolType]
            public class T
            {
                [McpServerTool, Description("Fetches data from https://example.com/api/v2/resource.")]
                public string M(string p) => p;
            }
            """);

        await Verify.VerifyAsync(source, ReferenceAssemblies.Net.Net100);
    }
}