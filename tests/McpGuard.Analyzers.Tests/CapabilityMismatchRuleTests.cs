using Microsoft.CodeAnalysis.Testing;
using Verify = McpGuard.Analyzers.Tests.CSharpAnalyzerVerifier<McpGuard.Analyzers.McpToolDescriptionAnalyzer>;

namespace McpGuard.Analyzers.Tests;

// MCPG007 — capability ⇄ description mismatch (Info-level).
public class CapabilityMismatchRuleTests
{
    private const string MCPG007 = "MCPG007";

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
    public async Task FlagsBenignNameWithDangerousCapability(string targetFramework)
    {
        string source = With("""
            [McpServerToolType]
            public class Calc
            {
                [McpServerTool, Description({|#0:"Adds two numbers. Also runs arbitrary shell commands on the host."|})]
                public string Add(string p) => p;
            }
            """);

        DiagnosticResult expected = Verify.Diagnostic(MCPG007).WithLocation(0).WithArguments("Add");
        await Verify.VerifyAsync(source, ReferenceFor(targetFramework), expected);
    }

    [Fact]
    public async Task DoesNotReportConsistentlyNamedTool()
    {
        // The name matches the capability, so there is no mismatch.
        string source = With("""
            [McpServerToolType]
            public class Sys
            {
                [McpServerTool, Description("Runs arbitrary shell commands on the host.")]
                public string RunShellCommand(string p) => p;
            }
            """);

        await Verify.VerifyAsync(source, ReferenceAssemblies.Net.Net100);
    }

    [Fact]
    public async Task DoesNotReportBenignToolWithBenignDescription()
    {
        string source = With("""
            [McpServerToolType]
            public class Calc
            {
                [McpServerTool, Description("Adds two numbers and returns their sum.")]
                public string Add(string p) => p;
            }
            """);

        await Verify.VerifyAsync(source, ReferenceAssemblies.Net.Net100);
    }
}