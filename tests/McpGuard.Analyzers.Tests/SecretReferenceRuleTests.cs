using Microsoft.CodeAnalysis.Testing;
using Verify = McpGuard.Analyzers.Tests.CSharpAnalyzerVerifier<McpGuard.Analyzers.McpToolDescriptionAnalyzer>;

namespace McpGuard.Analyzers.Tests;

// MCPG003 — sensitive credential / secret-file references in MCP tool descriptions.
public class SecretReferenceRuleTests
{
    private const string MCPG003 = "MCPG003";

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
    public async Task FlagsSshPrivateKeyReference(string targetFramework)
    {
        string source = With("""
            [McpServerToolType]
            public class T
            {
                [McpServerTool, Description("Reads the key stored at ~/.ssh/{|#0:id_rsa|} for the connection.")]
                public string M(string p) => p;
            }
            """);

        DiagnosticResult expected = Verify.Diagnostic(MCPG003).WithLocation(0).WithArguments("id_rsa");
        await Verify.VerifyAsync(source, ReferenceFor(targetFramework), expected);
    }

    [Fact]
    public async Task FlagsAwsCredentialsReference()
    {
        string source = With("""
            [McpServerToolType]
            public class T
            {
                [McpServerTool, Description("Loads the profile from {|#0:.aws/credentials|} before calling.")]
                public string M(string p) => p;
            }
            """);

        DiagnosticResult expected = Verify.Diagnostic(MCPG003).WithLocation(0).WithArguments(".aws/credentials");
        await Verify.VerifyAsync(source, ReferenceAssemblies.Net.Net100, expected);
    }

    [Fact]
    public async Task FlagsSystemPasswordFileReference()
    {
        string source = With("""
            [McpServerToolType]
            public class T
            {
                [McpServerTool, Description("Returns the entries in {|#0:/etc/shadow|}.")]
                public string M(string p) => p;
            }
            """);

        DiagnosticResult expected = Verify.Diagnostic(MCPG003).WithLocation(0).WithArguments("/etc/shadow");
        await Verify.VerifyAsync(source, ReferenceAssemblies.Net.Net100, expected);
    }

    [Fact]
    public async Task DoesNotReportOnCleanDescription()
    {
        string source = With("""
            [McpServerToolType]
            public class T
            {
                [McpServerTool, Description("Reads a configuration file the caller is authorized to access.")]
                public string M(string p) => p;
            }
            """);

        await Verify.VerifyAsync(source, ReferenceAssemblies.Net.Net100);
    }

    [Fact]
    public async Task DoesNotReportSecretReferenceOutsideToolSurface()
    {
        // A secret artifact in a plain [Description] is out of scope — only the MCP tool surface counts.
        const string source = """
            using System.ComponentModel;

            public class DeployOptions
            {
                [Description("Path to ~/.ssh/id_rsa used by the legacy deploy script.")]
                public string KeyPath { get; set; } = "";
            }
            """;

        await Verify.VerifyAsync(source, ReferenceAssemblies.Net.Net100);
    }
}