using Microsoft.CodeAnalysis.Testing;
using Verify = McpGuard.Analyzers.Tests.CSharpAnalyzerVerifier<McpGuard.Analyzers.McpToolDescriptionAnalyzer>;

namespace McpGuard.Analyzers.Tests;

// MCPG013 — the description-integrity baseline (rug-pull guard). The feature is opt-in: dormant unless a
// McpGuard.Baseline.txt is supplied as an additional file. When present, any drift of the exact
// model-visible text from its pinned fingerprint is reported.
public class DescriptionBaselineTests
{
    private const string MCPG013 = "MCPG013";
    private const string BaselineFileName = "McpGuard.Baseline.txt";

    // The harness puts class T in the global namespace, so the pinned identity is "T.M".
    private const string Identity = "T.M";
    private const string CleanDescription = "Reads a file.";

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

    // Whole-literal location is marked #0 for the cases that report drift.
    private const string MarkedBody = """
        [McpServerToolType]
        public class T
        {
            [McpServerTool, Description({|#0:"Reads a file."|})]
            public string M(string p) => p;
        }
        """;

    private const string PlainBody = """
        [McpServerToolType]
        public class T
        {
            [McpServerTool, Description("Reads a file.")]
            public string M(string p) => p;
        }
        """;

    private static string With(string body) => Harness + body;

    private static string Pinned(string text) => DescriptionBaseline.FormatLine(Identity, text);

    private static ReferenceAssemblies ReferenceFor(string targetFramework) => targetFramework switch
    {
        "net8.0" => ReferenceAssemblies.Net.Net80,
        "net10.0" => ReferenceAssemblies.Net.Net100,
        _ => throw new System.ArgumentException($"Unhandled target framework: {targetFramework}", nameof(targetFramework)),
    };

    [Theory]
    [InlineData("net8.0")]
    [InlineData("net10.0")]
    public async Task ReportsDriftWhenDescriptionChangedSincePinned(string targetFramework)
    {
        // The baseline pins a different text, so the current description's fingerprint no longer matches.
        // The reported "expected line" is the identity + the fingerprint of the *current* text.
        string baseline = Pinned("The description this tool was approved with.");
        DiagnosticResult expected = Verify.Diagnostic(MCPG013).WithLocation(0).WithArguments(Identity, Pinned(CleanDescription));
        await Verify.VerifyWithAdditionalFileAsync(With(MarkedBody), BaselineFileName, baseline, ReferenceFor(targetFramework), expected);
    }

    [Fact]
    public async Task StaysQuietWhenDescriptionMatchesPinnedFingerprint()
    {
        string baseline = Pinned(CleanDescription);
        await Verify.VerifyWithAdditionalFileAsync(With(PlainBody), BaselineFileName, baseline, ReferenceAssemblies.Net.Net100);
    }

    [Fact]
    public async Task ReportsUnpinnedToolWhenBaselineHasNoEntry()
    {
        // A baseline file exists (feature is active) but does not record this tool yet.
        const string baseline = "# pinned MCP tool descriptions\n";
        DiagnosticResult expected = Verify.Diagnostic(MCPG013).WithLocation(0).WithArguments(Identity, Pinned(CleanDescription));
        await Verify.VerifyWithAdditionalFileAsync(With(MarkedBody), BaselineFileName, baseline, ReferenceAssemblies.Net.Net100, expected);
    }

    [Fact]
    public async Task IsDormantWithoutABaselineFile()
    {
        // No additional file → the integrity baseline never reports, so ordinary builds opt out for free.
        await Verify.VerifyAsync(With(PlainBody), ReferenceAssemblies.Net.Net100);
    }

    [Fact]
    public async Task ParserIgnoresCommentsAndBlankLines()
    {
        string baseline = "# mcp-guard description-integrity baseline\n\n   \n" + Pinned(CleanDescription) + "\n# end\n";
        await Verify.VerifyWithAdditionalFileAsync(With(PlainBody), BaselineFileName, baseline, ReferenceAssemblies.Net.Net100);
    }

    [Fact]
    public void FingerprintIsStableAndCatchesAnInvisibleEdit()
    {
        Assert.Equal(DescriptionBaseline.Fingerprint(CleanDescription), DescriptionBaseline.Fingerprint(CleanDescription));

        // The fingerprint is over the raw bytes, so smuggling in a zero-width space (U+200B) changes it —
        // the exact guarantee that makes MCPG013 a meaningful integrity check.
        Assert.NotEqual(DescriptionBaseline.Fingerprint(CleanDescription), DescriptionBaseline.Fingerprint(CleanDescription + "\u200B"));
        Assert.Equal(32, DescriptionBaseline.Fingerprint(CleanDescription).Length);
    }

    [Theory]
    [InlineData("/repo/src/McpGuard.Baseline.txt", true)]
    [InlineData("mcpguard.baseline.TXT", true)]
    [InlineData("/repo/McpGuard.Baseline.json", false)]
    [InlineData("/repo/Baseline.txt", false)]
    public void IsBaselineFileMatchesByNameOnly(string path, bool expected)
    {
        Assert.Equal(expected, DescriptionBaseline.IsBaselineFile(path));
    }
}