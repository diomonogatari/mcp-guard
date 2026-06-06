using Microsoft.CodeAnalysis.Testing;
using System.Collections.Generic;
using Verify = McpGuard.Analyzers.Tests.CSharpCodeFixVerifier<McpGuard.Analyzers.McpToolDescriptionAnalyzer, McpGuard.Analyzers.DescriptionBaselineCodeFix>;

namespace McpGuard.Analyzers.Tests;

// The MCPG013 code fix records the offending tool's current fingerprint in McpGuard.Baseline.txt,
// preserving comments and unrelated entries. The merge logic is unit-tested directly; one end-to-end
// test proves the fix is offered and edits the additional file.
public class DescriptionBaselineCodeFixTests
{
    private const string MCPG013 = "MCPG013";
    private const string BaselineFileName = "McpGuard.Baseline.txt";
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

    private static KeyValuePair<string, string> Update() => new(Identity, Pinned(CleanDescription));

    [Fact]
    public async Task RecordsAnUnpinnedToolInTheBaseline()
    {
        // Empty baseline → the fix appends the tool's current fingerprint; source is unchanged.
        const string before = "";
        string after = DescriptionBaselineCodeFix.ApplyUpdates(before, new[] { Update() });
        DiagnosticResult expected = Verify.Diagnostic(MCPG013).WithLocation(0).WithArguments(Identity, Pinned(CleanDescription));

        await Verify.VerifyAdditionalFileFixAsync(
            With(MarkedBody), With(PlainBody), BaselineFileName, before, after, ReferenceAssemblies.Net.Net100, expected);
    }

    [Fact]
    public void ApplyUpdatesAppendsToAnEmptyBaseline()
    {
        string result = DescriptionBaselineCodeFix.ApplyUpdates("", new[] { new KeyValuePair<string, string>("A.B", "A.B => 1111") });
        Assert.Equal("A.B => 1111\n", result);
    }

    [Fact]
    public void ApplyUpdatesReplacesAnExistingEntryInPlace()
    {
        const string before = "# pinned\nA.B => oldhash\nC.D => keepme\n";
        string result = DescriptionBaselineCodeFix.ApplyUpdates(before, new[] { new KeyValuePair<string, string>("A.B", "A.B => newhash") });
        Assert.Equal("# pinned\nA.B => newhash\nC.D => keepme\n", result);
    }

    [Fact]
    public void ApplyUpdatesPreservesCommentsAndAppendsNewEntriesSorted()
    {
        const string before = "# header\nB.B => bbb\n";
        string result = DescriptionBaselineCodeFix.ApplyUpdates(before, new[]
        {
            new KeyValuePair<string, string>("Z.Z", "Z.Z => zzz"),
            new KeyValuePair<string, string>("A.A", "A.A => aaa"),
        });
        Assert.Equal("# header\nB.B => bbb\nA.A => aaa\nZ.Z => zzz\n", result);
    }

    [Fact]
    public void ApplyUpdatesIgnoresCarriageReturnsAndTrailingBlankLines()
    {
        const string before = "A.B => old\r\n\r\n";
        string result = DescriptionBaselineCodeFix.ApplyUpdates(before, new[] { new KeyValuePair<string, string>("A.B", "A.B => new") });
        Assert.Equal("A.B => new\n", result);
    }
}