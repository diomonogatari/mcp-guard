using Microsoft.CodeAnalysis.CSharp.Testing;
using Microsoft.CodeAnalysis.Diagnostics;
using Microsoft.CodeAnalysis.Testing;

namespace McpGuard.Analyzers.Tests;

/// <summary>
/// Thin wrapper over the Roslyn testing harness so a test can target a chosen runtime by passing
/// <see cref="ReferenceAssemblies"/>. Uses the framework-agnostic <see cref="DefaultVerifier"/>
/// (the per-framework XUnitVerifier is obsolete).
/// </summary>
internal static class CSharpAnalyzerVerifier<TAnalyzer>
    where TAnalyzer : DiagnosticAnalyzer, new()
{
    public static DiagnosticResult Diagnostic(string diagnosticId)
        => Microsoft.CodeAnalysis.CSharp.Testing.CSharpAnalyzerVerifier<TAnalyzer, DefaultVerifier>.Diagnostic(diagnosticId);

    public static Task VerifyAsync(string source, ReferenceAssemblies referenceAssemblies, params DiagnosticResult[] expected)
    {
        var test = new Test(referenceAssemblies) { TestCode = source };
        test.ExpectedDiagnostics.AddRange(expected);
        return test.RunAsync(CancellationToken.None);
    }

    /// <summary>Runs the analyzer with a baseline file supplied as an additional file (for MCPG013).</summary>
    public static Task VerifyWithAdditionalFileAsync(
        string source,
        string additionalFileName,
        string additionalFileContent,
        ReferenceAssemblies referenceAssemblies,
        params DiagnosticResult[] expected)
    {
        var test = new Test(referenceAssemblies) { TestCode = source };
        test.TestState.AdditionalFiles.Add((additionalFileName, additionalFileContent));
        test.ExpectedDiagnostics.AddRange(expected);
        return test.RunAsync(CancellationToken.None);
    }

    private sealed class Test : CSharpAnalyzerTest<TAnalyzer, DefaultVerifier>
    {
        public Test(ReferenceAssemblies referenceAssemblies) => ReferenceAssemblies = referenceAssemblies;
    }
}