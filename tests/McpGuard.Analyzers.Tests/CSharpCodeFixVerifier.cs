using Microsoft.CodeAnalysis.CodeFixes;
using Microsoft.CodeAnalysis.CSharp.Testing;
using Microsoft.CodeAnalysis.Diagnostics;
using Microsoft.CodeAnalysis.Testing;

namespace McpGuard.Analyzers.Tests;

/// <summary>Thin wrapper over the Roslyn code-fix test harness, using the framework's DefaultVerifier.</summary>
internal static class CSharpCodeFixVerifier<TAnalyzer, TCodeFix>
    where TAnalyzer : DiagnosticAnalyzer, new()
    where TCodeFix : CodeFixProvider, new()
{
    public static DiagnosticResult Diagnostic(string diagnosticId)
        => Microsoft.CodeAnalysis.CSharp.Testing.CSharpCodeFixVerifier<TAnalyzer, TCodeFix, DefaultVerifier>.Diagnostic(diagnosticId);

    public static System.Threading.Tasks.Task VerifyCodeFixAsync(string source, string fixedSource, ReferenceAssemblies referenceAssemblies, params DiagnosticResult[] expected)
    {
        var test = new Test(referenceAssemblies) { TestCode = source, FixedCode = fixedSource };
        test.ExpectedDiagnostics.AddRange(expected);
        return test.RunAsync(System.Threading.CancellationToken.None);
    }

    private sealed class Test : CSharpCodeFixTest<TAnalyzer, TCodeFix, DefaultVerifier>
    {
        public Test(ReferenceAssemblies referenceAssemblies) => ReferenceAssemblies = referenceAssemblies;
    }
}