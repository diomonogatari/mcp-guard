using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.Diagnostics;

namespace McpGuard.Analyzers;

/// <summary>
/// One mcp-guard rule: it owns its <see cref="DiagnosticDescriptor"/> and inspects an extracted MCP
/// tool description. Rules are stateless singletons registered with
/// <see cref="McpToolDescriptionAnalyzer"/>; adding a rule is a matter of subclassing this and
/// listing it in the analyzer's rule set.
/// </summary>
internal abstract class McpDescriptionRule
{
    /// <summary>The diagnostic this rule can report.</summary>
    public abstract DiagnosticDescriptor Descriptor { get; }

    /// <summary>Inspect <paramref name="description"/> and report any finding via <paramref name="context"/>.</summary>
    public abstract void Analyze(in McpDescription description, SyntaxNodeAnalysisContext context);
}