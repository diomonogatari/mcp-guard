using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.Diagnostics;

namespace McpGuard.Analyzers;

/// <summary>MCPG009 — phrasing that attaches covert behavior to other tools (tool shadowing).</summary>
internal sealed class CrossToolReferenceRule : McpDescriptionRule
{
    private static readonly DiagnosticDescriptor Rule = new(
        id: DiagnosticIds.CrossToolReferenceInDescription,
        title: "MCP tool description tries to influence other tools",
        messageFormat: "MCP tool description tries to influence other tools \"{0}\"; a tool must not redirect, shadow, or attach behavior to other tools",
        category: RuleMetadata.SecurityCategory,
        defaultSeverity: DiagnosticSeverity.Warning,
        isEnabledByDefault: true,
        description: "A description that attaches covert behavior to other tools (\"also BCC …\", \"forward a copy …\", \"for every other tool …\") is a tool-shadowing / cross-server compromise vector. A tool describes itself; it does not orchestrate the rest of the toolset.",
        helpLinkUri: RuleMetadata.HelpUri(DiagnosticIds.CrossToolReferenceInDescription));

    public override DiagnosticDescriptor Descriptor => Rule;

    public override void Analyze(in McpDescription description, SyntaxNodeAnalysisContext context)
    {
        if (CrossToolPhrases.TryFind(description.Text, out string match))
        {
            context.ReportDiagnostic(Diagnostic.Create(Rule, description.LocationOf(match), match));
        }
    }
}