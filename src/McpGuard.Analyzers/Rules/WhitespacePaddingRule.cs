using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.Diagnostics;

namespace McpGuard.Analyzers;

/// <summary>MCPG010 — whitespace padding used to push content off-screen in a description.</summary>
internal sealed class WhitespacePaddingRule : McpDescriptionRule
{
    private static readonly DiagnosticDescriptor Rule = new(
        id: DiagnosticIds.WhitespacePaddingInDescription,
        title: "MCP tool description contains off-screen whitespace padding",
        messageFormat: "MCP tool description contains {0} characters of whitespace padding; content hidden after a large gap is an off-screen exfiltration trick and should be removed",
        category: RuleMetadata.SecurityCategory,
        defaultSeverity: DiagnosticSeverity.Warning,
        isEnabledByDefault: true,
        description: "A long run of spaces or tabs pushes text off the visible area so a human reviewer never scrolls to it, while the model still reads it. Unlike MCPG002 this is ordinary visible whitespace; ordinary multi-line indentation (broken by newlines) is not flagged.",
        helpLinkUri: RuleMetadata.HelpUri(DiagnosticIds.WhitespacePaddingInDescription));

    public override DiagnosticDescriptor Descriptor => Rule;

    public override void Analyze(in McpDescription description, SyntaxNodeAnalysisContext context)
    {
        if (WhitespacePadding.TryFind(description.Text, out string run))
        {
            context.ReportDiagnostic(Diagnostic.Create(Rule, description.Location, run.Length));
        }
    }
}