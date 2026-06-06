using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.Diagnostics;

namespace McpGuard.Analyzers;

/// <summary>MCPG002 — hidden / non-printable Unicode inside an MCP tool/parameter/type description.</summary>
internal sealed class HiddenTextRule : McpDescriptionRule
{
    private static readonly DiagnosticDescriptor Rule = new(
        id: DiagnosticIds.HiddenTextInDescription,
        title: "MCP tool description contains hidden or non-printable characters",
        messageFormat: "MCP tool description contains {0}; invisible content can smuggle instructions past human review and should be removed",
        category: RuleMetadata.SecurityCategory,
        defaultSeverity: DiagnosticSeverity.Warning,
        isEnabledByDefault: true,
        description: "Zero-width, bidirectional-control, byte-order-mark, Unicode-tag, and other invisible characters have no place in a tool description. They are a known vector for hiding instructions a human reviewer cannot see but an LLM still reads. ZWJ / ZWNJ (legitimate in emoji and Indic scripts) and ESC (handled by MCPG005) are excluded.",
        helpLinkUri: RuleMetadata.HelpUri(DiagnosticIds.HiddenTextInDescription));

    public override DiagnosticDescriptor Descriptor => Rule;

    public override void Analyze(in McpDescription description, SyntaxNodeAnalysisContext context)
    {
        if (HiddenCharacters.TryFind(description.Text, out string detail))
        {
            context.ReportDiagnostic(Diagnostic.Create(Rule, description.Location, detail));
        }
    }
}