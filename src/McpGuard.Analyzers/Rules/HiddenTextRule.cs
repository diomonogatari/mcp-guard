using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.Diagnostics;

namespace McpGuard.Analyzers;

/// <summary>MCPG002 — hidden / non-printable Unicode inside an MCP tool/parameter/type description.</summary>
internal sealed class HiddenTextRule : McpDescriptionRule
{
    private static readonly DiagnosticDescriptor Rule = new(
        id: DiagnosticIds.HiddenTextInDescription,
        title: "MCP tool description contains hidden or non-printable characters",
        messageFormat: "MCP tool description contains a hidden or non-printable character (U+{0}); invisible text can smuggle instructions past human review and should be removed",
        category: RuleMetadata.SecurityCategory,
        defaultSeverity: DiagnosticSeverity.Warning,
        isEnabledByDefault: true,
        description: "Zero-width, bidirectional-control, byte-order-mark, and other invisible Unicode characters have no place in a tool description. They are a known vector for hiding instructions a human reviewer cannot see but an LLM still reads.",
        helpLinkUri: RuleMetadata.HelpUri(DiagnosticIds.HiddenTextInDescription));

    public override DiagnosticDescriptor Descriptor => Rule;

    public override void Analyze(in McpDescription description, SyntaxNodeAnalysisContext context)
    {
        if (HiddenCharacters.TryFind(description.Text, out int codePoint))
        {
            context.ReportDiagnostic(Diagnostic.Create(Rule, description.Location, codePoint.ToString("X4")));
        }
    }
}