using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.Diagnostics;

namespace McpGuard.Analyzers;

/// <summary>MCPG008 — embedded instruction markup (HTML comments, fake system tags) in a description.</summary>
internal sealed class EmbeddedMarkupRule : McpDescriptionRule
{
    private static readonly DiagnosticDescriptor Rule = new(
        id: DiagnosticIds.EmbeddedMarkupInDescription,
        title: "MCP tool description contains embedded instruction markup",
        messageFormat: "MCP tool description contains embedded markup \"{0}\"; fake tags and HTML comments are a delivery format for hidden instructions and must not appear in a description",
        category: RuleMetadata.SecurityCategory,
        defaultSeverity: DiagnosticSeverity.Warning,
        isEnabledByDefault: true,
        description: "HTML comments and fake system / instruction tags (<system>, <important>, <|im_start|>, [INST], …) are a common delivery format for smuggled instructions inside a tool description. A description is plain prose and should contain none of them.",
        helpLinkUri: RuleMetadata.HelpUri(DiagnosticIds.EmbeddedMarkupInDescription));

    public override DiagnosticDescriptor Descriptor => Rule;

    public override void Analyze(in McpDescription description, SyntaxNodeAnalysisContext context)
    {
        if (EmbeddedMarkup.TryFind(description.Text, out string match))
        {
            context.ReportDiagnostic(Diagnostic.Create(Rule, description.Location, match));
        }
    }
}