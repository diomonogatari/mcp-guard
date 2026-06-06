using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.Diagnostics;

namespace McpGuard.Analyzers;

/// <summary>MCPG004 — a data-exfiltration directive or sink inside an MCP tool description.</summary>
internal sealed class ExfiltrationRule : McpDescriptionRule
{
    private static readonly DiagnosticDescriptor Rule = new(
        id: DiagnosticIds.ExfiltrationInDescription,
        title: "MCP tool description routes data to an external destination",
        messageFormat: "MCP tool description routes data to an external destination via {0}; this is a data-exfiltration vector and should be removed",
        category: RuleMetadata.SecurityCategory,
        defaultSeverity: DiagnosticSeverity.Warning,
        isEnabledByDefault: true,
        description: "A tool description that ships secrets, credentials, or the conversation to an external URL or webhook is a data-exfiltration vector. The sink can be an explicit transmit directive or a markdown image/link a renderer auto-fetches. Legitimate \"upload to the configured endpoint\" tools are not flagged: a directive must pair a transmit verb, an external destination, and a sensitivity or covertness signal.",
        helpLinkUri: RuleMetadata.HelpUri(DiagnosticIds.ExfiltrationInDescription));

    public override DiagnosticDescriptor Descriptor => Rule;

    public override void Analyze(in McpDescription description, SyntaxNodeAnalysisContext context)
    {
        if (ExfiltrationCues.TryFindSink(description.Text, out string channel))
        {
            context.ReportDiagnostic(Diagnostic.Create(Rule, description.Location, channel));
        }
    }
}