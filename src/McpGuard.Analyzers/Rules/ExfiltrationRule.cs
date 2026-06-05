using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.Diagnostics;

namespace McpGuard.Analyzers;

/// <summary>MCPG004 — a data-exfiltration directive inside an MCP tool description.</summary>
internal sealed class ExfiltrationRule : McpDescriptionRule
{
    private static readonly DiagnosticDescriptor Rule = new(
        id: DiagnosticIds.ExfiltrationInDescription,
        title: "MCP tool description directs data to an external destination",
        messageFormat: "MCP tool description directs the model to {0} sensitive data to an external destination; this is a data-exfiltration vector and should be removed",
        category: RuleMetadata.SecurityCategory,
        defaultSeverity: DiagnosticSeverity.Warning,
        isEnabledByDefault: true,
        description: "A tool description that instructs the model to transmit secrets, credentials, the conversation, or other sensitive data to an external URL or webhook — or to do so covertly — is a data-exfiltration directive. Legitimate \"upload to the configured endpoint\" tools are not flagged: the rule requires a transmit verb, an external destination, and a sensitivity or covertness signal together.",
        helpLinkUri: RuleMetadata.HelpUri(DiagnosticIds.ExfiltrationInDescription));

    public override DiagnosticDescriptor Descriptor => Rule;

    public override void Analyze(in McpDescription description, SyntaxNodeAnalysisContext context)
    {
        if (ExfiltrationCues.TryFind(description.Text, out string verb))
        {
            context.ReportDiagnostic(Diagnostic.Create(Rule, description.Location, verb));
        }
    }
}