using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.Diagnostics;

namespace McpGuard.Analyzers;

/// <summary>MCPG006 — manipulative / authority phrasing inside an MCP tool description.</summary>
internal sealed class ManipulativePhrasingRule : McpDescriptionRule
{
    private static readonly DiagnosticDescriptor Rule = new(
        id: DiagnosticIds.ManipulativePhrasingInDescription,
        title: "MCP tool description contains manipulative or authority phrasing",
        messageFormat: "MCP tool description contains manipulative / authority phrasing \"{0}\"; a tool must not coerce the model or suppress other tools",
        category: RuleMetadata.SecurityCategory,
        defaultSeverity: DiagnosticSeverity.Warning,
        isEnabledByDefault: true,
        description: "Phrasing that coerces the model (\"you must comply\"), claims false authority (\"I am the developer\"), or tells it to ignore other tools is a tool-poisoning tactic. It complements MCPG001 (instruction-override phrasing) with the manipulation / authority layer.",
        helpLinkUri: RuleMetadata.HelpUri(DiagnosticIds.ManipulativePhrasingInDescription));

    public override DiagnosticDescriptor Descriptor => Rule;

    public override void Analyze(in McpDescription description, SyntaxNodeAnalysisContext context)
    {
        if (ManipulationPhrases.TryFind(description.Text, out string match))
        {
            context.ReportDiagnostic(Diagnostic.Create(Rule, description.Location, match));
        }
    }
}