using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.Diagnostics;

namespace McpGuard.Analyzers;

/// <summary>MCPG003 — a sensitive credential / secret-file reference inside an MCP tool description.</summary>
internal sealed class SecretReferenceRule : McpDescriptionRule
{
    private static readonly DiagnosticDescriptor Rule = new(
        id: DiagnosticIds.SecretReferenceInDescription,
        title: "MCP tool description references a sensitive credential artifact",
        messageFormat: "MCP tool description references the sensitive credential artifact \"{0}\"; tool descriptions must never direct the model toward secrets",
        category: RuleMetadata.SecurityCategory,
        defaultSeverity: DiagnosticSeverity.Warning,
        isEnabledByDefault: true,
        description: "An MCP tool description is read by the model as guidance. A reference to an SSH private key, a cloud-credential file, or a system password file has no legitimate place in a description and is a hallmark of a data-exfiltration / tool-poisoning payload.",
        helpLinkUri: RuleMetadata.HelpUri(DiagnosticIds.SecretReferenceInDescription));

    public override DiagnosticDescriptor Descriptor => Rule;

    public override void Analyze(in McpDescription description, SyntaxNodeAnalysisContext context)
    {
        if (SecretArtifacts.TryFind(description.Text, out string match))
        {
            context.ReportDiagnostic(Diagnostic.Create(Rule, description.LocationOf(match), match));
        }
    }
}