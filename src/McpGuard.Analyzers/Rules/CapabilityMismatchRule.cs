using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp.Syntax;
using Microsoft.CodeAnalysis.Diagnostics;

namespace McpGuard.Analyzers;

/// <summary>MCPG007 — a benign-named tool whose description claims a dangerous capability. Info-level.</summary>
internal sealed class CapabilityMismatchRule : McpDescriptionRule
{
    private static readonly DiagnosticDescriptor Rule = new(
        id: DiagnosticIds.CapabilityMismatchInDescription,
        title: "MCP tool name and described capability mismatch",
        messageFormat: "MCP tool \"{0}\" looks benign but its description claims a high-privilege capability; verify the tool's name and scope match what it does",
        category: RuleMetadata.SecurityCategory,
        defaultSeverity: DiagnosticSeverity.Info,
        isEnabledByDefault: true,
        description: "A benign-sounding tool (\"add\", \"format_date\") whose description claims file, network, or shell reach is a capability / description mismatch: a way to slip a dangerous tool past review under an innocuous name. Advisory (Info) because the heuristic is name-based.",
        helpLinkUri: RuleMetadata.HelpUri(DiagnosticIds.CapabilityMismatchInDescription));

    public override DiagnosticDescriptor Descriptor => Rule;

    public override void Analyze(in McpDescription description, SyntaxNodeAnalysisContext context)
    {
        // Only a member's own description can mismatch its name.
        if (description.Target != McpDescriptionTarget.Member)
        {
            return;
        }

        if (!CapabilityClaims.ClaimsDangerousCapability(description.Text))
        {
            return;
        }

        string toolName = GetToolName(context.Node);
        if (BenignToolNames.IsBenign(toolName))
        {
            context.ReportDiagnostic(Diagnostic.Create(Rule, description.Location, toolName));
        }
    }

    // context.Node is the [Description] attribute; its owning method is the tool.
    private static string GetToolName(SyntaxNode descriptionAttribute)
        => descriptionAttribute.Parent?.Parent is MethodDeclarationSyntax method ? method.Identifier.ValueText : string.Empty;
}