using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.Diagnostics;

namespace McpGuard.Analyzers;

/// <summary>MCPG001 — instruction-style phrasing inside an MCP tool/parameter/type description.</summary>
internal sealed class PromptInjectionRule : McpDescriptionRule
{
    private static readonly DiagnosticDescriptor Rule = new(
        id: DiagnosticIds.PromptInjectionInDescription,
        title: "MCP tool description contains prompt-injection phrasing",
        messageFormat: "MCP tool description contains instruction-style phrase \"{0}\"; LLMs read tool descriptions as instructions, so treat them as untrusted code and remove the directive",
        category: RuleMetadata.SecurityCategory,
        defaultSeverity: DiagnosticSeverity.Warning,
        isEnabledByDefault: true,
        description: "LLMs interpret MCP tool and parameter descriptions as instructions. Imperative or instruction-overriding phrasing inside a [Description] on an [McpServerTool] is a tool-poisoning / prompt-injection vector and should be removed.",
        helpLinkUri: RuleMetadata.HelpUri(DiagnosticIds.PromptInjectionInDescription));

    public override DiagnosticDescriptor Descriptor => Rule;

    public override void Analyze(in McpDescription description, SyntaxNodeAnalysisContext context)
    {
        if (ToolDescriptionPhrases.TryFindInjectionPhrase(description.Text, out string match))
        {
            context.ReportDiagnostic(Diagnostic.Create(Rule, description.LocationOf(match), match));
        }
    }
}