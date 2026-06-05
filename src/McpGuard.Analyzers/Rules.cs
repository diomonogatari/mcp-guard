using Microsoft.CodeAnalysis;
using System.Collections.Immutable;

namespace McpGuard.Analyzers;

/// <summary>
/// Central catalog of mcp-guard diagnostic descriptors. New rules are declared here and surfaced
/// through <see cref="All"/> so analyzers and the release-tracking files stay in sync.
/// </summary>
internal static class Rules
{
    private const string SecurityCategory = "Security";
    private const string HelpUriBase = "https://github.com/diomonogatari/mcp-guard/blob/main/docs/rules/";

    /// <summary>MCPG001 — instruction-style phrasing inside an MCP tool/parameter description.</summary>
    public static readonly DiagnosticDescriptor PromptInjection = new(
        id: DiagnosticIds.PromptInjectionInDescription,
        title: "MCP tool description contains prompt-injection phrasing",
        messageFormat: "MCP tool description contains instruction-style phrase \"{0}\"; LLMs read tool descriptions as instructions, so treat them as untrusted code and remove the directive",
        category: SecurityCategory,
        defaultSeverity: DiagnosticSeverity.Warning,
        isEnabledByDefault: true,
        description: "LLMs interpret MCP tool and parameter descriptions as instructions. Imperative or instruction-overriding phrasing inside a [Description] on an [McpServerTool] is a tool-poisoning / prompt-injection vector and should be removed.",
        helpLinkUri: HelpUriBase + DiagnosticIds.PromptInjectionInDescription + ".md");

    /// <summary>All descriptors mcp-guard can report. Returned verbatim as SupportedDiagnostics.</summary>
    public static readonly ImmutableArray<DiagnosticDescriptor> All = ImmutableArray.Create(PromptInjection);
}