using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.Diagnostics;

namespace McpGuard.Analyzers;

/// <summary>MCPG005 — an ANSI / terminal escape sequence inside an MCP tool description.</summary>
internal sealed class AnsiEscapeRule : McpDescriptionRule
{
    // ESC (U+001B) introduces every ANSI / terminal control sequence.
    private const char Escape = (char)0x1B;

    private static readonly DiagnosticDescriptor Rule = new(
        id: DiagnosticIds.AnsiEscapeInDescription,
        title: "MCP tool description contains an ANSI/terminal escape sequence",
        messageFormat: "MCP tool description contains an ANSI / terminal escape sequence (ESC, U+001B); terminal escapes can hide or rewrite rendered output and must not appear in a description",
        category: RuleMetadata.SecurityCategory,
        defaultSeverity: DiagnosticSeverity.Warning,
        isEnabledByDefault: true,
        description: "ANSI / terminal escape sequences (introduced by ESC, U+001B) can manipulate what a terminal-based MCP client renders, hiding text, rewriting lines, or spoofing hyperlinks. They have no legitimate place in a tool description.",
        helpLinkUri: RuleMetadata.HelpUri(DiagnosticIds.AnsiEscapeInDescription));

    public override DiagnosticDescriptor Descriptor => Rule;

    public override void Analyze(in McpDescription description, SyntaxNodeAnalysisContext context)
    {
        if (description.Text.IndexOf(Escape) >= 0)
        {
            context.ReportDiagnostic(Diagnostic.Create(Rule, description.Location));
        }
    }
}