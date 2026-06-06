namespace McpGuard.Analyzers;

/// <summary>
/// Stable diagnostic identifiers emitted by mcp-guard. Every id uses the <c>MCPG</c> prefix and is
/// permanent once shipped — ids are never reused or renumbered.
/// </summary>
internal static class DiagnosticIds
{
    /// <summary>Prefix shared by every mcp-guard diagnostic id.</summary>
    public const string Prefix = "MCPG";

    /// <summary>Prompt-injection / instruction-override phrasing embedded in an MCP tool description.</summary>
    public const string PromptInjectionInDescription = "MCPG001";

    /// <summary>Hidden / non-printable Unicode (zero-width, bidi controls, BOM, tag chars) in an MCP tool description.</summary>
    public const string HiddenTextInDescription = "MCPG002";

    /// <summary>Sensitive credential / secret-file reference inside an MCP tool description.</summary>
    public const string SecretReferenceInDescription = "MCPG003";

    /// <summary>Data-exfiltration directive or sink (external destination) in a description.</summary>
    public const string ExfiltrationInDescription = "MCPG004";

    /// <summary>ANSI / terminal escape sequence (ESC, U+001B) inside an MCP tool description.</summary>
    public const string AnsiEscapeInDescription = "MCPG005";

    /// <summary>Manipulative / authority phrasing (coercion, suppressing other tools) in a description.</summary>
    public const string ManipulativePhrasingInDescription = "MCPG006";

    /// <summary>Embedded instruction markup (HTML comments, fake system tags) in a description.</summary>
    public const string EmbeddedMarkupInDescription = "MCPG008";
}