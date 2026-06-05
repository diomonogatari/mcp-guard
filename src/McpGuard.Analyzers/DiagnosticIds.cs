namespace McpGuard.Analyzers;

/// <summary>
/// Stable diagnostic identifiers emitted by mcp-guard. Every id uses the <c>MCPG</c> prefix and is
/// permanent once shipped — ids are never reused or renumbered.
/// </summary>
internal static class DiagnosticIds
{
    /// <summary>Prefix shared by every mcp-guard diagnostic id.</summary>
    public const string Prefix = "MCPG";

    /// <summary>Prompt-injection / instruction-style phrasing embedded in an MCP tool description.</summary>
    public const string PromptInjectionInDescription = "MCPG001";
}