namespace McpGuard.Analyzers;

/// <summary>Metadata shared across mcp-guard diagnostic descriptors.</summary>
internal static class RuleMetadata
{
    /// <summary>Category for every mcp-guard rule.</summary>
    public const string SecurityCategory = "Security";

    private const string HelpUriBase = "https://github.com/diomonogatari/mcp-guard/blob/main/docs/rules/";

    /// <summary>The published help-doc URL for a rule id (e.g. <c>.../docs/rules/MCPG001.md</c>).</summary>
    public static string HelpUri(string ruleId) => HelpUriBase + ruleId + ".md";
}