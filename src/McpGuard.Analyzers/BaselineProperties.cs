namespace McpGuard.Analyzers;

/// <summary>
/// Keys for the diagnostic <c>Properties</c> bag MCPG013 carries, so the baseline code fix can update
/// the <c>McpGuard.Baseline.txt</c> entry without recomputing the fingerprint. The code-fixes assembly
/// cannot reference this assembly (that would be a circular project reference), so it mirrors these two
/// constant values — keep them in sync.
/// </summary>
internal static class BaselineProperties
{
    /// <summary>The pinned identity, e.g. <c>Acme.Tools.FileTools.ReadFile</c>.</summary>
    public const string Identity = "Identity";

    /// <summary>The canonical baseline line the entry should become (<c>identity =&gt; hash</c>).</summary>
    public const string ExpectedLine = "ExpectedLine";
}