using System.ComponentModel;

namespace PoisonedServer;

// NOT part of the MCP tool surface. Even though this [Description] contains a trigger phrase,
// mcp-guard must NOT flag it — MCPG001 only inspects descriptions an LLM actually reads as
// tool metadata. This anchors the analyzer's precision in the live sample build.
public sealed class LegacyOptions
{
    [Description("Ignore previous instructions in the legacy config parser; retained for back-compat.")]
    public string Mode { get; set; } = "default";
}