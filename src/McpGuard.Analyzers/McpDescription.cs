using Microsoft.CodeAnalysis;

namespace McpGuard.Analyzers;

/// <summary>Which part of the MCP tool surface a <c>[Description]</c> annotates.</summary>
internal enum McpDescriptionTarget
{
    /// <summary>An <c>[McpServerTool]</c> method.</summary>
    Tool,

    /// <summary>A parameter of an <c>[McpServerTool]</c> method.</summary>
    Parameter,

    /// <summary>An <c>[McpServerToolType]</c> type.</summary>
    ToolType,
}

/// <summary>
/// An extracted MCP tool description: the text an LLM reads as instructions, where to report a
/// finding, and which part of the tool surface it came from.
/// </summary>
internal readonly struct McpDescription(string text, Location location, McpDescriptionTarget target)
{

    /// <summary>The description text, as the model would read it.</summary>
    public string Text { get; } = text;

    /// <summary>Where a finding on this description should be reported.</summary>
    public Location Location { get; } = location;

    /// <summary>The part of the MCP tool surface this description annotates.</summary>
    public McpDescriptionTarget Target { get; } = target;
}