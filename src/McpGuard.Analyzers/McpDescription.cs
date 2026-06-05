using Microsoft.CodeAnalysis;

namespace McpGuard.Analyzers;

/// <summary>Which part of the MCP surface a scanned string comes from.</summary>
internal enum McpDescriptionTarget
{
    /// <summary>A [Description] on an MCP member method ([McpServerTool] / [McpServerPrompt] / [McpServerResource]).</summary>
    Member,

    /// <summary>A [Description] on a parameter of an MCP member method.</summary>
    Parameter,

    /// <summary>A [Description] on an MCP type ([McpServerToolType] / [McpServerPromptType] / [McpServerResourceType]).</summary>
    Type,

    /// <summary>The <c>Name = "..."</c> argument of an MCP member attribute.</summary>
    Name,
}

/// <summary>
/// An extracted MCP surface string: the text the model reads, where to report a finding, and which
/// part of the surface it came from.
/// </summary>
internal readonly struct McpDescription(string text, Location location, McpDescriptionTarget target)
{
    /// <summary>The text, as the model would read it.</summary>
    public string Text { get; } = text;

    /// <summary>Where a finding on this text should be reported.</summary>
    public Location Location { get; } = location;

    /// <summary>The part of the MCP surface this text came from.</summary>
    public McpDescriptionTarget Target { get; } = target;
}