using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp.Syntax;
using Microsoft.CodeAnalysis.Text;
using System;

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
/// An extracted MCP surface string: the text the model reads, the literal it came from (so findings
/// can be reported at the precise offending span), and which part of the surface it is.
/// </summary>
internal readonly struct McpDescription(string text, ExpressionSyntax expression, McpDescriptionTarget target)
{
    /// <summary>The text, as the model would read it.</summary>
    public string Text { get; } = text;

    /// <summary>The part of the MCP surface this text came from.</summary>
    public McpDescriptionTarget Target { get; } = target;

    private ExpressionSyntax Expression { get; } = expression;

    /// <summary>The whole string-literal location — used when a finding cannot be pinpointed.</summary>
    public Location Location => Expression.GetLocation();

    /// <summary>
    /// Best-effort precise location for a finding: the span of <paramref name="rawMatch"/> within the
    /// literal's source text, or the whole literal if it is not a verbatim substring (e.g. a phrase
    /// that only matches after whitespace normalization).
    /// </summary>
    public Location LocationOf(string rawMatch)
    {
        if (!string.IsNullOrEmpty(rawMatch))
        {
            string source = Expression.ToString();
            int index = source.IndexOf(rawMatch, StringComparison.OrdinalIgnoreCase);
            if (index >= 0)
            {
                return Location.Create(Expression.SyntaxTree, new TextSpan(Expression.SpanStart + index, rawMatch.Length));
            }
        }

        return Location;
    }
}