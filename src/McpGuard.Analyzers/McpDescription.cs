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

    /// <summary>The identifier name of a parameter of an MCP member method (a JSON-schema property key).</summary>
    ParameterName,

    /// <summary>The identifier name of a member of an enum used as an MCP tool parameter type.</summary>
    EnumMemberName,
}

/// <summary>
/// An extracted MCP surface string: the text the model reads, the source span it came from (so findings
/// can be reported at the precise offending substring), and which part of the surface it is. The source
/// can be a string-literal expression (a <c>[Description]</c> / <c>Name=</c> value) or an identifier
/// token (a parameter or enum-member name).
/// </summary>
internal readonly struct McpDescription
{
    private readonly Location _location;
    private readonly SyntaxTree? _tree;
    private readonly int _spanStart;
    private readonly string _source;

    private McpDescription(string text, McpDescriptionTarget target, Location location, SyntaxTree? tree, int spanStart, string source)
    {
        Text = text;
        Target = target;
        _location = location;
        _tree = tree;
        _spanStart = spanStart;
        _source = source;
    }

    /// <summary>The text, as the model would read it.</summary>
    public string Text { get; }

    /// <summary>The part of the MCP surface this text came from.</summary>
    public McpDescriptionTarget Target { get; }

    /// <summary>Builds a description from a string-literal expression (a [Description] / Name= value).</summary>
    public static McpDescription FromExpression(string text, ExpressionSyntax expression, McpDescriptionTarget target)
        => new(text, target, expression.GetLocation(), expression.SyntaxTree, expression.SpanStart, expression.ToString());

    /// <summary>Builds a description from an identifier token (a parameter or enum-member name).</summary>
    public static McpDescription FromToken(SyntaxToken token, McpDescriptionTarget target)
        => new(token.ValueText, target, token.GetLocation(), token.SyntaxTree, token.SpanStart, token.Text);

    /// <summary>The whole source-span location — used when a finding cannot be pinpointed.</summary>
    public Location Location => _location;

    /// <summary>
    /// Best-effort precise location for a finding: the span of <paramref name="rawMatch"/> within the
    /// source text, or the whole span if it is not a verbatim substring (e.g. a phrase that only matches
    /// after whitespace normalization, or content found only after decoding an embedded blob).
    /// </summary>
    public Location LocationOf(string rawMatch)
    {
        if (!string.IsNullOrEmpty(rawMatch) && _tree is not null)
        {
            int index = _source.IndexOf(rawMatch, StringComparison.OrdinalIgnoreCase);
            if (index >= 0)
            {
                return Location.Create(_tree, new TextSpan(_spanStart + index, rawMatch.Length));
            }
        }

        return _location;
    }
}