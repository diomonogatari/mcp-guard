using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp.Syntax;
using System.Linq;
using System.Threading;

namespace McpGuard.Analyzers;

/// <summary>
/// Pulls the model-visible strings out of MCP attributes — the <c>[Description(...)]</c> text and the
/// <c>Name = "..."</c> of an MCP member attribute. Attribute arguments are compile-time constants, so
/// the semantic model's constant value covers plain, verbatim, and raw string literals plus
/// <c>const</c> concatenation. (Interpolated strings are not constants and cannot appear in an
/// attribute, so there is no interpolation case to handle.)
/// </summary>
internal static class McpDescriptionExtractor
{
    /// <summary>Extracts the text of a <c>[Description(...)]</c> attribute.</summary>
    public static bool TryGetDescription(
        AttributeSyntax descriptionAttribute,
        SemanticModel semanticModel,
        McpDescriptionTarget target,
        CancellationToken cancellationToken,
        out McpDescription description)
    {
        description = default;

        AttributeArgumentSyntax? argument = descriptionAttribute.ArgumentList?.Arguments
            .FirstOrDefault(static a => a.NameEquals is null && a.NameColon is null);

        return argument is not null
            && TryBuild(argument.Expression, semanticModel, target, cancellationToken, out description);
    }

    /// <summary>Extracts the <c>Name = "..."</c> argument of an MCP member attribute, if present.</summary>
    public static bool TryGetToolName(
        AttributeSyntax memberAttribute,
        SemanticModel semanticModel,
        CancellationToken cancellationToken,
        out McpDescription name)
    {
        name = default;

        AttributeArgumentSyntax? argument = memberAttribute.ArgumentList?.Arguments
            .FirstOrDefault(static a => a.NameEquals is { } nameEquals && nameEquals.Name.Identifier.ValueText == "Name");

        return argument is not null
            && TryBuild(argument.Expression, semanticModel, McpDescriptionTarget.Name, cancellationToken, out name);
    }

    private static bool TryBuild(
        ExpressionSyntax expression,
        SemanticModel semanticModel,
        McpDescriptionTarget target,
        CancellationToken cancellationToken,
        out McpDescription description)
    {
        description = default;

        Optional<object?> constant = semanticModel.GetConstantValue(expression, cancellationToken);
        if (!constant.HasValue || constant.Value is not string text)
        {
            return false;
        }

        description = McpDescription.FromExpression(text, expression, target);
        return true;
    }
}