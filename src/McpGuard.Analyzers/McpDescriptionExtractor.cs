using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp.Syntax;
using System.Linq;
using System.Threading;

namespace McpGuard.Analyzers;

/// <summary>
/// Pulls the description text out of a <c>[Description(...)]</c> argument. Attribute arguments must
/// be compile-time constants, so the semantic model's constant value covers every legal form —
/// plain, verbatim, and raw string literals, plus <c>const</c> concatenation. (Interpolated strings
/// are not constants and cannot appear in an attribute, so there is no interpolation case to handle.)
/// </summary>
internal static class McpDescriptionExtractor
{
    public static bool TryExtract(
        AttributeSyntax descriptionAttribute,
        SemanticModel semanticModel,
        McpDescriptionTarget target,
        CancellationToken cancellationToken,
        out McpDescription description)
    {
        description = default;

        AttributeArgumentSyntax? argument = descriptionAttribute.ArgumentList?.Arguments
            .FirstOrDefault(static a => a.NameEquals is null && a.NameColon is null);
        if (argument is null)
        {
            return false;
        }

        Optional<object?> constant = semanticModel.GetConstantValue(argument.Expression, cancellationToken);
        if (!constant.HasValue || constant.Value is not string text)
        {
            return false;
        }

        description = new McpDescription(text, argument.Expression.GetLocation(), target);
        return true;
    }
}