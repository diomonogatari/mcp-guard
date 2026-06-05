using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp;
using Microsoft.CodeAnalysis.CSharp.Syntax;
using Microsoft.CodeAnalysis.Diagnostics;
using System;
using System.Collections.Immutable;
using System.Linq;
using System.Threading;

namespace McpGuard.Analyzers;

/// <summary>
/// Flags prompt-injection / tool-poisoning phrasing inside the <c>[Description]</c> text of MCP tools —
/// the strings an LLM consumes as instructions. Only descriptions that are part of the MCP tool surface
/// (a method carrying <c>[McpServerTool]</c>, one of its parameters, or a type carrying
/// <c>[McpServerToolType]</c>) are inspected, so ordinary <c>[Description]</c> usage is never flagged.
/// </summary>
[DiagnosticAnalyzer(LanguageNames.CSharp)]
public sealed class McpToolDescriptionAnalyzer : DiagnosticAnalyzer
{
    private static readonly ImmutableHashSet<string> ToolAttributeNames =
        ImmutableHashSet.Create(StringComparer.Ordinal, "McpServerTool", "McpServerToolAttribute");

    private static readonly ImmutableHashSet<string> ToolTypeAttributeNames =
        ImmutableHashSet.Create(StringComparer.Ordinal, "McpServerToolType", "McpServerToolTypeAttribute");

    private static readonly ImmutableHashSet<string> DescriptionAttributeNames =
        ImmutableHashSet.Create(StringComparer.Ordinal, "Description", "DescriptionAttribute");

    public override ImmutableArray<DiagnosticDescriptor> SupportedDiagnostics => Rules.All;

    public override void Initialize(AnalysisContext context)
    {
        context.EnableConcurrentExecution();
        context.ConfigureGeneratedCodeAnalysis(GeneratedCodeAnalysisFlags.None);
        context.RegisterSyntaxNodeAction(AnalyzeDescriptionAttribute, SyntaxKind.Attribute);
    }

    private static void AnalyzeDescriptionAttribute(SyntaxNodeAnalysisContext context)
    {
        var attribute = (AttributeSyntax)context.Node;

        if (!DescriptionAttributeNames.Contains(GetSimpleName(attribute.Name)))
        {
            return;
        }

        if (!IsOnMcpToolSurface(attribute))
        {
            return;
        }

        if (!TryGetDescriptionText(attribute, context.SemanticModel, context.CancellationToken, out string text, out Location location))
        {
            return;
        }

        if (ToolDescriptionPhrases.TryFindInjectionPhrase(text, out string match))
        {
            context.ReportDiagnostic(Diagnostic.Create(Rules.PromptInjection, location, match));
        }
    }

    // True when the [Description] annotates an MCP tool method, a parameter of one, or an MCP tool type.
    private static bool IsOnMcpToolSurface(AttributeSyntax attribute)
    {
        if (attribute.Parent is not AttributeListSyntax list)
        {
            return false;
        }

        switch (list.Parent)
        {
            case MethodDeclarationSyntax method:
                return HasAttribute(method.AttributeLists, ToolAttributeNames);
            case ParameterSyntax parameter when parameter.FirstAncestorOrSelf<BaseMethodDeclarationSyntax>() is { } owner:
                return HasAttribute(owner.AttributeLists, ToolAttributeNames);
            case TypeDeclarationSyntax type:
                return HasAttribute(type.AttributeLists, ToolTypeAttributeNames);
            default:
                return false;
        }
    }

    private static bool HasAttribute(SyntaxList<AttributeListSyntax> attributeLists, ImmutableHashSet<string> names)
        => attributeLists.SelectMany(static l => l.Attributes).Any(a => names.Contains(GetSimpleName(a.Name)));

    // Pulls the compile-time-constant description text out of the first positional argument. Using the
    // semantic model's constant value keeps us robust to verbatim strings and const concatenation.
    // (Interpolated strings are not C# constants and are deferred to the Phase 1 string engine.)
    private static bool TryGetDescriptionText(AttributeSyntax attribute, SemanticModel semanticModel, CancellationToken cancellationToken, out string text, out Location location)
    {
        text = string.Empty;
        location = Location.None;

        AttributeArgumentSyntax? argument = attribute.ArgumentList?.Arguments
            .FirstOrDefault(static a => a.NameEquals is null && a.NameColon is null);
        if (argument is null)
        {
            return false;
        }

        Optional<object?> constant = semanticModel.GetConstantValue(argument.Expression, cancellationToken);
        if (!constant.HasValue || constant.Value is not string value)
        {
            return false;
        }

        text = value;
        location = argument.Expression.GetLocation();
        return true;
    }

    private static string GetSimpleName(NameSyntax name) => name switch
    {
        QualifiedNameSyntax qualified => qualified.Right.Identifier.ValueText,
        SimpleNameSyntax simple => simple.Identifier.ValueText,
        _ => name.ToString(),
    };
}