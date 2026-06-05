using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp;
using Microsoft.CodeAnalysis.CSharp.Syntax;
using Microsoft.CodeAnalysis.Diagnostics;
using System;
using System.Collections.Immutable;
using System.Linq;

namespace McpGuard.Analyzers;

/// <summary>
/// Inspects the <c>[Description]</c> text of MCP tools — the strings an LLM consumes as instructions
/// — and runs the registered <see cref="McpDescriptionRule"/> set over each one. Only descriptions
/// on the MCP tool surface (a method carrying <c>[McpServerTool]</c>, one of its parameters, or a
/// type carrying <c>[McpServerToolType]</c>) are inspected, so ordinary <c>[Description]</c> usage
/// is never flagged.
/// </summary>
[DiagnosticAnalyzer(LanguageNames.CSharp)]
public sealed class McpToolDescriptionAnalyzer : DiagnosticAnalyzer
{
    private static readonly ImmutableArray<McpDescriptionRule> RuleSet =
        ImmutableArray.Create<McpDescriptionRule>(
            new PromptInjectionRule(),
            new HiddenTextRule(),
            new SecretReferenceRule());

    private static readonly ImmutableArray<DiagnosticDescriptor> Descriptors =
        RuleSet.Select(static rule => rule.Descriptor).ToImmutableArray();

    private static readonly ImmutableHashSet<string> ToolAttributeNames =
        ImmutableHashSet.Create(StringComparer.Ordinal, "McpServerTool", "McpServerToolAttribute");

    private static readonly ImmutableHashSet<string> ToolTypeAttributeNames =
        ImmutableHashSet.Create(StringComparer.Ordinal, "McpServerToolType", "McpServerToolTypeAttribute");

    private static readonly ImmutableHashSet<string> DescriptionAttributeNames =
        ImmutableHashSet.Create(StringComparer.Ordinal, "Description", "DescriptionAttribute");

    public override ImmutableArray<DiagnosticDescriptor> SupportedDiagnostics => Descriptors;

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

        if (GetMcpToolSurfaceTarget(attribute) is not { } target)
        {
            return;
        }

        if (!McpDescriptionExtractor.TryExtract(attribute, context.SemanticModel, target, context.CancellationToken, out McpDescription description))
        {
            return;
        }

        foreach (McpDescriptionRule rule in RuleSet)
        {
            rule.Analyze(in description, context);
        }
    }

    // Returns which part of the MCP tool surface the [Description] annotates, or null if it is not
    // part of the surface an LLM reads (so ordinary [Description] usage is never flagged).
    private static McpDescriptionTarget? GetMcpToolSurfaceTarget(AttributeSyntax attribute)
    {
        if (attribute.Parent is not AttributeListSyntax list)
        {
            return null;
        }

        switch (list.Parent)
        {
            case MethodDeclarationSyntax method:
                return HasAttribute(method.AttributeLists, ToolAttributeNames) ? McpDescriptionTarget.Tool : null;
            case ParameterSyntax parameter when parameter.FirstAncestorOrSelf<BaseMethodDeclarationSyntax>() is { } owner:
                return HasAttribute(owner.AttributeLists, ToolAttributeNames) ? McpDescriptionTarget.Parameter : null;
            case TypeDeclarationSyntax type:
                return HasAttribute(type.AttributeLists, ToolTypeAttributeNames) ? McpDescriptionTarget.ToolType : null;
            default:
                return null;
        }
    }

    private static bool HasAttribute(SyntaxList<AttributeListSyntax> attributeLists, ImmutableHashSet<string> names)
        => attributeLists.SelectMany(static l => l.Attributes).Any(a => names.Contains(GetSimpleName(a.Name)));

    private static string GetSimpleName(NameSyntax name) => name switch
    {
        QualifiedNameSyntax qualified => qualified.Right.Identifier.ValueText,
        SimpleNameSyntax simple => simple.Identifier.ValueText,
        _ => name.ToString(),
    };
}