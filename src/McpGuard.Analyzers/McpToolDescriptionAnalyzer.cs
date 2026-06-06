using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp;
using Microsoft.CodeAnalysis.CSharp.Syntax;
using Microsoft.CodeAnalysis.Diagnostics;
using System;
using System.Collections.Immutable;
using System.Linq;

namespace McpGuard.Analyzers;

/// <summary>
/// Inspects the strings an LLM reads from an MCP server — the <c>[Description]</c> text on
/// <c>[McpServerTool]</c> / <c>[McpServerPrompt]</c> / <c>[McpServerResource]</c> members, their
/// parameters, and <c>[McpServer*Type]</c> types, plus the <c>Name = "..."</c> of those members — and
/// runs the registered <see cref="McpDescriptionRule"/> set over each. Ordinary <c>[Description]</c>
/// usage outside the MCP surface is never flagged.
/// </summary>
[DiagnosticAnalyzer(LanguageNames.CSharp)]
public sealed class McpToolDescriptionAnalyzer : DiagnosticAnalyzer
{
    private static readonly ImmutableArray<McpDescriptionRule> RuleSet =
        ImmutableArray.Create<McpDescriptionRule>(
            new PromptInjectionRule(),
            new HiddenTextRule(),
            new SecretReferenceRule(),
            new ExfiltrationRule(),
            new AnsiEscapeRule(),
            new ManipulativePhrasingRule(),
            new EmbeddedMarkupRule(),
            new CrossToolReferenceRule(),
            new WhitespacePaddingRule(),
            new EncodedBlobRule(),
            new CapabilityMismatchRule());

    private static readonly ImmutableArray<DiagnosticDescriptor> Descriptors =
        RuleSet.Select(static rule => rule.Descriptor).ToImmutableArray();

    // Member-level MCP attributes whose [Description] (and Name) the model reads.
    private static readonly ImmutableHashSet<string> McpMemberAttributeNames =
        ImmutableHashSet.Create(
            StringComparer.Ordinal,
            "McpServerTool", "McpServerToolAttribute",
            "McpServerPrompt", "McpServerPromptAttribute",
            "McpServerResource", "McpServerResourceAttribute");

    private static readonly ImmutableHashSet<string> McpTypeAttributeNames =
        ImmutableHashSet.Create(
            StringComparer.Ordinal,
            "McpServerToolType", "McpServerToolTypeAttribute",
            "McpServerPromptType", "McpServerPromptTypeAttribute",
            "McpServerResourceType", "McpServerResourceTypeAttribute");

    private static readonly ImmutableHashSet<string> DescriptionAttributeNames =
        ImmutableHashSet.Create(StringComparer.Ordinal, "Description", "DescriptionAttribute");

    public override ImmutableArray<DiagnosticDescriptor> SupportedDiagnostics => Descriptors;

    public override void Initialize(AnalysisContext context)
    {
        context.EnableConcurrentExecution();
        context.ConfigureGeneratedCodeAnalysis(GeneratedCodeAnalysisFlags.None);
        context.RegisterSyntaxNodeAction(AnalyzeAttribute, SyntaxKind.Attribute);
    }

    private static void AnalyzeAttribute(SyntaxNodeAnalysisContext context)
    {
        var attribute = (AttributeSyntax)context.Node;
        string name = GetSimpleName(attribute.Name);

        // [Description] on the MCP surface (member, parameter, or type).
        if (DescriptionAttributeNames.Contains(name))
        {
            if (GetSurfaceTarget(attribute) is { } target
                && McpDescriptionExtractor.TryGetDescription(attribute, context.SemanticModel, target, context.CancellationToken, out McpDescription description))
            {
                RunRules(in description, context);
            }

            return;
        }

        // The Name = "..." of an MCP member attribute is also model-visible.
        if (McpMemberAttributeNames.Contains(name)
            && McpDescriptionExtractor.TryGetToolName(attribute, context.SemanticModel, context.CancellationToken, out McpDescription toolName))
        {
            RunRules(in toolName, context);
        }
    }

    private static void RunRules(in McpDescription description, SyntaxNodeAnalysisContext context)
    {
        foreach (McpDescriptionRule rule in RuleSet)
        {
            rule.Analyze(in description, context);
        }
    }

    // Which part of the MCP surface the [Description] annotates, or null if it is ordinary usage.
    private static McpDescriptionTarget? GetSurfaceTarget(AttributeSyntax attribute)
    {
        if (attribute.Parent is not AttributeListSyntax list)
        {
            return null;
        }

        switch (list.Parent)
        {
            case MethodDeclarationSyntax method:
                return HasAttribute(method.AttributeLists, McpMemberAttributeNames) ? McpDescriptionTarget.Member : null;
            case ParameterSyntax parameter when parameter.FirstAncestorOrSelf<BaseMethodDeclarationSyntax>() is { } owner:
                return HasAttribute(owner.AttributeLists, McpMemberAttributeNames) ? McpDescriptionTarget.Parameter : null;
            case TypeDeclarationSyntax type:
                return HasAttribute(type.AttributeLists, McpTypeAttributeNames) ? McpDescriptionTarget.Type : null;
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