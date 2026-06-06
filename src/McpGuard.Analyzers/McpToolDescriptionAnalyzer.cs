using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp;
using Microsoft.CodeAnalysis.CSharp.Syntax;
using Microsoft.CodeAnalysis.Diagnostics;
using System;
using System.Collections.Concurrent;
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
    // Held by reference so the encoded-blob escalation (G2) can reuse their MCPG003/MCPG004 descriptors
    // when a payload is found only after decoding an embedded blob.
    private static readonly SecretReferenceRule SecretRule = new();
    private static readonly ExfiltrationRule SinkRule = new();

    private static readonly ImmutableArray<McpDescriptionRule> RuleSet =
        ImmutableArray.Create<McpDescriptionRule>(
            new PromptInjectionRule(),
            new HiddenTextRule(),
            SecretRule,
            SinkRule,
            new AnsiEscapeRule(),
            new ManipulativePhrasingRule(),
            new EmbeddedMarkupRule(),
            new CrossToolReferenceRule(),
            new WhitespacePaddingRule(),
            new EncodedBlobRule(),
            new CapabilityMismatchRule());

    // Escalation: a secret reference (MCPG003) plus an external sink (MCPG004) on the same description
    // is no longer a heuristic — it is a working exfiltration payload, reported at Error.
    private static readonly DiagnosticDescriptor ConfirmedExfiltration = new(
        id: DiagnosticIds.ConfirmedExfiltrationInDescription,
        title: "MCP tool description is a confirmed data-exfiltration payload",
        messageFormat: "MCP tool description both references a secret and routes data to an external destination; this is a confirmed data-exfiltration payload and must be removed",
        category: RuleMetadata.SecurityCategory,
        defaultSeverity: DiagnosticSeverity.Error,
        isEnabledByDefault: true,
        description: "When a single description triggers both MCPG003 (a secret-file reference) and MCPG004 (an external sink), the combination is a working data-exfiltration payload, not a heuristic. mcp-guard escalates it to an error.",
        helpLinkUri: RuleMetadata.HelpUri(DiagnosticIds.ConfirmedExfiltrationInDescription));

    // Description-integrity baseline (rug-pull guard): when a committed baseline pins a tool's
    // description, any later edit to the exact model-visible text drifts from the pinned fingerprint.
    // Dormant unless the consumer adds a McpGuard.Baseline.txt to AdditionalFiles.
    private static readonly DiagnosticDescriptor DescriptionBaselineDrift = new(
        id: DiagnosticIds.DescriptionBaselineDrift,
        title: "MCP tool description does not match the integrity baseline",
        messageFormat: "MCP tool description for '{0}' does not match the pinned integrity baseline; review the change, then update the baseline entry to '{1}'",
        category: RuleMetadata.SecurityCategory,
        defaultSeverity: DiagnosticSeverity.Warning,
        isEnabledByDefault: true,
        description: "A description-integrity baseline pins each MCP tool's model-visible description to a fingerprint committed to source. A rug-pull changes a description after it was approved; this diagnostic makes any such change a reviewable, build-breakable event instead of a silent edit. The feature is opt-in: it is inert until a McpGuard.Baseline.txt is added to the project's AdditionalFiles.",
        helpLinkUri: RuleMetadata.HelpUri(DiagnosticIds.DescriptionBaselineDrift));

    private static readonly ImmutableArray<DiagnosticDescriptor> Descriptors =
        RuleSet.Select(static rule => rule.Descriptor)
            .Append(ConfirmedExfiltration)
            .Append(DescriptionBaselineDrift)
            .ToImmutableArray();

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
        context.RegisterCompilationStartAction(static start =>
        {
            DescriptionBaseline baseline = DescriptionBaseline.Load(start.Options.AdditionalFiles, start.CancellationToken);
            // Each enum used as a tool parameter type is scanned once per compilation, no matter how many
            // tools share it, so its members are not reported twice.
            var scannedEnums = new ConcurrentDictionary<ITypeSymbol, byte>(SymbolEqualityComparer.Default);
            start.RegisterSyntaxNodeAction(ctx => AnalyzeAttribute(ctx, baseline, scannedEnums), SyntaxKind.Attribute);
        });
    }

    private static void AnalyzeAttribute(
        SyntaxNodeAnalysisContext context,
        DescriptionBaseline baseline,
        ConcurrentDictionary<ITypeSymbol, byte> scannedEnums)
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

                if (target == McpDescriptionTarget.Member && baseline.IsActive)
                {
                    CheckBaseline(in description, attribute, baseline, context);
                }
            }

            return;
        }

        // An MCP member attribute: the Name = "..." is model-visible, and so are the names of its
        // parameters (JSON-schema property keys) and any enum-typed parameter's members.
        if (McpMemberAttributeNames.Contains(name))
        {
            if (McpDescriptionExtractor.TryGetToolName(attribute, context.SemanticModel, context.CancellationToken, out McpDescription toolName))
            {
                RunRules(in toolName, context);
            }

            ScanMemberNames(attribute, context, scannedEnums);
        }
    }

    // Scans the identifier names the model also sees for an MCP member: each parameter name, and the
    // member names of any enum used as a parameter type.
    private static void ScanMemberNames(
        AttributeSyntax memberAttribute,
        SyntaxNodeAnalysisContext context,
        ConcurrentDictionary<ITypeSymbol, byte> scannedEnums)
    {
        if (memberAttribute.Parent is not AttributeListSyntax { Parent: MethodDeclarationSyntax method })
        {
            return;
        }

        foreach (ParameterSyntax parameter in method.ParameterList.Parameters)
        {
            McpDescription paramName = McpDescription.FromToken(parameter.Identifier, McpDescriptionTarget.ParameterName);
            ScanName(in paramName, context);

            if (context.SemanticModel.GetDeclaredSymbol(parameter, context.CancellationToken) is { Type: { TypeKind: TypeKind.Enum } enumType }
                && scannedEnums.TryAdd(enumType, 0))
            {
                ScanEnumMemberNames(enumType, context);
            }
        }
    }

    private static void ScanEnumMemberNames(ITypeSymbol enumType, SyntaxNodeAnalysisContext context)
    {
        foreach (ISymbol member in enumType.GetMembers())
        {
            if (member is not IFieldSymbol { IsConst: true } field)
            {
                continue;
            }

            foreach (SyntaxReference reference in field.DeclaringSyntaxReferences)
            {
                if (reference.GetSyntax(context.CancellationToken) is EnumMemberDeclarationSyntax declaration)
                {
                    McpDescription memberName = McpDescription.FromToken(declaration.Identifier, McpDescriptionTarget.EnumMemberName);
                    ScanName(in memberName, context);
                }
            }
        }
    }

    // A parameter/enum-member name is a high false-positive surface — it legitimately uses artifact-like
    // tokens as documentation — so it is NOT run through the full rule set. Only a secret-file reference
    // that reads as a directive (artifact + an access verb) is flagged, via the MCPG003 descriptor.
    private static void ScanName(in McpDescription name, SyntaxNodeAnalysisContext context)
    {
        if (SuspiciousNames.TryFindSecretDirective(name.Text, out string artifact))
        {
            context.ReportDiagnostic(Diagnostic.Create(SecretRule.Descriptor, name.LocationOf(artifact), artifact));
        }
    }

    private static void RunRules(in McpDescription description, SyntaxNodeAnalysisContext context)
    {
        foreach (McpDescriptionRule rule in RuleSet)
        {
            rule.Analyze(in description, context);
        }

        string text = description.Text;
        bool secret = SecretArtifacts.TryFind(text, out _);
        bool sink = ExfiltrationCues.TryFindSink(text, out _);

        // A secret reference or exfil sink can be hidden inside an encoded blob (the blob alone is only
        // MCPG011 Info). Decode it and re-scan; a hit is reported with the MCPG003/MCPG004 descriptor at
        // the blob and counts toward the escalation below.
        if (EncodedBlob.TryFind(text, out string blob) && EncodedBlob.TryDecode(blob, out string decoded))
        {
            if (!secret && SecretArtifacts.TryFind(decoded, out string secretMatch))
            {
                secret = true;
                context.ReportDiagnostic(Diagnostic.Create(SecretRule.Descriptor, description.LocationOf(blob), secretMatch));
            }

            if (!sink && ExfiltrationCues.TryFindSink(decoded, includeShellFetchVerbs: true, out string channel))
            {
                sink = true;
                context.ReportDiagnostic(Diagnostic.Create(SinkRule.Descriptor, description.LocationOf(blob), channel));
            }
        }

        // Multi-signal escalation: a secret reference plus an external sink is a confirmed payload.
        if (secret && sink)
        {
            context.ReportDiagnostic(Diagnostic.Create(ConfirmedExfiltration, description.Location));
        }
    }

    // Compares a member's [Description] against the committed integrity baseline and reports drift.
    private static void CheckBaseline(
        in McpDescription description,
        AttributeSyntax attribute,
        DescriptionBaseline baseline,
        SyntaxNodeAnalysisContext context)
    {
        if (attribute.Parent is not AttributeListSyntax { Parent: MethodDeclarationSyntax method }
            || context.SemanticModel.GetDeclaredSymbol(method, context.CancellationToken) is not { } symbol)
        {
            return;
        }

        string identity = DescriptionBaseline.IdentityFor(symbol);
        if (baseline.Check(identity, description.Text, out string expectedLine) == BaselineStatus.Match)
        {
            return;
        }

        // Carry the identity and expected line so the code fix can update the baseline file in place.
        ImmutableDictionary<string, string?> properties = ImmutableDictionary<string, string?>.Empty
            .Add(BaselineProperties.Identity, identity)
            .Add(BaselineProperties.ExpectedLine, expectedLine);

        context.ReportDiagnostic(Diagnostic.Create(
            DescriptionBaselineDrift, description.Location, properties, identity, expectedLine));
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