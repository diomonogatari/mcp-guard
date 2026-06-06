using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CodeActions;
using Microsoft.CodeAnalysis.CodeFixes;
using Microsoft.CodeAnalysis.CSharp;
using Microsoft.CodeAnalysis.CSharp.Syntax;
using System;
using System.Collections.Immutable;
using System.Composition;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;

namespace McpGuard.Analyzers;

/// <summary>
/// Safe, mechanical fixes that clean an MCP description literal: strip hidden characters (MCPG002),
/// remove ANSI escape sequences (MCPG005), and collapse off-screen whitespace padding (MCPG010).
/// </summary>
[ExportCodeFixProvider(LanguageNames.CSharp, Name = nameof(DescriptionSanitizerCodeFix))]
[Shared]
public sealed class DescriptionSanitizerCodeFix : CodeFixProvider
{
    public override ImmutableArray<string> FixableDiagnosticIds { get; } =
        ImmutableArray.Create("MCPG002", "MCPG005", "MCPG010");

    public override FixAllProvider GetFixAllProvider() => WellKnownFixAllProviders.BatchFixer;

    public override async Task RegisterCodeFixesAsync(CodeFixContext context)
    {
        SyntaxNode? root = await context.Document.GetSyntaxRootAsync(context.CancellationToken).ConfigureAwait(false);
        if (root is null)
        {
            return;
        }

        foreach (Diagnostic diagnostic in context.Diagnostics)
        {
            SyntaxNode node = root.FindNode(diagnostic.Location.SourceSpan, getInnermostNodeForTie: true);
            LiteralExpressionSyntax? literal =
                node.FirstAncestorOrSelf<LiteralExpressionSyntax>(static l => l.IsKind(SyntaxKind.StringLiteralExpression))
                ?? node.DescendantNodesAndSelf().OfType<LiteralExpressionSyntax>().FirstOrDefault(static l => l.IsKind(SyntaxKind.StringLiteralExpression));

            if (literal is null || literal.Token.Value is not string current)
            {
                continue;
            }

            string cleaned = Clean(diagnostic.Id, current);
            if (string.Equals(cleaned, current, StringComparison.Ordinal))
            {
                continue;
            }

            LiteralExpressionSyntax target = literal;
            context.RegisterCodeFix(
                CodeAction.Create(
                    TitleFor(diagnostic.Id),
                    cancellationToken => ReplaceAsync(context.Document, target, cleaned, cancellationToken),
                    equivalenceKey: diagnostic.Id),
                diagnostic);
        }
    }

    private static string Clean(string diagnosticId, string text) => diagnosticId switch
    {
        "MCPG002" => DescriptionSanitizer.RemoveHidden(text),
        "MCPG005" => DescriptionSanitizer.RemoveAnsi(text),
        "MCPG010" => DescriptionSanitizer.CollapseWhitespacePadding(text),
        _ => text,
    };

    private static string TitleFor(string diagnosticId) => diagnosticId switch
    {
        "MCPG002" => "Remove hidden characters",
        "MCPG005" => "Remove the terminal escape sequence",
        "MCPG010" => "Collapse the whitespace padding",
        _ => "Clean the description",
    };

    private static async Task<Document> ReplaceAsync(Document document, LiteralExpressionSyntax literal, string cleaned, CancellationToken cancellationToken)
    {
        SyntaxNode root = (await document.GetSyntaxRootAsync(cancellationToken).ConfigureAwait(false))!;
        LiteralExpressionSyntax replacement = SyntaxFactory
            .LiteralExpression(SyntaxKind.StringLiteralExpression, SyntaxFactory.Literal(cleaned))
            .WithTriviaFrom(literal);

        return document.WithSyntaxRoot(root.ReplaceNode(literal, replacement));
    }
}