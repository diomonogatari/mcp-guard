using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.Diagnostics;

namespace McpGuard.Analyzers;

/// <summary>MCPG011 — a long encoded (base64/hex) blob inside an MCP tool description. Info-level.</summary>
internal sealed class EncodedBlobRule : McpDescriptionRule
{
    private static readonly DiagnosticDescriptor Rule = new(
        id: DiagnosticIds.EncodedBlobInDescription,
        title: "MCP tool description contains an encoded blob",
        messageFormat: "MCP tool description contains a {0}-character base64/hex blob; encoded blobs are an obfuscation channel — verify it is not a hidden payload",
        category: RuleMetadata.SecurityCategory,
        defaultSeverity: DiagnosticSeverity.Info,
        isEnabledByDefault: true,
        description: "A long contiguous run of base64 / hex characters in a description can carry an obfuscated payload. This is advisory (Info) because hashes and long tokens can look the same; review the blob and remove it if it is not legitimate.",
        helpLinkUri: RuleMetadata.HelpUri(DiagnosticIds.EncodedBlobInDescription));

    public override DiagnosticDescriptor Descriptor => Rule;

    public override void Analyze(in McpDescription description, SyntaxNodeAnalysisContext context)
    {
        if (EncodedBlob.TryFind(description.Text, out string blob))
        {
            context.ReportDiagnostic(Diagnostic.Create(Rule, description.LocationOf(blob), blob.Length));
        }
    }
}