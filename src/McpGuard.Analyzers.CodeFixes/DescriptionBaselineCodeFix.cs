using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CodeActions;
using Microsoft.CodeAnalysis.CodeFixes;
using Microsoft.CodeAnalysis.Text;
using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Composition;
using System.IO;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;

namespace McpGuard.Analyzers;

/// <summary>
/// Updates the committed description-integrity baseline (<c>McpGuard.Baseline.txt</c>) so an MCPG013
/// finding is recorded: the offending tool's entry is replaced (or appended if new) with the fingerprint
/// of its current description. Comments and unrelated entries are preserved. The fix edits the baseline
/// additional file, not source. Fix-all populates an empty baseline in one pass.
/// </summary>
[ExportCodeFixProvider(LanguageNames.CSharp, Name = nameof(DescriptionBaselineCodeFix))]
[Shared]
public sealed class DescriptionBaselineCodeFix : CodeFixProvider
{
    // Mirrors McpGuard.Analyzers.DiagnosticIds / BaselineProperties / DescriptionBaseline — the code-fix
    // assembly cannot reference the analyzer assembly (that would be a circular project reference).
    private const string DiagnosticId = "MCPG013";
    private const string IdentityKey = "Identity";
    private const string ExpectedLineKey = "ExpectedLine";
    private const string BaselineFileName = "McpGuard.Baseline.txt";
    private const string Separator = " => ";
    private const string Title = "Update mcp-guard integrity baseline";

    public override ImmutableArray<string> FixableDiagnosticIds { get; } = ImmutableArray.Create(DiagnosticId);

    public override FixAllProvider GetFixAllProvider() => BaselineFixAllProvider.Instance;

    public override Task RegisterCodeFixesAsync(CodeFixContext context)
    {
        Project project = context.Document.Project;
        if (FindBaseline(project) is not { } baseline)
        {
            // Without a baseline additional file there is nothing to edit; the diagnostic message still
            // tells the user the exact line to record once they add one.
            return Task.CompletedTask;
        }

        foreach (Diagnostic diagnostic in context.Diagnostics)
        {
            if (!TryGetUpdate(diagnostic, out KeyValuePair<string, string> update))
            {
                continue;
            }

            DocumentId baselineId = baseline.Id;
            context.RegisterCodeFix(
                CodeAction.Create(
                    Title,
                    cancellationToken => UpdateBaselineAsync(project.Solution, baselineId, new[] { update }, cancellationToken),
                    equivalenceKey: DiagnosticId),
                diagnostic);
        }

        return Task.CompletedTask;
    }

    private static TextDocument? FindBaseline(Project project)
        => project.AdditionalDocuments.FirstOrDefault(static d => IsBaselineName(d));

    private static bool IsBaselineName(TextDocument document)
    {
        string name = !string.IsNullOrEmpty(document.Name)
            ? document.Name
            : (document.FilePath is { } path ? Path.GetFileName(path) : string.Empty);
        return string.Equals(name, BaselineFileName, StringComparison.OrdinalIgnoreCase);
    }

    private static bool TryGetUpdate(Diagnostic diagnostic, out KeyValuePair<string, string> update)
    {
        update = default;
        if (diagnostic.Properties.TryGetValue(IdentityKey, out string? identity) && !string.IsNullOrEmpty(identity)
            && diagnostic.Properties.TryGetValue(ExpectedLineKey, out string? line) && !string.IsNullOrEmpty(line))
        {
            update = new KeyValuePair<string, string>(identity!, line!);
            return true;
        }

        return false;
    }

    private static async Task<Solution> UpdateBaselineAsync(
        Solution solution,
        DocumentId baselineId,
        IReadOnlyList<KeyValuePair<string, string>> updates,
        CancellationToken cancellationToken)
    {
        if (solution.GetAdditionalDocument(baselineId) is not { } baseline)
        {
            return solution;
        }

        SourceText text = await baseline.GetTextAsync(cancellationToken).ConfigureAwait(false);
        string updated = ApplyUpdates(text.ToString(), updates);
        return solution.WithAdditionalDocumentText(baselineId, SourceText.From(updated));
    }

    /// <summary>
    /// Returns the baseline text with each update applied: an existing entry for an identity is replaced
    /// in place, a new identity is appended (sorted), and comments / blank lines / unrelated entries are
    /// preserved. Pure and deterministic so it can be unit-tested directly.
    /// </summary>
    internal static string ApplyUpdates(string baseline, IReadOnlyList<KeyValuePair<string, string>> updates)
    {
        var remaining = new Dictionary<string, string>(StringComparer.Ordinal);
        foreach (KeyValuePair<string, string> update in updates)
        {
            remaining[update.Key] = update.Value;
        }

        var lines = new List<string>();
        foreach (string rawWithCr in (baseline ?? string.Empty).Split('\n'))
        {
            string raw = rawWithCr.TrimEnd('\r');
            string trimmed = raw.Trim();
            if (trimmed.Length > 0 && trimmed[0] != '#')
            {
                int split = trimmed.IndexOf(Separator, StringComparison.Ordinal);
                if (split > 0 && remaining.TryGetValue(trimmed.Substring(0, split).Trim(), out string? replacement))
                {
                    lines.Add(replacement);
                    remaining.Remove(trimmed.Substring(0, split).Trim());
                    continue;
                }
            }

            lines.Add(raw);
        }

        // Drop trailing blank lines — the Split('\n') artifact of the final newline plus any blank lines
        // at EOF — so the file ends in exactly one newline and does not accumulate blanks on every fix.
        while (lines.Count > 0 && lines[lines.Count - 1].Length == 0)
        {
            lines.RemoveAt(lines.Count - 1);
        }

        foreach (KeyValuePair<string, string> appended in remaining.OrderBy(static kv => kv.Key, StringComparer.Ordinal))
        {
            lines.Add(appended.Value);
        }

        return lines.Count == 0 ? string.Empty : string.Join("\n", lines) + "\n";
    }

    // Applies every MCPG013 finding in scope to the relevant project's baseline in a single edit — the
    // natural way to populate a freshly added (empty) baseline.
    private sealed class BaselineFixAllProvider : FixAllProvider
    {
        public static readonly BaselineFixAllProvider Instance = new();

        public override async Task<CodeAction?> GetFixAsync(FixAllContext context)
        {
            var perProject = new List<(Project Project, ImmutableArray<Diagnostic> Diagnostics)>();
            switch (context.Scope)
            {
                case FixAllScope.Document when context.Document is { } document:
                    perProject.Add((context.Project, await context.GetDocumentDiagnosticsAsync(document).ConfigureAwait(false)));
                    break;
                case FixAllScope.Project:
                    perProject.Add((context.Project, await context.GetAllDiagnosticsAsync(context.Project).ConfigureAwait(false)));
                    break;
                case FixAllScope.Solution:
                    foreach (Project project in context.Solution.Projects)
                    {
                        perProject.Add((project, await context.GetAllDiagnosticsAsync(project).ConfigureAwait(false)));
                    }

                    break;
                default:
                    return null;
            }

            Solution solution = context.Solution;
            bool changed = false;
            foreach ((Project project, ImmutableArray<Diagnostic> diagnostics) in perProject)
            {
                List<KeyValuePair<string, string>> updates = CollectUpdates(diagnostics);
                if (updates.Count == 0 || FindBaseline(project) is not { } baseline)
                {
                    continue;
                }

                solution = await UpdateBaselineAsync(solution, baseline.Id, updates, context.CancellationToken).ConfigureAwait(false);
                changed = true;
            }

            if (!changed)
            {
                return null;
            }

            Solution fixedSolution = solution;
            return CodeAction.Create(Title, _ => Task.FromResult(fixedSolution), equivalenceKey: DiagnosticId);
        }

        private static List<KeyValuePair<string, string>> CollectUpdates(ImmutableArray<Diagnostic> diagnostics)
        {
            var map = new Dictionary<string, string>(StringComparer.Ordinal);
            foreach (Diagnostic diagnostic in diagnostics)
            {
                if (TryGetUpdate(diagnostic, out KeyValuePair<string, string> update))
                {
                    map[update.Key] = update.Value;
                }
            }

            return map.ToList();
        }
    }
}