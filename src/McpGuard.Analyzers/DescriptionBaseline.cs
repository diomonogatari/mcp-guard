using Microsoft.CodeAnalysis;
using System;
using System.Collections.Immutable;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading;

namespace McpGuard.Analyzers;

/// <summary>How an MCP tool description compares to the committed integrity baseline.</summary>
internal enum BaselineStatus
{
    /// <summary>The description's fingerprint matches the pinned one — no drift.</summary>
    Match,

    /// <summary>The identity is pinned but its fingerprint changed since — a rug-pull-style edit.</summary>
    Drifted,

    /// <summary>The identity is not pinned yet — a new tool description the baseline does not record.</summary>
    Unpinned,
}

/// <summary>
/// The committed description-integrity baseline (MCPG013). A consumer opts in by adding a
/// <c>McpGuard.Baseline.txt</c> to the project's <c>AdditionalFiles</c>; each line pins one MCP tool
/// member's description to a fingerprint of the exact model-visible text:
/// <code>Namespace.Type.Member =&gt; &lt;hash&gt;</code>
/// Blank lines and <c>#</c> comments are ignored. When no baseline file is present the feature is
/// dormant (<see cref="IsActive"/> is <see langword="false"/>) and never reports — it is pure opt-in.
/// The fingerprint is over the <b>raw</b> text, so even an invisible-character edit trips drift.
/// </summary>
internal sealed class DescriptionBaseline
{
    /// <summary>The conventional baseline file name a project lists under <c>AdditionalFiles</c>.</summary>
    public const string FileName = "McpGuard.Baseline.txt";

    /// <summary>Separator between an identity and its fingerprint on a baseline line.</summary>
    public const string Separator = " => ";

    private static readonly DescriptionBaseline Inactive = new(isActive: false, ImmutableDictionary<string, string>.Empty);

    private static readonly SymbolDisplayFormat IdentityFormat = new(
        typeQualificationStyle: SymbolDisplayTypeQualificationStyle.NameAndContainingTypesAndNamespaces,
        memberOptions: SymbolDisplayMemberOptions.IncludeContainingType);

    private readonly ImmutableDictionary<string, string> _pinned;

    private DescriptionBaseline(bool isActive, ImmutableDictionary<string, string> pinned)
    {
        IsActive = isActive;
        _pinned = pinned;
    }

    /// <summary>True when a baseline file is present, i.e. the consumer has opted into MCPG013.</summary>
    public bool IsActive { get; }

    /// <summary>Loads the baseline from the project's additional files, or returns the dormant instance.</summary>
    public static DescriptionBaseline Load(ImmutableArray<AdditionalText> additionalFiles, CancellationToken cancellationToken)
    {
        AdditionalText? file = additionalFiles.FirstOrDefault(static f => IsBaselineFile(f.Path));
        if (file is null)
        {
            return Inactive;
        }

        var pinned = ImmutableDictionary.CreateBuilder<string, string>(StringComparer.Ordinal);
        if (file.GetText(cancellationToken) is { } text)
        {
            foreach (Microsoft.CodeAnalysis.Text.TextLine line in text.Lines)
            {
                string raw = line.ToString().Trim();
                if (raw.Length == 0 || raw[0] == '#')
                {
                    continue;
                }

                int split = raw.IndexOf(Separator, StringComparison.Ordinal);
                if (split <= 0)
                {
                    continue;
                }

                string identity = raw.Substring(0, split).Trim();
                string hash = raw.Substring(split + Separator.Length).Trim();
                if (identity.Length > 0 && hash.Length > 0)
                {
                    pinned[identity] = hash;
                }
            }
        }

        return new DescriptionBaseline(isActive: true, pinned.ToImmutable());
    }

    /// <summary>Recognizes the baseline file by name, regardless of directory or casing.</summary>
    public static bool IsBaselineFile(string path)
    {
        if (string.IsNullOrEmpty(path))
        {
            return false;
        }

        string name = System.IO.Path.GetFileName(path);
        return string.Equals(name, FileName, StringComparison.OrdinalIgnoreCase);
    }

    /// <summary>The stable baseline identity for an MCP tool member (e.g. <c>Acme.Tools.FileTools.ReadFile</c>).</summary>
    public static string IdentityFor(ISymbol symbol) => symbol.ToDisplayString(IdentityFormat);

    /// <summary>A short hex fingerprint of the exact model-visible text (raw — invisible edits trip it).</summary>
    public static string Fingerprint(string text)
    {
        using var sha = SHA256.Create();
        byte[] digest = sha.ComputeHash(Encoding.UTF8.GetBytes(text ?? string.Empty));
        var builder = new StringBuilder(32);
        for (int i = 0; i < 16; i++)
        {
            builder.Append(digest[i].ToString("x2"));
        }

        return builder.ToString();
    }

    /// <summary>The canonical baseline line for an identity and its current description text.</summary>
    public static string FormatLine(string identity, string text) => identity + Separator + Fingerprint(text);

    /// <summary>Compares one tool member's current description to the pinned fingerprint.</summary>
    public BaselineStatus Check(string identity, string text, out string expectedLine)
    {
        string hash = Fingerprint(text);
        expectedLine = identity + Separator + hash;

        if (!_pinned.TryGetValue(identity, out string? pinned))
        {
            return BaselineStatus.Unpinned;
        }

        return string.Equals(pinned, hash, StringComparison.OrdinalIgnoreCase)
            ? BaselineStatus.Match
            : BaselineStatus.Drifted;
    }
}