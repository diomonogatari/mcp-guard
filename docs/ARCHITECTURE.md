# Architecture

mcp-guard is a Roslyn `DiagnosticAnalyzer` plus a small rule framework that runs at build time and in
the IDE. It targets `netstandard2.0` so it loads in every supported build host — verified on the
.NET 8 SDK (Roslyn 4.8) and the .NET 10 SDK (Roslyn 5.0).

## The pipeline

For every `[Description]` attribute in the compilation,
[`McpToolDescriptionAnalyzer`](../src/McpGuard.Analyzers/McpToolDescriptionAnalyzer.cs):

1. **Gates to the MCP surface** — keeps only strings the model actually reads: `[Description]` on an
   `[McpServerTool]` / `[McpServerPrompt]` / `[McpServerResource]` member, one of its parameters, or an
   `[McpServer*Type]` type, plus the `Name = "..."` of those members. Ordinary `[Description]` usage is
   ignored, which keeps false positives near zero. MCP attributes are matched by name, so the analyzer
   does not require the MCP SDK to be resolvable.
2. **Extracts the text** — attribute arguments are compile-time constants, so the semantic model's
   constant value covers plain, verbatim, and raw string literals plus `const` concatenation
   ([`McpDescriptionExtractor`](../src/McpGuard.Analyzers/McpDescriptionExtractor.cs)).
3. **Runs the rule set** — each rule inspects the extracted text and reports its own diagnostic.

## The rule framework

A rule is a small class deriving from
[`McpDescriptionRule`](../src/McpGuard.Analyzers/McpDescriptionRule.cs): it owns its
`DiagnosticDescriptor` and a single `Analyze` method, and is a stateless singleton registered in the
analyzer's `RuleSet`. Adding a rule does not touch the orchestration — see
[CONTRIBUTING](../CONTRIBUTING.md#adding-a-rule).

Detection logic lives in dedicated, testable helpers (e.g. `ToolDescriptionPhrases`,
`HiddenCharacters`, `SecretArtifacts`, `ExfiltrationCues`) so the rules stay thin.

## Scope: static, not runtime

mcp-guard only sees source at build time, so it covers the *static* half of MCP defense — description
and metadata content. Runtime guards (rug pulls, tool shadowing, live exfiltration) are out of scope
by design; see the [threat model](THREAT-MODEL.md).

## Packaging

The analyzer ships as `McpGuard.Analyzers`, a development dependency whose DLL is packed into
`analyzers/dotnet/cs/` (no `lib/`), so Roslyn auto-loads it for both IDE squiggles and command-line
build warnings. It declares no package dependencies. `Microsoft.CodeAnalysis.CSharp` is pinned to the
oldest supported host (4.8.0) — referencing a newer Roslyn would stop the analyzer loading on older
build hosts.
