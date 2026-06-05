# Contributing

Thanks for helping harden the .NET MCP ecosystem.

## Build & test

```bash
dotnet build McpGuard.slnx -c Release
dotnet test  McpGuard.slnx -c Release
bash scripts/verify-format.sh --fix     # or --verify
```

Tests use `Microsoft.CodeAnalysis.Testing` and run against net8.0 and net10.0 reference assemblies.
Keep analyzer coverage high (currently ~98% line) — every rule ships with positive, negative, and
edge-case tests.

## Repository layout

```
src/McpGuard.Analyzers          the analyzer (netstandard2.0 -> analyzers/dotnet/cs)
tests/McpGuard.Analyzers.Tests  verifier tests (net8 + net10)
samples/PoisonedServer          poisoned-on-purpose MCP tools; the analyzer is wired in from source
docs/                           architecture, threat model, roadmap, and per-rule docs
```

## Adding a rule

1. Add the id to [`DiagnosticIds`](src/McpGuard.Analyzers/DiagnosticIds.cs) (`MCPGxxx`, never reused).
2. Add a `…Rule : McpDescriptionRule` class under `src/McpGuard.Analyzers/Rules/` with its descriptor
   and `Analyze` method; keep detection logic in a separate, testable helper.
3. Register it in `McpToolDescriptionAnalyzer.RuleSet`.
4. Track it in [`AnalyzerReleases.Unshipped.md`](src/McpGuard.Analyzers/AnalyzerReleases.Unshipped.md).
5. Write `docs/rules/MCPGxxx.md`.
6. Add a `…RuleTests.cs`, and a poisoned tool in the sample if it should fire there.

Favor **precision over recall** — a noisy security analyzer gets disabled. Prefer high-confidence
rules; gate heuristics behind multiple signals.

## Commits & releases

Commit messages follow [Conventional Commits](https://www.conventionalcommits.org/)
(`feat:`, `fix:`, `refactor:`, `test:`, `docs:`, `chore:`). A release is cut by tagging `vX.Y.Z` as a
GitHub release, which triggers the publish workflow to pack and push `McpGuard.Analyzers` to NuGet;
unreleased rules live in `AnalyzerReleases.Unshipped.md` and move to `Shipped.md` at release time.
