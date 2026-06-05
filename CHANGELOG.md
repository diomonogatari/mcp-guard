# Changelog

All notable changes to mcp-guard are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres to
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.0] - 2026-06-05

### Added

- **MCPG001** — flags prompt-injection / instruction-style phrasing in the `[Description]` of an MCP
  tool, parameter, or tool type (e.g. *"ignore previous instructions"*, *"do not tell the user"*,
  *"before answering, …"*).
- **MCPG002** — flags hidden / non-printable Unicode (zero-width spaces, bidirectional controls,
  byte-order marks, tag characters) in MCP tool descriptions.
- Roslyn analyzer packaged as `McpGuard.Analyzers` (`netstandard2.0`), loadable on the .NET 8 and
  .NET 10 build hosts; surfaces as IDE squiggles and build warnings, configurable via `.editorconfig`.
- Pluggable rule framework, a deliberately poisoned sample server used as a live fixture, and a
  `Microsoft.CodeAnalysis.Testing` verifier suite run against net8.0 and net10.0 (~98% line coverage).

[Unreleased]: https://github.com/diomonogatari/mcp-guard/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/diomonogatari/mcp-guard/releases/tag/v0.1.0
