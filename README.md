# mcp-guard

**A Roslyn analyzer that catches prompt-injection and tool-poisoning in your C# MCP server's tool descriptions — at build time, before they ship.**

[![CI](https://github.com/diomonogatari/mcp-guard/actions/workflows/ci.yml/badge.svg)](https://github.com/diomonogatari/mcp-guard/actions/workflows/ci.yml)

`mcp-guard` is a `DiagnosticAnalyzer` for .NET projects that build [Model Context
Protocol](https://modelcontextprotocol.io) servers with the official
[C# SDK](https://github.com/modelcontextprotocol/csharp-sdk). It scans the strings an LLM reads as
**instructions** — the `[Description(...)]` on `[McpServerTool]` methods, their parameters, and tool
types — and flags prompt-injection / tool-poisoning patterns as IDE squiggles and build warnings.

> It is **not** an MCP server. It is static analysis that *protects* MCP servers. See the
> [threat model](docs/THREAT-MODEL.md) for why tool descriptions are attack surface.

## Rules

| Rule | Summary | Severity |
|------|---------|----------|
| [`MCPG001`](docs/rules/MCPG001.md) | Instruction-style / prompt-injection phrasing in a description | Warning |
| [`MCPG002`](docs/rules/MCPG002.md) | Hidden / non-printable Unicode (zero-width, bidi, BOM, tag chars) | Warning |
| [`MCPG003`](docs/rules/MCPG003.md) | A sensitive credential / secret-file reference (`~/.ssh/id_rsa`, `.aws/credentials`, …) | Warning |
| [`MCPG004`](docs/rules/MCPG004.md) | A data-exfiltration directive (transmit verb + external destination + sensitive/covert cue) | Warning |
| [`MCPG005`](docs/rules/MCPG005.md) | An ANSI / terminal escape sequence (`U+001B`) | Warning |
| [`MCPG006`](docs/rules/MCPG006.md) | Manipulative / authority phrasing (coercion, suppressing other tools) | Warning |
| [`MCPG007`](docs/rules/MCPG007.md) | A benign tool name whose description claims a dangerous capability | Info |
| [`MCPG008`](docs/rules/MCPG008.md) | Embedded instruction markup (HTML comments, fake system tags) | Warning |
| [`MCPG009`](docs/rules/MCPG009.md) | Cross-tool / tool-shadowing references (influencing other tools) | Warning |
| [`MCPG010`](docs/rules/MCPG010.md) | Off-screen whitespace padding (a long run of spaces/tabs) | Warning |
| [`MCPG011`](docs/rules/MCPG011.md) | An encoded (base64/hex) payload blob | Info |
| [`MCPG012`](docs/rules/MCPG012.md) | **Confirmed exfiltration payload** — a secret reference **and** an external sink together | **Error** |
| [`MCPG013`](docs/rules/MCPG013.md) | Description drifted from the committed integrity baseline (rug-pull guard; opt-in) | Warning |

Precision is the priority: mcp-guard only inspects descriptions on the **MCP tool surface**
(`[McpServerTool]` / `[McpServerPrompt]` / `[McpServerResource]` members, their parameters, and the
matching `[McpServer*Type]` types), so ordinary `[Description]` usage never false-positives. Most rules
are individually high-confidence heuristics; [`MCPG012`](docs/rules/MCPG012.md) escalates the
co-occurrence of two of them to a build-breaking error. The [roadmap](docs/ROADMAP.md) tracks the
remaining work on the path to 1.0.

## Install

```xml
<ItemGroup>
  <PackageReference Include="McpGuard.Analyzers" Version="0.1.0" PrivateAssets="all" />
</ItemGroup>
```

`PrivateAssets="all"` keeps the analyzer from flowing to your package's consumers — it runs at *your*
build time. The analyzer targets `netstandard2.0`, so it loads in every IDE and build host; it is
verified against projects targeting **.NET 8** and **.NET 10**.

## Configuration

Tune severity per rule via `.editorconfig` — e.g. to gate the build on findings:

```ini
dotnet_diagnostic.MCPG001.severity = error
```

Inline suppression (`#pragma warning disable MCPG001`) is supported, but suppressing a security rule
should be rare — prefer rewording the description.

## Gate your CI

mcp-guard runs inside your build, so failing CI on a finding is just a matter of escalating the rules.
The reusable GitHub Action does it for you:

```yaml
- uses: diomonogatari/mcp-guard@v1
  with:
    project: src/MyMcpServer/MyMcpServer.csproj
```

See [docs/CI.md](docs/CI.md) for inputs, the plain `dotnet build` equivalent, and `.editorconfig` gating.

## Documentation

- [Coverage scorecard](docs/SCORECARD.md) — what it catches, what it doesn't, and the evidence
- [Threat model](docs/THREAT-MODEL.md) — why descriptions are attack surface, and the static-vs-runtime scope
- [Architecture](docs/ARCHITECTURE.md) — how the analyzer works
- [Gating CI](docs/CI.md) — the reusable Action and `.editorconfig` gating
- [Roadmap](docs/ROADMAP.md) — the shipped rule catalog on the path to 1.0
- [Test plan](docs/TEST-PLAN.md) — the known-attack corpus and live-server tiers
- [Rule reference](docs/rules/) — one page per `MCPGxxx`
- [Contributing](CONTRIBUTING.md) — build, test, and add a rule
- [Security policy](SECURITY.md)

## License

[MIT](LICENSE) © Diogo Carvalho
