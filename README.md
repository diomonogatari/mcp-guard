# mcp-guard

**A Roslyn analyzer that catches prompt-injection and tool-poisoning in your C# MCP server's tool descriptions at build time, before they ship.**

[![CI](https://github.com/diomonogatari/mcp-guard/actions/workflows/ci.yml/badge.svg)](https://github.com/diomonogatari/mcp-guard/actions/workflows/ci.yml)

`mcp-guard` is a `DiagnosticAnalyzer` for .NET projects that build [Model Context
Protocol](https://modelcontextprotocol.io) servers with the official
[C# SDK](https://github.com/modelcontextprotocol/csharp-sdk). It scans the strings an LLM reads as
**instructions**: the `[Description(...)]` on `[McpServerTool]` methods, their parameters, and tool
types, plus tool `Name`s and parameter / enum-member names. It flags prompt-injection and tool-poisoning
patterns as IDE squiggles and build warnings.

> It is **not** an MCP server. It is static analysis that *protects* MCP servers. See the
> [threat model](docs/THREAT-MODEL.md) for why tool descriptions are attack surface.

**Who is it for?** Whoever owns the build: maintainers, platform and security teams, registries and
auditors, and careful solo developers who want to prove no description-resident poison slipped into
their source, including the invisible payloads a diff review cannot see. See
[who this protects](docs/THREAT-MODEL.md#who-this-protects-and-why-human-review-is-not-enough).

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
| [`MCPG012`](docs/rules/MCPG012.md) | **Confirmed exfiltration payload**: a secret reference **and** an external sink together | **Error** |
| [`MCPG013`](docs/rules/MCPG013.md) | Description drifted from the committed integrity baseline (rug-pull guard; opt-in) | Warning |

Precision is the priority: mcp-guard only inspects the **MCP tool surface**
(`[McpServerTool]` / `[McpServerPrompt]` / `[McpServerResource]` members, their parameters and parameter
names, and the matching `[McpServer*Type]` types), so ordinary `[Description]` usage never
false-positives. Most rules are individually high-confidence heuristics. **MCPG012** escalates the
co-occurrence of two of them, a secret reference plus an external sink, to a build-breaking error: a
confirmed exfiltration payload. The [roadmap](docs/ROADMAP.md) documents the full 1.0 rule catalog.

## Install

```xml
<ItemGroup>
  <PackageReference Include="McpGuard.Analyzers" Version="1.0.0" PrivateAssets="all" />
</ItemGroup>
```

The package is a development dependency: it runs at *your* build time and never flows to your package's
consumers. The analyzer targets `netstandard2.0`, so it loads in every IDE and build host, and it is
verified against projects targeting **.NET 8** and **.NET 10**. There is nothing else to configure;
findings appear as soon as the project builds.

## Configuration

Tune severity per rule in `.editorconfig`. For example, to gate the build on the highest-signal rules:

```ini
[*.cs]
dotnet_diagnostic.MCPG001.severity = error
dotnet_diagnostic.MCPG003.severity = error
dotnet_diagnostic.MCPG004.severity = error
```

MCPG012 is already an error by default. Inline suppression is supported for a reviewed false positive,
though suppressing a security rule should be rare; prefer rewording the description:

```csharp
#pragma warning disable MCPG001 // reviewed: documentation example, not an instruction
```

## Rug-pull defense (opt-in)

A tool description can be changed after it was first reviewed. To guard against that, add an empty
`McpGuard.Baseline.txt` to your project as an additional file:

```xml
<ItemGroup>
  <AdditionalFiles Include="McpGuard.Baseline.txt" />
</ItemGroup>
```

Build once and apply the **"Update mcp-guard integrity baseline"** quick fix to record each tool's
description fingerprint. From then on, any change to a description re-fires
[MCPG013](docs/rules/MCPG013.md) until the baseline is deliberately updated, so a silent edit becomes a
reviewable diff.

## Gate your CI

mcp-guard runs inside your build, so failing CI on a finding is a matter of escalating the rules. The
reusable GitHub Action does it for you:

```yaml
- uses: diomonogatari/mcp-guard@v1
  with:
    project: src/MyMcpServer/MyMcpServer.csproj
```

See [docs/CI.md](docs/CI.md) for inputs, the plain `dotnet build` equivalent, and `.editorconfig` gating.

## Documentation

- [Coverage scorecard](docs/SCORECARD.md): what it catches, what it doesn't, and the evidence
- [Threat model](docs/THREAT-MODEL.md): why descriptions are attack surface, and the static-vs-runtime scope
- [Architecture](docs/ARCHITECTURE.md): how the analyzer works
- [Gating CI](docs/CI.md): the reusable Action and `.editorconfig` gating
- [Roadmap](docs/ROADMAP.md): the 1.0 rule catalog and the research behind it
- [Test plan](docs/TEST-PLAN.md): the known-attack corpus and live-server tiers
- [Rule reference](docs/rules/): one page per `MCPGxxx`
- [Contributing](CONTRIBUTING.md): build, test, and add a rule
- [Security policy](SECURITY.md)

## License

[MIT](LICENSE) © Diogo Carvalho
