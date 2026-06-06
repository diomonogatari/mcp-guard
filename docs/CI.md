# Gating CI with mcp-guard

mcp-guard is a Roslyn analyzer: it runs inside your build, so any build that compiles your MCP server
also runs mcp-guard. In CI you usually want a finding to **fail** the build rather than print a warning.
There are two ways to do that.

## Option 1 — the reusable GitHub Action

Reference the analyzer in the project you want gated:

```xml
<ItemGroup>
  <PackageReference Include="McpGuard.Analyzers" Version="1.0.0" PrivateAssets="all" />
</ItemGroup>
```

Then add the action to a workflow. It builds your project and escalates every mcp-guard finding to an
error:

```yaml
name: mcp-guard
on: [push, pull_request]

jobs:
  mcp-guard:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: diomonogatari/mcp-guard@v1
        with:
          project: src/MyMcpServer/MyMcpServer.csproj   # optional; omit to build the whole repo
          dotnet-version: 8.0.x                          # optional; omit to use the runner's SDK
```

### Inputs

| Input | Default | Description |
|-------|---------|-------------|
| `project` | *(empty)* | Project or solution to analyze; empty lets `dotnet` pick the one in the working directory. |
| `configuration` | `Release` | Build configuration. |
| `dotnet-version` | *(empty)* | SDK version(s) to install via `actions/setup-dotnet`; empty uses the runner's SDK. |
| `warnings-as-errors` | `true` | Escalate findings to build errors so they fail CI. |
| `rules` | warning-severity set | Semicolon-separated rule ids to escalate. Info rules (MCPG007, MCPG011) are advisory and not failed by default; MCPG012 is already an error. |
| `working-directory` | `.` | Directory to run in. |

## Option 2 — plain `dotnet build`

The action is a thin wrapper. If you already have a build step, just escalate the rules yourself:

```bash
dotnet build src/MyMcpServer/MyMcpServer.csproj -c Release \
  -warnaserror:"MCPG001;MCPG002;MCPG003;MCPG004;MCPG005;MCPG006;MCPG008;MCPG009;MCPG010;MCPG013"
```

Or escalate per-rule in `.editorconfig`, which also covers local builds and the IDE:

```ini
[*.cs]
dotnet_diagnostic.MCPG001.severity = error
# …one line per rule you want to block on.
```

## Notes

- **MCPG012** (confirmed exfiltration payload) is already an error by default. It fails the build even
  without `warnings-as-errors`.
- **MCPG013** (the integrity baseline) only fires once you commit a `McpGuard.Baseline.txt`; see
  [the rule docs](rules/MCPG013.md).
- Suppressing a security rule should be deliberate and reviewed; prefer fixing the description.
