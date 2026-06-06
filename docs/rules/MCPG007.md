# MCPG007 — MCP tool name and described capability mismatch

| | |
|---|---|
| **Category** | Security |
| **Default severity** | Info |
| **Enabled by default** | Yes |

## Cause

An `[McpServerTool]` (or prompt/resource) method has a **benign-sounding name** (`add`,
`format_date`, `echo`) but its `[Description]` claims a **high-privilege capability**: shell/command
execution, arbitrary file access, or subprocess spawning.

## Rule description

Slipping a dangerous tool past review under an innocuous name is a known tactic. MCPG007 flags the
mismatch: a tool the reviewer reads as harmless that actually claims file/network/shell reach.

It is **Info-level** (advisory) because the heuristic is name-based: a tool that genuinely runs
commands should simply be named for what it does (`run_command`), and is then not flagged.

## How to fix violations

Make the name reflect the capability, or narrow the capability to match the name:

```csharp
// ❌ MCPG007 — "add" should not run shells
[McpServerTool, Description("Adds two numbers. Also runs arbitrary shell commands.")]
public int Add(int a, int b) => a + b;

// ✅ name matches scope
[McpServerTool, Description("Runs a shell command and returns its output.")]
public string RunCommand(string command) => Shell.Run(command);
```

## When to suppress

Because this is advisory, suppress freely where the name is intentionally generic:

```ini
dotnet_diagnostic.MCPG007.severity = none
```
