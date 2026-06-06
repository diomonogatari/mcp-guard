# MCPG013 — MCP tool description does not match the integrity baseline

| | |
|---|---|
| **Category** | Security |
| **Default severity** | Warning |
| **Enabled by default** | Yes (but inert until a baseline file exists) |

## Cause

A committed integrity baseline pins an MCP tool member's `[Description]`, and the current description's
fingerprint no longer matches it: either it changed since it was pinned, or it is a new tool the
baseline does not yet record.

## Rule description

The one attack a text rule structurally can't catch is the **rug-pull**: a tool description that is
benign when the user approves it and is changed to something hostile *afterward*. MCPG013 pins the exact
model-visible text of each tool description to a fingerprint **committed to source**, so any later edit
is a reviewable diff and a build signal instead of a silent change.

The fingerprint is taken over the **raw** description bytes, so even an invisible-character edit (the
kind [MCPG002](MCPG002.md) catches) trips drift.

> **Scope.** This is the *build-time* analog of rug-pull defense: it catches changes to descriptions in
> **your** server's source. A third-party server that mutates the descriptions it serves *at runtime*
> is out of scope — that is the job of a runtime proxy (see the [threat model](../THREAT-MODEL.md)).

## How to enable

The rule is **opt-in** and completely inert until you add a baseline file. It never fires on a project
that has not opted in.

1. Add an empty `McpGuard.Baseline.txt` next to your project and list it as an additional file:

   ```xml
   <ItemGroup>
     <AdditionalFiles Include="McpGuard.Baseline.txt" />
   </ItemGroup>
   ```

2. Build. Every MCP tool description now reports MCPG013 as *unpinned*; each message ends with the exact
   line to record, e.g.:

   ```text
   warning MCPG013: ... update the baseline entry to 'Acme.Tools.FileTools.ReadFile => 2ea6be57cad29995'
   ```

3. Paste those lines into `McpGuard.Baseline.txt` (or apply the **"Update mcp-guard integrity baseline"**
   code fix). Commit the file. From now on, any description change re-fires MCPG013 until the baseline is
   deliberately updated in the same way, which shows up in code review.

### Baseline file format

One entry per line, `identity => fingerprint`. Blank lines and `#` comments are ignored.

```text
# mcp-guard description-integrity baseline — review every change to this file
Acme.Tools.FileTools.ReadFile => 2ea6be57cad29995...
Acme.Tools.SearchTools.Grep   => 9f1c0a4b7e2d8810...
```

The identity is the tool member's fully-qualified name. Only **member-level** `[McpServerTool]` /
`[McpServerPrompt]` / `[McpServerResource]` descriptions are pinned; parameter and type descriptions are
not pinned in this version. A removed tool leaves a stale line you can prune by hand.

## How to fix violations

Review the description change. If it is intended, update the baseline entry to the reported line (the
code fix does this for you). If it is not, revert the description.

## When to suppress

Suppressing MCPG013 defeats the purpose: the value is that a description change cannot pass silently.
Update the baseline instead. If you do not want integrity pinning at all, simply remove the baseline file.
