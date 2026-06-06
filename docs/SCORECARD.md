# mcp-guard coverage scorecard

What mcp-guard catches, what it deliberately does **not** claim, and the evidence behind both. mcp-guard
is a build-time Roslyn analyzer: it scans the model-visible strings of a C# MCP server — `[Description]`
text on tools / parameters / resources / prompts, tool `Name`s, and parameter / enum-member names — and
fails the build on a poisoned one. It owns the **static** half of MCP defense; runtime guards are out of
scope (below).

## What it catches

| Attack class | Rules | Standards |
|---|---|---|
| Prompt injection / instruction override (incl. hidden Unicode, ANSI escapes, embedded markup) | [MCPG001](rules/MCPG001.md), [MCPG002](rules/MCPG002.md), [MCPG005](rules/MCPG005.md), [MCPG008](rules/MCPG008.md) | OWASP **MCP03** Tool Poisoning; MCP-38 **MCP-10** |
| Sensitive-data exposure / secret-file references (in descriptions **and** parameter/enum names) | [MCPG003](rules/MCPG003.md) | MCP-38 **MCP-11** (full-schema poisoning) |
| Data exfiltration (transmit verb + external sink, markdown image/link sinks, encoded-blob payloads) | [MCPG004](rules/MCPG004.md), [MCPG011](rules/MCPG011.md) | OWASP MCP03; MCP-38 MCP-10 |
| Manipulative / authority phrasing; preference manipulation | [MCPG006](rules/MCPG006.md) | MCP-38 **MCP-15** (MPMA) |
| Cross-tool / tool-shadowing references | [MCPG009](rules/MCPG009.md) | MCP-38 **MCP-13** |
| Off-screen whitespace hiding | [MCPG010](rules/MCPG010.md) | MCP-38 MCP-10 |
| Capability ⇄ name mismatch (advisory) | [MCPG007](rules/MCPG007.md) | — |
| **Confirmed exfiltration payload** — secret + sink on one description → **Error** | [MCPG012](rules/MCPG012.md) | escalation |
| **Description integrity / source-level rug-pull** — drift from a committed baseline (opt-in) | [MCPG013](rules/MCPG013.md) | MCP-38 **MCP-16** |

This is the natural ceiling of a build-time text scanner: **MCP-38 Category I** (semantic
manipulation / poisoning) plus the rug-pull baseline. Most rules are individually high-confidence
heuristics; MCPG012 escalates the co-occurrence of two of them to a build-breaking error.

## Evidence

Grounded in a [known-attack corpus](../tests/McpGuard.Analyzers.Tests/KnownAttackCorpusTests.cs) of
payloads transplanted from public defensive-research PoCs (DVMCP, Invariant Labs, Repello, CyberArk;
all exfil endpoints neutralized to `example.test`):

- **9 known attacks** — each asserts the exact set of rules it triggers (e.g. Invariant `direct-poisoning`
  → MCPG001 + MCPG003 + MCPG004 + **MCPG012**; Repello's base64-wrapped exfil → MCPG011 + decoded
  MCPG003/MCPG004 + MCPG012; CyberArk full-schema poisoning in a parameter name → MCPG003).
- **8 benign look-alikes** — realistic clean tools that brush against the rules (OAuth login to an https
  URL, artifact upload, a `curl` fetch, base64/hex mentions, an authorized config read, a documentary
  `id_rsa_compat_mode` parameter) — all assert **zero** diagnostics. This is the false-positive guard;
  precision is the top priority.
- **6 boundary cases** — runtime-only attacks asserted to fire **nothing** (see below).
- **Live tiers** ([integration tests](../tests/McpGuard.IntegrationTests/LiveServerTests.cs)): a poisoned
  description is proven to survive serialization into the `tools/list` a client receives, and a runtime
  rug-pull (a description swapped after load) is demonstrated end-to-end.

All of it runs on every PR: **126 analyzer + 3 integration tests**, against **.NET 8 and .NET 10**.

## What it does NOT claim (runtime boundary)

A build-time analyzer cannot see runtime behavior or cross-session state. These are out of scope and
belong to runtime / proxy tooling — the corpus includes them as negative-scope tests so the boundary is
explicit (see the [threat model](THREAT-MODEL.md)):

- **Runtime rug-pulls** by a third-party server (the *source-level* analog is [MCPG013](rules/MCPG013.md)).
- **Indirect injection** via data the tool fetches at runtime (DVMCP challenge 6, Backslash web-scraper).
- **ATPA** — payloads emitted in a tool's runtime **output / errors** (CyberArk).
- **Tool shadowing across connected servers**, cross-server confused-deputy, live typosquatting.
- **Full-schema poisoning via non-standard JSON-schema fields** — mcp-guard reads C# attributes, not the
  emitted schema (payloads in parameter/enum **names** *are* covered).
- **Actual network exfiltration** — observable only at runtime.

Pair mcp-guard with runtime defenses for the rest. It catches the poison *before it ships*.
