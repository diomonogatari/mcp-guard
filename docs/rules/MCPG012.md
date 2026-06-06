# MCPG012 — MCP tool description is a confirmed data-exfiltration payload

| | |
|---|---|
| **Category** | Security |
| **Default severity** | **Error** |
| **Enabled by default** | Yes |

## Cause

A single `[Description]` on the MCP tool surface triggers **both** [MCPG003](MCPG003.md) (a secret /
credential-file reference) **and** [MCPG004](MCPG004.md) (an external sink — a transmit directive or a
markdown sink).

## Rule description

The individual rules are high-confidence heuristics. Their **co-occurrence on the same description** is
not — a description that references a secret *and* ships data to an external destination is a working
exfiltration payload. mcp-guard escalates that combination to an **Error** so it fails the build, not
just a warning.

## How to fix violations

Remove the payload. The fixes for MCPG003 and MCPG004 each resolve this escalation, since it requires
both to fire.

## When to suppress

A confirmed exfiltration payload should essentially never be suppressed. If you are certain it is a
false positive (e.g. documentation that legitimately names both), scope a narrow
`#pragma warning disable MCPG012` with a justification, or reword to clear MCPG003 / MCPG004.
