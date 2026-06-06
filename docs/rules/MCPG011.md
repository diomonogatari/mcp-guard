# MCPG011 — MCP tool description contains an encoded blob

| | |
|---|---|
| **Category** | Security |
| **Default severity** | Info |
| **Enabled by default** | Yes |

## Cause

A `[Description]` on the MCP tool surface contains a long contiguous run (40+) of base64 / hex
characters that includes at least one digit.

## Rule description

An encoded blob inside a description is a way to **obfuscate a payload** so it survives human review.
MCPG011 is intentionally **Info-level** (advisory, non-blocking) because a hash or a long opaque token
can look identical — review the blob and remove it if it is not legitimate.

URLs and paths do not trip it: `:`, `.`, and `?` are not base64 characters and break the run.

## How to fix violations

If the blob is a real value the tool needs, accept it as a parameter rather than embedding it in the
description. If it is documentation, shorten or remove it.

## When to suppress

Because this is advisory, suppress freely when the blob is a known-good value (e.g. a sample hash):

```ini
dotnet_diagnostic.MCPG011.severity = none
```
