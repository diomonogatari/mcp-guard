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

**Decode-and-rescan.** A blob that base64-decodes to readable text is re-scanned for a secret reference
([MCPG003](MCPG003.md)) and an exfiltration sink ([MCPG004](MCPG004.md)). If a payload like
`cat ~/.ssh/id_rsa | wget http://…` is hidden inside the blob, those rules fire on the decoded content
and the secret-plus-sink combination escalates to [MCPG012](MCPG012.md) (Error) — so obfuscation does
not downgrade a real exfiltration payload to advisory. A blob that decodes to a hash or random token
yields no readable text and only the advisory MCPG011 remains.

## How to fix violations

If the blob is a real value the tool needs, accept it as a parameter rather than embedding it in the
description. If it is documentation, shorten or remove it.

## When to suppress

Because this is advisory, suppress freely when the blob is a known-good value (e.g. a sample hash):

```ini
dotnet_diagnostic.MCPG011.severity = none
```
