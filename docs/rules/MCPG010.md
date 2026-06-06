# MCPG010 — MCP tool description contains off-screen whitespace padding

| | |
|---|---|
| **Category** | Security |
| **Default severity** | Warning |
| **Enabled by default** | Yes |

## Cause

A `[Description]` on the MCP tool surface contains a long run of spaces or tabs (20+) — used to push
text off the visible area so a human reviewer never scrolls to it.

## Rule description

This is a documented exfiltration / poisoning trick: hide the payload after a big horizontal gap, so
the description *looks* short and clean while the model still reads the hidden tail. Unlike
[MCPG002](MCPG002.md), the padding is ordinary **visible** whitespace, not hidden characters.

Newlines break the run, so ordinary multi-line indentation is never flagged.

## How to fix violations

Remove the padding and the content it hides; keep the description short and on a single logical line.

## When to suppress

A description has no reason for a 20-character run of spaces, so suppression is rarely appropriate.
