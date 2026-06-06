# MCPG005 — MCP tool description contains an ANSI/terminal escape sequence

| | |
|---|---|
| **Category** | Security |
| **Default severity** | Warning |
| **Enabled by default** | Yes |

## Cause

A `[Description]` on the MCP tool surface contains an ANSI / terminal escape sequence: text
introduced by the ESC control character (U+001B), such as `ESC[31m` (set color) or `ESC[2K`
(erase line).

## Rule description

Many MCP clients render tool names, descriptions, and output in a terminal. ANSI escape sequences let
that text **manipulate the terminal**: hide or overwrite lines, move the cursor, or spoof hyperlinks
(OSC 8). An attacker can use them to make a poisoned description look innocuous to a human while it
still reaches the model — or to rewrite what the user sees after a tool runs ("output poisoning").

There is no legitimate reason for an ESC byte in a tool description, so MCPG005 flags any occurrence.
ESC is deliberately excluded from [MCPG002](MCPG002.md) so the two rules never double-report the same
byte.

## How to fix violations

Remove the escape. Describe the tool in plain text; if you need to convey emphasis, use words, not
terminal control codes. A code fix is available: your IDE's Quick Fix (lightbulb) removes the ANSI
escape sequence automatically.

## When to suppress

Effectively never: a tool description should be plain text. For an unusual, justified case, scope a
`#pragma warning disable MCPG005`.
