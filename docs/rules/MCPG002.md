# MCPG002 — MCP tool description contains hidden or non-printable characters

| | |
|---|---|
| **Category** | Security |
| **Default severity** | Warning |
| **Enabled by default** | Yes |

## Cause

A `[Description]` on the MCP tool surface — a method annotated with `[McpServerTool]`, one of its
parameters, or a type annotated with `[McpServerToolType]` — contains an invisible or non-printable
character: a zero-width space/joiner, a bidirectional-control code, a byte-order mark, a Unicode
"tag" character, or a stray control code.

## Rule description

A description is supposed to be human-readable prose. Invisible characters are not — and they are a
known smuggling vector: a human reviewing the source (or the rendered tool list) sees innocuous text,
while the model receives extra characters that can carry or obscure instructions. Bidirectional
overrides can even make displayed text read differently from its logical order.

MCPG002 flags invisible / non-printable content — including:

- zero-width space `U+200B`, word joiner `U+2060`, byte-order mark `U+FEFF`, soft hyphen `U+00AD`
- bidirectional controls `U+202A`–`U+202E`, `U+2066`–`U+2069`
- the Unicode **tag** block `U+E0000`–`U+E007F` — and the hidden ASCII it carries is **decoded into the
  diagnostic message** (e.g. *…that reads "Ignore previous instructions"*)
- **runs** of variation selectors (`U+FE00`–`U+FE0F`, `U+E0100`–`U+E01EF`) used for byte-smuggling
- any **Control** character (`Cc`) other than ordinary whitespace (tab, newline, carriage return)

To stay precise it does **not** flag two legitimate cases: a lone zero-width joiner / non-joiner
(`U+200D` / `U+200C`, used in emoji ZWJ sequences and Indic scripts) or a single variation selector
(emoji styling). `ESC` (`U+001B`) is handled by [MCPG005](MCPG005.md).

## How to fix violations

Retype the description as plain text. If you pasted it from another source, the invisible character
likely came along for the ride — delete and re-enter the affected text.

```csharp
// ❌ MCPG002 — a zero-width space hides between "log." and the trailing text
[McpServerTool, Description("Returns the recent audit log.​")]

// ✅ plain text only
[McpServerTool, Description("Returns the recent audit log.")]
```

## When to suppress

Effectively never — there is no legitimate reason for an invisible character in a tool description.
If a specific code point is a genuine false positive for your domain, prefer rewording; a scoped
`#pragma warning disable MCPG002` is a last resort.
