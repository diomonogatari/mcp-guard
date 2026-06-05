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

MCPG002 flags any character in the Unicode **Format** category (`Cf`) — including:

- zero-width space `U+200B`, zero-width non-joiner `U+200C`, zero-width joiner `U+200D`
- word joiner `U+2060`, byte-order mark / zero-width no-break space `U+FEFF`
- soft hyphen `U+00AD`
- bidirectional controls `U+202A`–`U+202E`, `U+2066`–`U+2069`
- the Unicode tag block `U+E0000`–`U+E007F`

and any **Control** character (`Cc`) other than ordinary whitespace (tab, newline, carriage return).

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
