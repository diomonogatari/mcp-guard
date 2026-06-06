# MCPG008 — MCP tool description contains embedded instruction markup

| | |
|---|---|
| **Category** | Security |
| **Default severity** | Warning |
| **Enabled by default** | Yes |

## Cause

A `[Description]` on the MCP tool surface contains markup used as a **delivery format for hidden
instructions** — an HTML comment, a fake system/instruction tag, or a chat-template control token.

## Rule description

Attackers wrap a poisoned instruction in markup so it reads as structure rather than prose — an HTML
comment a human skims over, or a tag the model treats as a control channel. MCPG008 flags a curated
set of such markers:

- HTML comments — `<!-- … -->`
- fake instruction tags — `<system>`, `<important>`, `<instructions>`, `<assistant>`
- chat-template tokens — `<|im_start|>`, `<|im_end|>`, `<<SYS>>`, `[INST]`

It matches **specific** markers only, so ordinary text is not affected — comparison operators
(`x < 10 and y > 5`) and genuine examples (*"wrap each value in `<item>` elements"*) are not flagged.

## How to fix violations

Remove the markup and describe the tool in plain prose.

## When to suppress

A tool description has no need for instruction markup, so suppression is rarely appropriate; prefer
rewording.
