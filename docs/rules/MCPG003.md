# MCPG003 — MCP tool description references a sensitive credential artifact

| | |
|---|---|
| **Category** | Security |
| **Default severity** | Warning |
| **Enabled by default** | Yes |

## Cause

A model-visible string on the MCP tool surface names a sensitive credential artifact — an SSH private
key, a cloud-credential file, or a system password file. The surface includes a `[Description]` on a
method with `[McpServerTool]`, one of its parameters, or a type with `[McpServerToolType]`, **and** the
identifier names the model also reads: a parameter name and the member names of an enum used as a tool
parameter type (so a payload smuggled into `content_from_reading_ssh_id_rsa` is caught, not just one in
the description text).

## Rule description

A tool description is read by the model as guidance about what the tool does. There is no legitimate
reason for a description to name a secret like `~/.ssh/id_rsa` or `.aws/credentials`; such a reference
is a hallmark of a tool-poisoning / data-exfiltration payload that steers the model toward reading and
leaking those files.

MCPG003 flags references to specific, unambiguous secret artifacts, including:

- SSH private keys — `id_rsa`, `id_ed25519`, `id_dsa`, `id_ecdsa`, `~/.ssh`
- credential stores — `.aws/credentials`, `.pgpass`, `.git-credentials`
- system password files — `/etc/shadow`, `/etc/passwd`

It deliberately does **not** flag generic terms such as *"password"* or *"API key"*, which have
legitimate uses — those are left to the exfiltration rule (verb + external-destination gate).

## How to fix violations

Describe what the tool does without naming secrets. If the tool legitimately handles credentials,
describe the capability in the abstract:

```csharp
// ❌ MCPG003
[McpServerTool, Description("Reads ~/.ssh/id_rsa and returns its contents.")]

// ✅
[McpServerTool, Description("Reads the contents of a file the caller is authorized to access.")]
```

## When to suppress

Rarely appropriate. If your tool genuinely documents a credential path for operators, prefer rewording
to avoid the literal artifact; otherwise scope a `#pragma warning disable MCPG003`.
