# mcp-guard rule roadmap & threat model

This roadmap maps the known MCP security-guard landscape to **what a build-time Roslyn analyzer can
actually enforce**. It's the backlog that drives 0.2.0+ — grounded in the OWASP MCP Top 10, the MCP
specification's security best practices, Invariant Labs' `mcp-scan`, CyberArk's "poison everywhere"
output-injection research, and academic tool-poisoning work (see [Sources](#sources)).

## The scope boundary

A Roslyn analyzer sees the **C# source at build time** — the text and metadata of tools, parameters,
resources, and prompts (`[McpServerTool]`, `[Description]`, input schemas). It is the *static* half of
MCP defense. The *runtime* half (live traffic, cross-session state, multi-server topology) is out of
reach and we document it as such, rather than pretend to cover it.

## Shipped (0.1.0)

| Rule | Detects | Attack class |
|------|---------|--------------|
| MCPG001 | Instruction / prompt-injection phrasing in a tool/parameter/type `[Description]` | Tool poisoning, prompt injection |
| MCPG002 | Hidden / non-printable Unicode (zero-width, bidi, BOM, tag chars) | Hidden-instruction smuggling |

## Backlog — statically checkable (prioritized)

### P1 — high confidence, low false-positive, ship next

| ID | Rule | Detection pattern | False-positive risk | Code fix? |
|----|------|-------------------|---------------------|-----------|
| MCPG003 | **Sensitive credential / secret-file reference** in a description | Curated artifact list: `id_rsa`, `id_ed25519`, `~/.ssh`, `.aws/credentials`, `.pgpass`, `/etc/shadow`, `/etc/passwd`, private-key files. Generic terms (`api key`, `access token`, `password`) only when paired with a transmit verb. | Low for file artifacts; medium for generic terms (hence the verb gate) | No (semantic) |
| MCPG004 | **Exfiltration directive** — description tells the model to send data somewhere | Transmit verb (`send`, `post`, `upload`, `exfiltrate`, `email`, `transmit`) **+** an external destination cue (URL, IP, domain, "external", "server") | Medium — require an explicit external destination to avoid "uploads to the configured endpoint" | No |
| MCPG005 | **ANSI / terminal escape sequences** in a description | `ESC` (U+001B) followed by a CSI/OSC sequence (`\x1B[`, `\x1B]`) | Very low | **Yes** — strip the sequence |

> MCPG005 partially overlaps MCPG002 (an `ESC` is already a control char), but a dedicated rule gives
> a precise message + its own severity. Decide whether to fold it into MCPG002 or ship separately.

### P2 — heuristic, tune against the stash-mcp dogfood corpus

| ID | Rule | Detection pattern | False-positive risk |
|----|------|-------------------|---------------------|
| MCPG006 | **Manipulative / authority phrasing** (extends MCPG001) | "this is very important", "you must", "always call this first", "do not use other tools", fake `<IMPORTANT>`/system tags, addressing "the assistant"/"AI"/"the model" | Medium |
| MCPG007 | **Over-broad capability hints** | description/name implies shell/exec/arbitrary file or network access ("run any command", "read any file", "execute arbitrary") | Medium — mostly advisory |
| MCPG008 | **Embedded markup / hidden comments** in a description | HTML comments `<!-- … -->`, fake XML/JSON "system" tags, markdown smuggling | Medium |

### P3 — limited static value / needs configuration

| ID | Rule | Note |
|----|------|------|
| MCPG009 | **Tool-name typosquatting / collisions** | Only meaningful with a curated known-tools list or within-project name-collision detection; high FP without config. Better as opt-in. |
| MCPG010 | **Description ⇄ schema mismatch** | Parameter described as X but schema permits Y; higher complexity, later. |

## Out of scope — runtime-only (document the boundary)

These are real MCP guards but **cannot** be done by build-time static analysis; mcp-guard should name
them and point users to runtime tooling (e.g. `mcp-scan` proxy mode):

- **Rug pulls** — a description that mutates *after* the user approved it (needs cross-session pinning/hashing).
- **Tool shadowing** across *connected* servers (needs the live multi-server topology).
- **Cross-server confused deputy / toxic-flow analysis** — data flow across tool calls at runtime.
- **Live typosquatting** against the public registry (needs registry state).
- **Actual data exfiltration / network behavior** — observable only at runtime.

## Quality bar

Match what C# devs expect of an analyzer (cf. `Meziantou.Analyzer`): one focused rule per id, a docs
page per rule, per-rule `.editorconfig` severity, and **code fixes where a safe mechanical fix exists**
(MCPG002 → strip the hidden char; MCPG005 → strip the ANSI sequence). Injection/poisoning rules
(MCPG001/004/006) have no safe auto-fix — offer suppression guidance only.

## Sources

- OWASP MCP Top 10 — <https://owasp.org/www-project-mcp-top-10/>
- OWASP MCP Security Cheat Sheet — <https://cheatsheetseries.owasp.org/cheatsheets/MCP_Security_Cheat_Sheet.html>
- MCP spec — security best practices — <https://modelcontextprotocol.io/docs/tutorials/security/security_best_practices>
- Invariant Labs — mcp-scan docs — <https://invariantlabs-ai.github.io/docs/mcp-scan/>
- Invariant Labs — tool-poisoning attacks — <https://invariantlabs.ai/blog/mcp-security-notification-tool-poisoning-attacks>
- CyberArk — "poison everywhere" (output injection) — <https://www.cyberark.com/resources/threat-research-blog/poison-everywhere-no-output-from-your-mcp-server-is-safe>
- CoSAI — MCP security working notes — <https://github.com/cosai-oasis/ws4-secure-design-agentic-systems/blob/main/model-context-protocol-security.md>
- UpGuard — typosquatting in the MCP ecosystem — <https://www.upguard.com/blog/typosquatting-in-the-mcp-ecosystem>
