# mcp-guard rule roadmap & threat model

mcp-guard owns the **static** half of MCP defense: the tool / parameter / resource / prompt
descriptions and metadata present in C# source at build time. Runtime guards (live exfiltration,
cross-server topology) are out of scope and named in the [threat model](THREAT-MODEL.md). The 1.0 rule
set below is feature-complete; this page is the threat-grounded record of what shipped and why.

Grounded in the OWASP MCP Top 10, the MCP spec security guidance, Invariant's mcp-scan and tool-poisoning
research, Trail of Bits' ANSI-in-MCP work, CyberArk's terminal-escape research, and the MCP-38 / MCPTox
taxonomies (see [Sources](#sources)).

## Shipped rules

The full 1.0 catalog. Each rule ships with a positive fixture (fires), a clean look-alike (stays quiet),
and a [reference page](rules/). Severity reflects confidence: the deterministic core is `Warning`, the
fuzzy rules are `Info`, and the confirmed-payload escalation is `Error`.

| ID | Rule | Severity |
|----|------|----------|
| [MCPG001](rules/MCPG001.md) | Prompt-injection / instruction-override phrasing (incl. secrecy directives) | Warning |
| [MCPG002](rules/MCPG002.md) | Hidden / non-printable Unicode (zero-width, bidi, BOM, tag chars; non-ESC controls) | Warning |
| [MCPG003](rules/MCPG003.md) | Sensitive credential / secret-file references | Warning |
| [MCPG004](rules/MCPG004.md) | Exfiltration directive (verb + external destination + sensitivity) **or** a markdown image/data-link sink | Warning |
| [MCPG005](rules/MCPG005.md) | ANSI / terminal-escape sequence poisoning (sequence-aware CSI/OSC) | Warning |
| [MCPG006](rules/MCPG006.md) | Manipulative / authority phrasing ("you must", "always call this first", "do not use other tools") | Warning |
| [MCPG007](rules/MCPG007.md) | Capability ⇄ description **mismatch** (benign tool name, dangerous claimed reach) | Info |
| [MCPG008](rules/MCPG008.md) | Embedded instruction markup (HTML comments, fake `<system>` / `<IMPORTANT>` tags) | Warning |
| [MCPG009](rules/MCPG009.md) | Cross-tool / tool-shadowing references (influencing another named tool) | Warning |
| [MCPG010](rules/MCPG010.md) | Off-screen whitespace padding (long runs of spaces/tabs) | Warning |
| [MCPG011](rules/MCPG011.md) | Encoded payload blobs (long base64 / hex obfuscation) | Info |
| [MCPG012](rules/MCPG012.md) | **Confirmed exfiltration payload** — MCPG003 + MCPG004 on one description | **Error** |
| [MCPG013](rules/MCPG013.md) | Description drifted from the committed integrity baseline (rug-pull guard; opt-in) | Warning |

> **No standalone secrecy rule.** Secrecy / non-disclosure directives ("do not tell the user", …) are
> covered by **MCPG001**; the MCPG012 escalation combines MCPG003 (a secret reference) and MCPG004 (a sink).
>
> **MCPG007 / MCPG011** stay `Info` on purpose: a raw capability- or entropy-keyword match is noisy
> ("runs arbitrary shell commands" is often an accurate description, not an attack), so the deterministic
> core stays trusted.

### Refinements (shipped)

- **MCPG002 hardening.** `U+200D` (ZWJ) is not blanket-flagged (legitimate in emoji/Indic scripts);
  variation-selector runs (`U+FE00–U+FE0F`, `U+E0100–U+E01EF`) are caught; Unicode-tag hits
  (`U+E0000–U+E007F`) are decoded into the diagnostic message.
- **MCPG004 markdown sinks.** A rendered image/link with data in the query string
  (`![x](http://host/?d={data})`) is flagged even with no transmit verb.
- **MCPG005 sequence-aware** — full CSI (`ESC[ … @–~`) and OSC (`ESC] … BEL`/`ST`, incl. OSC-8) are
  recognized; the code fix strips the whole sequence, and MCPG002 keeps any bare/raw ESC.

## Cross-cutting (shipped)

- **Full metadata-surface coverage.** Every detector runs on the whole surface: method and **parameter**
  `[Description]`s, **tool `Name` strings**, and `[McpServerResource]` / `[McpServerPrompt]` /
  `[McpServer*Type]` descriptions. A payload in any of them is caught, not just the method description.
- **Multi-signal escalation (MCPG012).** A secret reference (MCPG003) plus an external sink (MCPG004) on
  one description is promoted to `Error`.
- **Severity hygiene.** The fuzzy/capability rules (MCPG007, MCPG011) stay `Info`/opt-in so the
  deterministic core stays trusted.
- **Robustness.** String extraction handles plain/verbatim/raw literals and `const` concatenation
  (interpolation cannot appear in an attribute).

## Differentiator: description-integrity baseline (rug-pull) — **shipped (MCPG013)**

The one attack a runtime scanner catches but a text rule can't is the **rug-pull**: a description
changed *after* the user approved it. mcp-guard pins it in source: a committed `McpGuard.Baseline.txt`
of per-description fingerprints (added as an `AdditionalFiles`), with [MCPG013](rules/MCPG013.md) on
drift unless the baseline is deliberately updated. The fingerprint is over the raw bytes, so even an
invisible-character edit trips it. The feature is opt-in (inert until the baseline file exists). This is
the "does what runtime scanners structurally can't" story for the *source-level* rug-pull; runtime
mutation by a third-party server stays out of scope.

## Out of scope — runtime only

Documented in the [threat model](THREAT-MODEL.md): live exfiltration / network behavior, tool shadowing
across *connected* servers at runtime, cross-server confused-deputy / toxic-flow, and tool **output**
ANSI poisoning (mcp-guard sees descriptions in source, not runtime output).

## Test corpus & evals

Each `MCPGxxx`: a positive fixture (fires), a clean look-alike (stays quiet), plus a Unicode/escape
fixture where relevant. Real-attack corpora to draw from:

- `invariantlabs-ai/mcp-injection-experiments`: poisoning + WhatsApp exfil + rug-pull PoCs.
- Trail of Bits ANSI-in-MCP PoC (`\x1B[38;5;231;49m` white-on-white) — the canonical MCPG005 fixture.
- `aminrj-labs/mcp-attack-labs`: offline reproducible poisoned servers.
- MCPTox (arXiv 2508.14925) — tool-poisoning benchmark.
- `roslyn-codelens-mcp` CVE GHSA-552p-8f74-6x7q: the README "this is real" example.

## Sources

- Trail of Bits — *Deceiving users with ANSI terminal codes in MCP* — <https://blog.trailofbits.com/2025/04/29/deceiving-users-with-ansi-terminal-codes-in-mcp/>
- CyberArk — *Abusing Terminal Emulators with ANSI Escape Characters*
- Invariant Labs — Tool Poisoning Attacks + `mcp-injection-experiments`
- *MCP-38: A Threat Taxonomy for MCP* (arXiv 2603.18063)
- AWS Security — *Defending LLM apps against Unicode character smuggling* (Sep 2025)
- OWASP MCP Top 10 — <https://owasp.org/www-project-mcp-top-10/>
- OSC 8 hyperlink spec — <https://gist.github.com/egmontkob/eb114294efbcd5adb1944c9f3cb5feda>
