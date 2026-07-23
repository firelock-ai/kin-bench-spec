# Kin merge-trust benchmark specification (prereg v1)

Status: v1.0.1 -- 2026-07-23. Protocol frozen; section 14 items confirmed against the
reference implementation. Results published separately upon independent verification.
Scope: the merge-trust adapter of the Kin benchmark harness (kin-bench), protocol
identifier `merge-trust-prereg-v1`.
Method note: every claim below was read directly from the reference implementation
of the merge-trust harness -- its dataset-identity, scenario-extraction, arm,
canonicalization, scoring, statistics, and hygiene modules -- and cross-checked
against a real accepted evidence bundle. Details that were open at v1.0 have since
been confirmed against the reference implementation (section 14). This document
deliberately carries no measured
result figures; it describes the mechanism and the protocol constants a stranger
needs to reimplement the benchmark, not any run's outcome.

Brand note for any later outward-facing derivative: describe declared actors,
content-addressed identifiers, and reproducible reruns. Do not describe any output
as proven, verified, or tamper-proof.

---

## 1. What the benchmark measures

Merge-trust is a counterfactual review benchmark. Each scenario is one proposed git
change (a single commit, expressed as a `base..head` range) drawn from a real
open-source repository. Every arm is a different reviewer answering the same
question: if this change were merged, should it be trusted, and what else would it
impact?

The experiment isolates one variable -- the substrate the reviewer reasons over:

- Arm K (the system under test) answers from Kin's semantic graph.
- Arm G (the primary baseline) answers from a deterministic text-only rule.
- Arm L (an optional companion baseline) answers from a language model with no
  graph.

Because every arm sees the same scenarios and emits the same decision schema, the
difference between arms is attributable to substrate, not to task framing. The
headline comparison is the scenario-paired K-vs-G contrast; K-vs-L is a companion
contrast when Arm L is run.

---

## 2. Hashing primitives (pin these first)

The protocol uses three distinct canonical serializations. They are NOT
interchangeable; mixing them produces wrong digests. A reimplementation must
reproduce each exactly.

### 2.1 Identity / seal / ledger / manifest digest

Used for the segment-ledger `content_sha256`, the harness-source-manifest
`content_sha256`, every seal and identity digest, and per-stamp payload digests.

```
def canonical_digest(obj):
    text = json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    return sha256(text.encode("utf-8")).hexdigest()
```

Compact separators, keys sorted at every depth, non-ASCII escaped. In the reference
implementation this is the single canonical-digest primitive that the run driver and
each arm wrap for every seal, identity, and ledger digest.

### 2.2 Determinism / report digest

Used only for the per-pass shadow-report comparison in the determinism gate (section
6). Identical to 2.1 except `ensure_ascii=False`.

```
def report_bytes(canon_report):
    return json.dumps(canon_report, sort_keys=True,
                      separators=(",", ":"), ensure_ascii=False).encode("utf-8")
```

### 2.3 Dataset digest

Used for the records-array dataset identity (section 4). Default separators (a comma
and a space, a colon and a space), keys sorted, ASCII escaped by default.

```
def dataset_records_digest(records):
    return sha256(json.dumps(list(records), sort_keys=True).encode()).hexdigest()
```

### 2.4 File digest

Streamed `sha256` over the raw bytes of a file (used for `raw_file_sha256` and for
each stamp file digest). Reproducible with a standard `shasum -a 256` on the file.

---

## 3. Task model and scenario record

### 3.1 Scenario record (one dataset row)

The dataset is a JSONL file, one scenario per line. Each record carries:

- `scenario_id` -- stable identifier, of the form
  `mtrust__<owner>_<repo>__<family>__<shorthash>` (family is an authoring bucket such
  as benign, regfix, or revert).
- `repo` -- repository slug (for example `django/django`).
- `base_commit`, `head_commit` -- the change range; base is the parent, head is the
  proposed commit.
- `diff_ref`, `language`, `repo_url`, `extractor_version` -- provenance of the row.
- `gold` -- the label object: `should_flag` (boolean, the primary label),
  `risk_class`, `impacted_files`, `impacted_basis`, `impacted_granularity`,
  `signature_changed`.
- `provenance` -- label provenance: `confidence`, `evidence`, `label_source`,
  `matched_symbols`.

Arms consume only `scenario_id`, `repo`, `base_commit`, `head_commit`. The `gold` and
`provenance` blocks are consumed only by the scorer, never by an arm; an arm never
sees the label it is being scored against.

### 3.2 Counterfactual design

`should_flag` is the gold: a scenario is "dangerous" (`should_flag` true) when the
change was reverted or was a regression culprit, and "benign" (`should_flag` false)
otherwise. The impacted-file gold captures the true blast radius of the change. The
benchmark therefore asks two things of each arm per scenario: a trust decision (flag
or not, and how hard) and a blast-radius prediction (which other files the change
reaches).

### 3.3 Repository corpus

Scenarios are drawn from a fixed set of large open-source repositories. The block
execution order recorded in a full-run provenance names them (for example django,
sphinx, pytest, cli, svelte, catch2). The corpus repositories are pinned by commit
through the scenario `base_commit` / `head_commit`, and the graph is built against a
worktree materialized at `base`.

---

## 4. Dataset identity (two digest families)

A run records two independent digests of its dataset, plus the record count.

- `dataset.sha256` (also emitted as `dataset.records_array_sha256`) -- the
  records-array digest of section 2.3, computed over the parsed record list. It is
  order-sensitive: `sort_keys=True` sorts each record's keys but not the record
  sequence, so reordering records changes the digest. The record sequence is part of
  the cohort identity. Anything that wants a different processing order must reorder
  execution, never the records.
- `dataset.raw_file_sha256` -- the file digest of section 2.4 over the raw JSONL
  bytes. This is what a plain `shasum` of the dataset file reproduces.
- `dataset.n` -- the record count.

Why two families: the records-array digest is stable against cosmetic file
differences (trailing newline, line ordering of keys within a record) because it
hashes parsed structure; the raw-file digest is what an external party gets by
hashing the file they were handed. Carrying both lets a replicator confirm both the
bytes they received and the semantic content the harness executed.

Producer and consumer agree by construction. The extractor computes both digests when
it writes the dataset. The runner recomputes the records-array digest from the rows it
loaded and refuses to run if it does not match the declared `dataset.sha256`; it then
re-asserts that identity before running, before scoring, and inside the provenance
gate. `raw_file_sha256` and `records_array_sha256` are passed through from the dataset
sidecar rather than recomputed by the runner.

Older dataset sidecars written before the dual-digest change carry only `sha256`;
`raw_file_sha256` and `records_array_sha256` are absent, and the runner carries those two
fields through as null rather than recomputing them. A verifier must treat
`raw_file_sha256` (and the `records_array_sha256` alias) as optional; dataset identity is
still enforced on every run through `dataset.sha256`, the records-array digest, which the
runner recomputes from the loaded records and refuses on mismatch.

---

## 5. Arms and their contracts

### 5.1 Shared decision schema

Every arm emits, per scenario:

- `verdict` in `{pass, needs_attention, would_block}`.
- `flag` -- boolean, true iff `verdict` is `needs_attention` or `would_block`.
- `impacted_files` -- sorted list of repository-relative paths the arm predicts the
  change reaches (excluding the changed files themselves).
- `risk_class` in `{api-signature-change, behavioral-change, benign-additive,
  benign-local}`.

The persisted decision record wraps this with `scenario_id` and `arm` (upper-cased).
Arm L additionally may carry `parse_failure` and `error`.

### 5.2 Arm G -- deterministic text-only baseline

Arm G is a name-grep gate with no graph and no model. For each changed symbol it
applies a frozen rule with threshold T = 3 (not re-tunable): flag when a definition
line was removed or modified and the symbol has at least one cross-file textual
reference at base, or when any changed symbol has at least T cross-file references.
Cross-file references are found with `git grep` at the base commit. Arm G is binary:
it emits `pass` or `would_block` only, never `needs_attention`. Dependencies: git
only; no Kin, no daemon, no model, no network. It is fully deterministic.

### 5.3 Arm K -- Kin semantic shadow gate (system under test)

Per scenario, Arm K: materializes a git worktree at `base`; builds the Kin graph cold
on a fresh graph directory and bootstraps the pinned daemon; runs the Kin shadow
review over the `base..head` range three times, enforcing byte-identity across passes
(section 6); and maps the resulting shadow report to the shared decision schema. It
returns the shared decision plus the three raw passes, the determinism block, and a
runtime-identity attestation of the daemon, CLI, and graph. `impacted_files` is the
union of the shadow report's blast-radius buckets (callers, dependents, contract
consumers, tests). Dependencies: the Kin CLI and the pinned Kin daemon (graph build is
GPU-backed), plus git. Cold-build environment pins embedding and warm caches off so
the measurement is not served from a prior run's cache.

### 5.4 Arm L -- language-model baseline (optional)

Arm L is a senior-engineer language-model reviewer with no graph. It is given the
unified diff and read-only grep and read tools scoped to the base worktree, under a
frozen system prompt, and asked for the same verdict vocabulary. It runs three passes
and records cross-pass variance; the scored decision is the first parsed pass, and if
every pass fails to parse the decision is an explicit `parse_failure`, never a silent
default. Dependencies: a language model served over an OpenAI-compatible endpoint (LM
Studio in the reference runs), plus git and local grep/read. Arm L is measured, not
required: transport and parse errors are recorded as proof-safe failure categories.

Arm L is operator-gated. It runs only when `l` is in the arms list. When it is not
selected, the run records `arm_l: null` and `model_runtime: null` and builds no model
executor. A run that selects `l` must resolve a valid model configuration with a base
URL and must have the model served in serial mode, or the run is refused or marked
non-citable. None of these conditions gate Arm K or Arm G.

---

## 6. Determinism requirements (bit-identical reruns)

The Kin arm must produce a byte-identical shadow report across three passes of a
scenario after canonicalization. This is the reproducibility gate.

Canonicalization before hashing (section 2.2 serialization) normalizes three classes
of non-semantic variation and compares everything else verbatim:

- Volatile value keys are neutralized to a sentinel wherever they appear at any depth.
  At minimum this covers the emit-time wall-clock stamp (`generated_at`).
- Accounting value keys are neutralized the same way. At minimum this covers the
  per-pass cold/warm hydration counter (`hydrated_changes`), which is a caching
  artifact, not a semantic difference.
- Absolute worktree and corpus path prefixes are folded to a repository sentinel
  inside every string leaf, so the hash is a property of report content, not its
  location.

Any other cross-pass difference -- a change in verdict, blast radius, findings, entity
set, or review mutations -- is a real varying failure and voids citability.

The gate evaluates `bit_identical` over the pass hashes: true only when more than one
pass is present and every pass hashes to the same value. A single pass can never
satisfy the gate. The per-scenario determinism block records `n`, the per-pass hashes,
`bit_identical`, the shared canonical digest when identical, the path prefixes folded,
and a substrate-trace flag. A citable run requires exactly three raw passes and
re-derives `bit_identical` from those raw passes so the determinism block cannot be
hand-authored.

The aggregate determinism block in the verdict carries `kin_bit_identical`,
`varying_scenarios`, `kin_substrate_verified`, `missing_substrate_trace_scenarios`,
and `n_scenarios`. The substrate trace confirms each Kin pass actually came from the
Kin review tool (its audit block names the tool, a tool version, and an emit time, and
the determinism block carries a shared canonical digest over enough passes), guarding
against a well-formed report that did not come from the substrate under test.

---

## 7. Block-seal semantics

Block seal is the mechanism that binds a run's measurements to one frozen graph state
per repository, so that no scenario can be measured against a graph that a later
scenario silently mutated. It is selected with a run flag and recorded as
`prep_regime = v2.1-per-repo-block-seal`. The regime is decided by the artifact, not by
a claim: a bundle that claims block seal without its block record is rejected, and a
bundle that carries a block record without claiming the regime is rejected.

### 7.1 Graph state and the authoritative invariant

The graph state captured for a repository is `{content_sha256, graph_root_hash,
graph_generation}`. Of these, only `graph_root_hash` -- the daemon's entity Merkle
root -- is the semantic-authority invariant asserted across a measured command. The
content digest and the generation counter legitimately move as the embedding worker
writes derived-index snapshots; asserting them would produce false alarms. The graph
root is fetched only when the graph identity reports itself consistent (valid, no
broken chains, all checked entities accounted for) and is a lower-cased 64-hex value.

### 7.2 Seal observation

A seal observation is captured in a fixed order: the full graph manifest first, then a
fresh daemon identity. The observation is decorated with a graph-seal boundary that
records a schema tag, the capture order, the manifest digest, and the manifest content
digest. A validator requires that boundary to have exactly those fields, the expected
schema and capture order, and a manifest that can be resolved from the observation
graph catalog (section 7.4).

### 7.3 Digest-only stamps

Observations do not embed the full per-file graph manifest -- for a large repository
that would be hundreds of megabytes per stamp. Instead each observation carries a
compact summary: a schema tag, the manifest digest, a file count, a byte total, an
excluded-volatile-path count, an excluded-volatile-paths digest, and a content digest.
Seals cite their evidence by digest rather than restating it: the seal observation
digest, the sealed graph-state digest, and the block-seal digest. A stamp points at
its evidence rather than carrying it.

`[NOTE]`: these two mechanisms are sometimes tracked internally under issue or
pull-request identifiers. Those identifiers are not tokens in the source and should not
be grepped for; the mechanism is what matters and is described here.

### 7.4 Reconstructable-seal binding

A digest-only summary is only trustworthy if the full manifest it names can be
reconstructed and re-derived. The full manifest is retained once, in a content-
addressed catalog of deltas. Every summary's manifest digest is resolved back to a
full manifest through that catalog, and the validator rejects any summary whose
manifest is not reconstructable, as well as any pre-catalog stamp that carried only a
summary with no catalog link. This is the property that lets a compact stamp stand in
for a large manifest without loss of checkability.

### 7.5 Ranges requiring hydration

`ranges_requiring_hydration` is a list of `{base, head}` objects, not a single
digest. It records exactly which ranges in a block actually paid a lazy-hydration
walk. A range is excluded (cost-free) only when its first recorded hydration attempt
reported zero changes and hit no timeout; otherwise it is listed. When bases share
ancestry and the prep order collapses the walks, this list can be as short as a single
range. The whole block-seal record (which contains this list) is fingerprinted as a
single block-seal digest.

### 7.6 Block-seal record

For each repository the block seal prepares one graph, hydrates every range in the
block to a zero-change fixpoint, seals, and binds all the block's scenarios to that one
sealed state. The record carries a schema tag, the repository root, the ranges in
dataset order and their count, per-attempt hydration records, hydration order and
depths, `ranges_requiring_hydration`, a preparation block (regime, materialized base,
run token, fresh worktree, init command, cold environment, CLI digest, initial graph
content digest, and the full prepared manifest), the sealed graph state and its
digest, the seal observation and its digest, a block responder-identity digest, the
prep regime, the scenario identifiers, and a cleanup terminator scenario. A mid-block
mutation trips the graph-root binding for the mutating scenario and every scenario
after it, so cross-scenario contamination surfaces rather than hiding.

The per-arm `arm_identity` object hashed, together with the common identity, into each
ledger `identity_sha256` is enumerated in section 14. For Arm K it attests the Kin CLI
and daemon binary pins, their self-reported build identifiers, and the daemon
behavior-environment; for Arm G it is empty; for Arm L it is the model-configuration and
served-model runtime identities. The common-identity object is enumerated in section 11.3.

---

## 8. Metrics

All metrics are pure functions of the arms' decisions and the gold labels. Nothing in
the scorer favors an arm. This section defines the axes; it carries no result figures.

### 8.1 Flag decision (primary trust axis)

Positive = flag. Over the paired lists of predicted flags and gold `should_flag`:

```
precision   = tp / (tp + fp)
recall      = tp / (tp + fn)
f1          = 2 * precision * recall / (precision + recall)
specificity = tn / (tn + fp)
accuracy    = (tp + tn) / n
```

with the usual zero-guard when a denominator is zero. The confusion block records
`n, tp, fp, tn, fn` and all five derived rates. A `flag_high_confidence` variant
applies the same math to the subset of scenarios whose label provenance confidence is
high.

### 8.2 V8 verdict-aware scoring

The arms emit a three-way verdict; a binary flag score collapses `needs_attention`
into a hard failure and so over-penalizes a soft attention. V8 is a semantics
correction that scores the three verdicts on their own terms while leaving the gold
labels untouched:

- Primary block: positive prediction is `verdict == would_block` only (a
  `needs_attention` is not a positive prediction on this axis); positive gold is a
  dangerous merge. It reuses the section 8.1 confusion math.
- Secondary soft-attention rate: the share of rows landing on `needs_attention`, split
  by gold label (dangerous vs benign).
- Residual table: every benign-labeled `needs_attention` row is classified against a
  checked-in `scenario_id -> classification` mapping whose values must be one of
  `{product_correct_soft_attention, partial_precision_issue, true_inaccuracy}`. A
  benign near-block that is not in the mapping defaults to `true_inaccuracy` and sets a
  fail-loud hard stop -- an unexplained benign near-block must be reviewed, never
  silently absorbed.

The verdict semantics are recorded verbatim in the bundle: pass means no meaningful
runtime or product risk found; needs_attention means a real behavior or surface change
with consumer impact but insufficient evidence to block; would_block means strong
graph evidence of an unsafe or breaking merge.

### 8.3 Impacted-set overlap (blast-radius axis)

Micro-averaged over a single basis stratum: precision is total intersection over total
predicted size, recall is total intersection over total gold size, plus F1 and a
macro-averaged Jaccard over scenarios with a non-empty union. This axis is reported
split by basis (symbol-referenced-repair vs local-self) and never pooled into one
headline.

### 8.4 Risk-class agreement

A per-scenario agreement between the arm's product signal and the gold risk class,
under a fixed mapping: an api-signature-change gold needs a flag with a signature-
change risk class; a behavioral-change gold needs any flag; a benign gold needs a
pass.

There is no per-scenario winner. The flag decision is binary with no partial credit;
arm comparison is aggregate, through the paired statistics of section 9.

---

## 9. Paired statistics protocol

The K-vs-baseline comparison is scenario-paired and frozen. Constants:
bootstrap resamples = 10000, bootstrap seed = 20260703, significance level = 0.05.

### 9.1 McNemar (exact)

Two-sided exact binomial McNemar on the discordant pairs of per-scenario correctness
(correctness = prediction equals gold), with a null probability of one half. No
continuity correction and no chi-square approximation.

```
n01 = count(a correct and b wrong)
n10 = count(a wrong and b correct)
n   = n01 + n10
if n == 0: p_value = 1.0
else:
    k    = min(n01, n10)
    tail = sum(comb(n, i) for i in 0..k) * (0.5 ** n)
    p_value = min(1.0, 2.0 * tail)
```

### 9.2 Paired bootstrap over delta-F1

The statistic is delta-F1 = F1(arm) minus F1(baseline) on the flag decision. The point
estimate is computed on the real data. Each of the 10000 resamples draws n scenario
indices with replacement from a generator seeded at 20260703, and the same drawn
indices index gold, arm, and baseline so the pairing is preserved. The 95 percent
confidence interval is the 2.5th and 97.5th percentiles by linear interpolation.
`excludes_zero` is true when the interval lies entirely above or entirely below zero.

### 9.3 Decision rule

The arm "beats" the baseline iff the bootstrap interval excludes zero and the McNemar
exact p-value is below the significance level; otherwise the verdict is a tie. The
direction is reported from the sign of delta-F1. The verdict carries the McNemar
block, the bootstrap block, the paired count, the verdict, and the direction.

---

## 10. Preregistration rules

The protocol, scoring, statistics, arm-decision schema, and source boundary are frozen
before a run and re-checked per stamp.

- `protocol` is the literal `merge-trust-prereg-v1`; any other value is rejected.
- `protocol_commit` is the harness git HEAD at run time. A citable run refuses unless
  the tree is clean, the recorded head matches the expected commit, and the commit is
  not unknown.
- The frozen harness source set is sealed into a harness-source manifest (schema
  `kin.merge-trust-harness-source.v1`) whose content digest binds the schema, the file
  list (each file's path, size, and digest), and the tool list. Every stamp must carry
  a matching manifest, or it is rejected as differing from the frozen evaluator.
- `prep_regime` is present as the block-seal regime only when block seal is selected,
  and its presence must agree with the presence of the block-seal record.
- The decision fields and the verdict and flag vocabularies are frozen; the primary
  comparison requires both Arm K and Arm G complete with zero parse failures.
- The statistics constants (resamples, seed, significance level) are frozen in code.
- The V8 residual classification mapping is checked in and authoritative; a malformed
  mapping fails loud rather than degrading to no classifications.

---

## 11. Evidence bundle format

A run's top-level bundle is four files, plus a per-scenario artifact tree. They are
written in this order: provenance first, the segment ledger checkpointed after every
arm, then the decisions file and the verdict at the end.

### 11.1 provenance.json

The run's environment attestation. Keys:

- `protocol`, `protocol_commit`, `generated_at`, `platform`.
- `arms` -- the arms run.
- `dataset` -- `{path, sha256, n}` plus optional `records_array_sha256` and
  `raw_file_sha256` (section 4).
- `binaries` -- `kin`, `kin_daemon`, `harness`, `eval_runtime`, each `{path, sha256}`
  (each digest is a file digest of the named binary).
- `command` -- `{argv, cwd}`.
- `environment` -- `{launch, injected}`; injected records per-arm environment (for Arm
  K, the daemon binary and the cold-cache pins).
- `harness_source_manifest` -- `{schema, files[{path, sha256, size}], tools[{name,
  path, sha256}], content_sha256}` (section 10). The content digest is the identity
  digest (section 2.1) of `{schema, files, tools}`.
- `source_control` -- `{schema, clean, dirty_entry_count, head, expected_commit,
  head_matches_expected, git_path, git_sha256, repo_root, status_sha256}`. The status
  digest is a text digest of the porcelain status.
- `hygiene` -- `{allow_unclean, block_seal, env_scan{benign, stray}, lmstudio,
  openai_env}`.
- `model_runtime` and its alias `arm_l` -- null unless Arm L is selected.
- `prep_regime` when block seal is selected; `block_execution_order` when a block
  order is set.

### 11.2 verdict.json

The scored outcome. Keys: `protocol`, `protocol_commit`, `generated_at`, `dataset`,
`arms`; `scores` (per arm: `flag`, `flag_high_confidence`, `risk_class`,
`impacted_by_basis` split into symbol-referenced-repair and local-self, `scored_n`,
`parse_failures`); `paired` (`k_vs_g` and `k_vs_l`, each the section 9 block or null);
`v8` (the section 8.2 blocks: `semantics`, `primary_block`, `secondary_soft_attention`,
`legacy_overstrict`, `legacy_note`, `residual`, `residual_arm`, `hard_stop`,
`hard_stop_reason`); `determinism` (section 6 aggregate block); `hygiene_precheck`
(`{env_clean, lmstudio_serial}`); `provenance_gate` (`{ok, reasons, ledger}`, where
`ledger` is the full segment ledger, byte-equal to segments.json); and the citability
prechecks (`citable_eligible_precheck`, `citable_reasons`, `citable_note`). The note
records that the authoritative citability stamp is the separate rerun gate, not this
precheck.

### 11.3 segments.json (the segment ledger)

Schema `kin.merge-trust-segment-ledger.v1`. Top-level keys: `schema`, `run_id`,
`authoritative_source` (per-arm-v2-provenance), `selected_stamp_count` (records times
arms), `readable_stamp_count`, `validated_stamp_count`, `segments`, and `content_sha256`.
The content digest is the identity digest (section 2.1) of the ledger with the
`content_sha256` key removed. This is the ledger's self-check and the strongest digest
recomputable from the bundle alone.

Each segment carries `segment_id`, `produced_at`, `harness_commit`,
`common_identity_sha256`, and `arm_writes` (sorted by scenario then arm). The common
identity is the identity digest of a common object comprising `{protocol,
harness_commit, harness pin, eval_runtime pin, dataset, platform, environment,
harness_source_manifest, source_control}`.

Each arm write carries `scenario_id`, `arm` (upper-cased), `written_at`,
`identity_sha256` (the identity digest of `{common, arm: arm_identity}`),
`provenance_path` (relative path to that scenario-arm's stamp), `stamp_sha256` (the
file digest of that stamp), and `artifact_set_sha256` (from the stamp's artifacts
manifest). Within a segment, an arm's `identity_sha256` is constant across scenarios,
because it depends only on the common identity and the arm's configuration identity;
`stamp_sha256` and `artifact_set_sha256` vary per scenario. The ledger is a
deterministic function of the sealed per-arm stamps: on a verified rebuild it must
match the on-disk ledger exactly.

### 11.4 decisions.jsonl

One line per scenario-arm pair, in dataset record order then arm order, emitted only
where a decision exists. Each line is the flat decision record: `scenario_id`, `arm`
(upper-cased), `verdict`, `flag`, `impacted_files`, `risk_class` (and for Arm L,
optionally `parse_failure` and `error`). Serialized with sorted keys and default
separators.

### 11.5 Per-scenario artifact tree (referenced, not in the four-file bundle)

Under `scenarios/<scenario_id>/arm_<arm>/`: `decision.json`; for Arm K the three raw
passes and a determinism `hashes.json`; for Arm L the raw passes and a `variance.json`;
and a per-arm `provenance.json` stamp (schema `kin.merge-trust-arm-provenance.v2`)
written last as the completion marker. The stamp embeds the runtime identity (carrying
the block-seal digest, the observation graph catalog, the graph preparation, and the
command bindings) and an artifacts manifest (schema `kin.merge-trust-arm-artifacts.v1`:
`{schema, files[{path, size, sha256}], artifact_set_sha256}`), plus a stamp-payload
digest. Full replication of a bundle checks these too; the standalone verifier that
ships with this spec checks the four top-level files and the ledger they reference.

The input to `artifact_set_sha256` (the arm-artifacts manifest digest) is the identity
digest (section 2.1) of the manifest's path-sorted `{path, size, sha256}` file-entry list
alone, as detailed in section 14; the schema tag and the digest field itself are excluded.
Full per-scenario stamp verification still requires the per-scenario tree, not just the
four-file bundle.

---

## 12. Reproduction and citability

Two gates separate an internally consistent bundle from a citable one:

- The harness precheck in the verdict (`citable_eligible_precheck`) is advisory. It
  reflects hygiene, determinism, provenance-gate, and parse-failure conditions the
  harness could see at scoring time.
- The authoritative citability stamp is a separate rerun gate over a pinned release
  tag, run outside the harness. A citable claim rests on that gate, on a clean source
  tree at the recorded commit, on the block-seal regime being present and internally
  consistent, and on the determinism gate holding across the cohort.

A bundle that fails any hard check (a determinism varying failure, an unexplained
benign near-block, a dataset-identity mismatch, a harness-source mismatch) is
non-citable by construction.

---

## 13. Reimplementation checklist

A stranger reimplementing merge-trust prereg v1 must:

1. Reproduce the three hashing primitives of section 2 exactly, including the
   `ensure_ascii` and separator differences among them.
2. Define the scenario record and gold schema of section 3, and build a dataset whose
   two digest families (section 4) are computed as specified and are order-sensitive.
3. Implement the shared decision schema and verdict vocabulary of section 5.1.
4. Implement Arm G's frozen text rule with threshold T = 3 (section 5.2), git-only.
5. Implement Arm K against the graph substrate: cold build, pinned daemon, three shadow
   passes, decision mapping, and the runtime-identity attestation (section 5.3).
6. Optionally implement Arm L as a gated model baseline with the frozen prompt and the
   first-parsed-pass rule (section 5.4).
7. Implement the determinism gate: three passes, the canonicalization normalizations,
   and the bit-identity rule with the single-pass exclusion (section 6).
8. Implement block seal: graph-root binding, the seal observation and its ordered
   capture, digest-only stamps, the reconstructable catalog, the hydration-range list,
   and the block-seal record (section 7).
9. Implement the scorer: flag score, V8 primary block and soft-attention and residual
   table, impacted-set overlap split by basis, and risk-class agreement (section 8).
10. Implement the paired statistics with the frozen constants and the exact McNemar and
    paired bootstrap (section 9).
11. Enforce the preregistration checks: protocol constant, protocol commit and clean
    tree, harness-source manifest, prep-regime agreement, and frozen vocabularies
    (section 10).
12. Emit the four-file bundle and per-scenario tree of section 11 with the ledger self-
    check and the per-stamp digests.
13. Confirm a rerun is bit-identical and passes the standalone verifier that ships with
    this spec.

---

## 14. Protocol details confirmed against the reference implementation

These were the last open protocol details at v1.0. Each has now been read directly from
the reference implementation and is stated here as a confirmed part of the protocol. This
section carries no measured result figures, only mechanism.

- Ledger `identity_sha256` is the identity digest (section 2.1) of `{common, arm}`, where
  `common` is the common-identity object of section 11.3 and `arm` is a per-arm identity
  object. For Arm K that per-arm object attests the Kin runtime that produced the pass:
  the Kin CLI binary pin (its path and file digest), the configured Kin daemon binary pin
  (its path and file digest), the daemon's and the CLI's self-reported build identifiers
  read back from the running graph, and the daemon behavior-environment captured at
  bootstrap (the cold-cache and embedding pins that determine how it answers). For Arm G
  the object is empty -- the deterministic text arm attests no runtime. For Arm L it is
  the resolved model-configuration identity together with the attested served-model
  runtime identity.
- `artifact_set_sha256` in the arm-artifacts manifest is the identity digest (section
  2.1) of the manifest's file-entry list alone: the path-sorted array of one `{path,
  size, sha256}` object per sealed artifact, where `path` is the arm-directory-relative
  filename, `size` is its byte length, and `sha256` is the file digest (section 2.4) of
  that artifact. The manifest's schema tag and the `artifact_set_sha256` field itself are
  not part of the hashed input, and the verifier recomputes the digest over the entry
  list to check it.
- `stamp_payload_sha256` is the identity digest (section 2.1) of the entire per-arm v2
  stamp object -- its schema tag, stamp mode and attribution, the protocol and harness
  commit, the run and segment identifiers, the produced/written/recorded timestamps, the
  scenario id and arm, the binary set and its per-binary digests, the command,
  environment, harness-source manifest, source-control block, model runtime,
  runtime-identity attestation, hygiene block, platform, and dataset block and digest,
  plus the embedded artifacts manifest -- with only the `stamp_payload_sha256` field
  itself excluded, because it is computed before being inserted. The stamp is then
  persisted with that payload digest embedded, and the ledger's `stamp_sha256` is the file
  digest (section 2.4) of the persisted stamp bytes. The two digests therefore nest: the
  payload digest binds the stamp's canonical content independent of serialization, and the
  file digest binds the exact bytes handed out, which already contain the payload digest.
  Full per-scenario stamp verification requires the per-scenario tree, not just the
  four-file bundle.
- The older-sidecar dataset-identity fallback (section 4) is a backward-compatibility
  path, not a gap. The run driver recomputes the records-array digest (section 2.3) from
  the loaded records and refuses the run unless it equals the sidecar's declared primary
  digest (`dataset.sha256`); the raw-file and explicit records-array digests are carried
  through from the sidecar unmodified and are absent on sidecars written before the
  dual-digest convention. A verifier must therefore treat `raw_file_sha256` (and the
  `records_array_sha256` alias) as optional, while dataset identity stays fully enforced
  through the primary digest regardless of sidecar vintage. The reference datasets that
  ship with the harness currently carry only the primary digest, so an external
  replicator should expect these optional fields to be absent.
