# Kin merge-trust benchmark: specification and verifier

This repository is the public specification of Kin's merge-trust review benchmark and a
standalone verifier for the sealed evidence bundles the benchmark emits. The verifier is
Python standard library only. It needs no Kin, no daemon, and no network.

Merge-trust asks a focused question: given a proposed change to a real repository, should
it be trusted before it is merged, and what else does it impact? Each reviewer, called an
arm, answers from a different substrate, and the benchmark isolates that substrate as the
only variable. [`SPEC.md`](SPEC.md) carries the full protocol.

## What you can do here today

**Reimplement the protocol.** [`SPEC.md`](SPEC.md) pins the hashing primitives, the
scenario and gold schema, the arm contracts, the determinism gate, the block-seal
mechanism, the scorer, and the paired-statistics protocol, and it ends with a
reimplementation checklist. It is written so a stranger can build a compatible harness.

**Check a bundle you have been handed.** The verifier reads the four top-level files of a
bundle and prints one line per check. A single failing check sets a non-zero exit code.

```bash
# Requires Python 3.8+ (standard library only).
python3 verify_bundle.py path/to/bundle/

# Recompute the dataset digests from the run's dataset file:
python3 verify_bundle.py path/to/bundle/ --dataset path/to/dataset.jsonl

# Machine-readable output:
python3 verify_bundle.py path/to/bundle/ --json
```

**Watch the verifier work before you have a bundle.** This repository generates a
synthetic example bundle you can run against:

```bash
python3 make_example_bundle.py example-out/
python3 verify_bundle.py example-out/bundle/ --dataset example-out/dataset.jsonl
```

That bundle carries no measured result and is not evidence about Kin. Every scenario is
invented and every score is a made-up but internally consistent toy. What it shows you is
the mechanism. The verifier accepts a bundle of the shape section 11 of the specification
describes, and it rejects a copy whose ledger digest, metric arithmetic, decision
reconciliation, verdict vocabulary, or commit chain has been altered. CI runs exactly
that sequence on every change, so a regression in the verifier or in one of the digest
primitives turns the build red.

## What the verifier checks, and what it does not

The verifier is conservative by design. Anything it cannot recompute from the bundle
alone is reported as declared rather than trusted silently, and the report says which is
which.

| Declared value | What the verifier does with it |
|---|---|
| `segments.json` `content_sha256` | Recomputes the canonical digest over the ledger and compares |
| `verdict.provenance_gate.ledger` `content_sha256` | Recomputes it, and requires the embedded ledger to equal `segments.json` |
| `harness_source_manifest.content_sha256` | Recomputes it over the schema, file list, and tool list |
| `dataset.sha256`, `dataset.raw_file_sha256` | Recomputes both from the dataset file when you pass `--dataset`, otherwise reports them as declared |
| Every other `*_sha256` field, at any depth | Checks it is 64 lowercase hex, including the binary pins and the per-stamp digests |
| `identity_sha256`, `stamp_sha256`, `artifact_set_sha256`, `common_identity_sha256` | Format only. Recomputing these needs the per-scenario artifact tree, which is not part of the four-file bundle |
| Counts, determinism block, confusion arithmetic, decisions, paired statistics | Recomputed and cross-checked internally, with no gold label required |

Concretely, the internal consistency checks confirm that scenario and stamp counts agree
across files, that the determinism block is coherent, that every verdict is in the frozen
vocabulary and each flag follows its verdict, that the confusion-matrix arithmetic
reproduces the declared metrics, that each arm's decisions reconcile with its score
block, and that `protocol_commit` agrees with the source-control head and the ledger's
harness commit.

The verifier does not re-execute the substrate, and it cannot tell you whether a run's
gold labels are right. It tells you whether a bundle is an internally consistent,
self-checking record of whatever run produced it.

## What is not here

The runner and the proof infrastructure, meaning the orchestration, the pinned-release
proof gate, and the hosted measurement environment, are proprietary and are not part of
this repository. Bundles come from that runner, so this repository does not distribute
them. The surface here is the specification and the verifier. See
[`TRANSPARENCY.md`](TRANSPARENCY.md) for why the boundary sits where it does.

This repository also carries no measured result figures. It describes the mechanism and
the protocol constants a stranger needs to reimplement or check the benchmark, not any
run's outcome.

Materials that cite Kin's Multi-SWE-Bench determinism study are citing a different
benchmark from the one specified here. That study's protocol, figures, and evidence
artifacts live at [firelock.ai/labs/kin-proof](https://firelock.ai/labs/kin-proof). This
repository neither specifies nor scores it.

## How to read a result

A bundle names its declared actors with content-addressed identifiers, and a rerun of the
same inputs is reproducible down to the byte. A passing verifier run means the bundle is
internally consistent and its recomputable digests hold. Describe results in those terms:
declared actors, content-addressed identifiers, and reproducible reruns.

## Files

| File | What it is |
|---|---|
| [`SPEC.md`](SPEC.md) | The pre-registered protocol, prereg v1. Carries no result figures. |
| [`verify_bundle.py`](verify_bundle.py) | The standalone bundle verifier. Standard library only. |
| [`make_example_bundle.py`](make_example_bundle.py) | Writes the synthetic example bundle used above. No measured result. |
| [`TRANSPARENCY.md`](TRANSPARENCY.md) | Why the specification and verifier are open while the runner stays private. |
| [`LICENSE`](LICENSE), [`NOTICE`](NOTICE) | Apache License 2.0, and the attribution notice it requires. |
