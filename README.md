# Kin merge-trust benchmark — specification & verifier

This repository is the **public, reimplementable specification** of Kin's merge-trust
review benchmark, together with a **standalone, dependency-free verifier** for the sealed
evidence bundles the benchmark emits.

Merge-trust asks a focused question: given a proposed change to a real repository, should
it be trusted before it is merged, and what else does it impact? Each reviewer ("arm")
answers from a different substrate, and the benchmark isolates that substrate as the only
variable. See [`SPEC.md`](SPEC.md) for the full protocol.

## What is here

| File | What it is |
|---|---|
| [`SPEC.md`](SPEC.md) | The pre-registered protocol (prereg v1): hashing primitives, scenario and gold schema, arm contracts, determinism gate, block-seal mechanism, scorer, and paired-statistics protocol — written so a stranger can build a compatible harness. Carries no result figures. |
| [`verify_bundle.py`](verify_bundle.py) | A standalone verifier for a sealed evidence bundle. Python standard library only — no Kin, no daemon, no network, no third-party packages. |
| [`TRANSPARENCY.md`](TRANSPARENCY.md) | Why the specification and verifier are open while the runner and proof infrastructure stay private for now, and how the two relate. |
| [`LICENSE`](LICENSE) | License for this specification and verifier. |

## What is *not* here

The **runner and proof infrastructure** — the orchestration, the pinned-release proof
gate, and the hosted measurement environment — are proprietary and are not part of this
repository. This surface is the spec and the verifier; the runner opens later, if at all.
See [`TRANSPARENCY.md`](TRANSPARENCY.md).

This repository also carries **no measured result figures**. It describes the mechanism
and the protocol constants a stranger needs to reimplement or check the benchmark, not any
run's outcome.

## Verifying a sealed evidence bundle

The verifier reads the four top-level files of a bundle
(`provenance.json`, `verdict.json`, `segments.json`, `decisions.jsonl`) and reports one
line per check.

```bash
# Requires Python 3.8+ (standard library only).
python3 verify_bundle.py path/to/bundle/

# Optionally recompute the dataset digests from the run's dataset file:
python3 verify_bundle.py path/to/bundle/ --dataset path/to/dataset.jsonl

# Machine-readable output:
python3 verify_bundle.py path/to/bundle/ --json
```

The verifier is deliberately conservative. It recomputes every digest that is checkable
from the bundle alone (the segment-ledger content digest, the harness-source-manifest
digest, and — when the dataset is supplied — both dataset digests), checks internal
consistency (counts agree across files, the determinism block is coherent, the
confusion-matrix arithmetic reproduces the declared metrics, and the per-arm decisions
reconcile with the score block without any hidden label), and reports anything it cannot
recompute as *declared* rather than trusting it silently. A single failing check sets a
non-zero exit code.

## How to read a result

A bundle names its declared actors with content-addressed identifiers, and a rerun of the
same inputs is reproducible down to the byte. The verifier confirms that a bundle is an
internally consistent, self-checking record of whatever run produced it — it does not
re-execute the substrate. Describe results in those terms: declared actors,
content-addressed identifiers, and reproducible reruns.
