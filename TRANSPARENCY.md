# Kin benchmark transparency posture -- DRAFT

## Statement

Kin's core is open. The semantic engine and the repo substrate are Apache-2.0, and the
benchmark that measures them is being opened along a deliberate boundary. The benchmark
specification is written to be reimplementable by a stranger, and every run emits a
sealed evidence bundle that anyone can check with an open, dependency-free verifier: the
bundle names its declared actors with content-addressed identifiers, and a rerun of the
same inputs is reproducible down to the byte. What stays private for now is the runner
and the proof infrastructure -- the orchestration, the pinned-release proof gate, and the
hosted measurement environment -- because that is where the operational and, potentially,
patent-relevant mechanism lives. The direction is one-way: the spec and the verifier open
first, sealed bundles become checkable by outsiders, and independent replication is
planned so the measurement does not rest on our word alone.

## FAQ

Why is the runner private?

The runner is the operational harness: it drives the graph substrate, the daemon, the
GPU proof window, and the pinned-release gate that decides whether a result is citable.
Some of its mechanism -- the block seal, the reconstructable digest-only stamps, and the
graph-root binding -- may be patent-relevant, and the whole pipeline is where a run can be
made honest or made to lie. Opening the spec and a standalone verifier gives outsiders
what they need to check a claim without handing over the machine that produced it. The
runner can open later; the order is intentional.

How do I verify a claim?

Take the sealed evidence bundle for the claim and run the open verifier against it. The
verifier is Python standard library only -- no Kin, no daemon, no network. It confirms the
bundle's shape, recomputes the digests that are checkable from the bundle alone (the
segment-ledger content digest, the harness-source-manifest digest, and, when you supply
the dataset file, both dataset digests), and checks internal consistency: the scenario and
stamp counts agree across files, the determinism block is coherent, the confusion-matrix
arithmetic reproduces the declared metrics, and the per-arm decisions reconcile with the
score block without needing any hidden label. Anything the verifier cannot recompute from
the bundle is reported as declared rather than trusted silently.

How would I reimplement the benchmark?

Read the specification. It pins the hashing primitives, the scenario and gold schema, the
two dataset-identity families, the arm contracts, the determinism gate, the block-seal
mechanism, the scorer, and the paired-statistics protocol, and it ends with a
reimplementation checklist. A stranger following it can build a compatible harness and,
against a shared dataset, produce bundles that the same open verifier accepts.
