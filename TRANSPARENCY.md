# Kin benchmark transparency posture

Status: v1.1, 2026-08-12. Protocol frozen; results published separately upon independent
verification.

## Statement

Kin's core is open. The semantic engine and the repo substrate are Apache-2.0, and the
benchmark that measures them is being opened along a deliberate boundary. The benchmark
specification is written to be reimplementable by a stranger, and every run emits a
sealed evidence bundle that an open, dependency-free verifier can check: the bundle names
its declared actors with content-addressed identifiers, and a rerun of the same inputs is
reproducible down to the byte. What stays private for now is the runner and the proof
infrastructure, meaning the orchestration, the pinned-release proof gate, and the hosted
measurement environment, because that is where the operational and, potentially,
patent-relevant mechanism lives. The direction is one-way: the spec and the verifier open
first, sealed bundles become checkable by outsiders, and independent replication is
planned so the measurement does not rest on our word alone.

## FAQ

Why is the runner private?

The runner is the operational harness. It drives the graph substrate, the daemon, the GPU
proof window, and the pinned-release gate that decides whether a result is citable. Some
of its mechanism, including the block seal, the reconstructable digest-only stamps, and
the graph-root binding, may be patent-relevant, and the whole pipeline is where a run can
be made honest or made to lie. Opening the spec and a standalone verifier gives outsiders
what they need to check a claim without handing over the machine that produced it. The
runner can open later; the order is intentional.

How do I verify a claim?

Take the sealed evidence bundle behind the claim and run the open verifier against it.
The verifier is Python standard library only, with no Kin, no daemon, and no network. It
confirms the bundle's shape, recomputes the digests that are checkable from the bundle
alone, and checks internal consistency. The README lists digest by digest what it
recomputes and what it can only report as declared.

Where do I get a bundle?

From whoever makes the claim. Bundles are emitted by the runner, which is private, so
this repository does not distribute them, and it ships no measured result of its own.
That is the honest limit of what is open today: you can read the protocol and run the
verifier, but a Kin run's bundle has to be handed to you. Until then,
`make_example_bundle.py` writes a synthetic bundle that exercises the verifier end to
end. It carries no measured result and is not evidence about Kin.

How would I reimplement the benchmark?

Read the specification. It pins the hashing primitives, the scenario and gold schema, the
two dataset-identity families, the arm contracts, the determinism gate, the block-seal
mechanism, the scorer, and the paired-statistics protocol, and it ends with a
reimplementation checklist. A stranger following it can build a compatible harness and,
against a shared dataset, produce bundles that the same open verifier accepts.
