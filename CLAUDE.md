> **Umbrella guidance:** the workspace-root `AGENTS.md` is the source of truth for cross-repo thesis, boundaries, and rules. This file is the repo-specific authority for `kin-bench-spec`.

# kin-bench-spec

The public specification of Kin's merge-trust review benchmark, and a standalone verifier for the
sealed evidence bundles it emits (manifest layer `support`, role
`public-benchmark-spec-and-verifier`). It exists so a stranger can check a proof bundle without the
private runner. `kin-bench`, the runner itself, stays private per IP strategy, and nothing from it
belongs here.

`SPEC.md` is the protocol. `verify_bundle.py` is the verifier and `make_example_bundle.py` builds a
synthetic bundle to run it against. Python 3.8 or newer, standard library only: no Kin, no daemon,
no network.

## Commands

```bash
python3 verify_bundle.py path/to/bundle/
python3 verify_bundle.py path/to/bundle/ --dataset path/to/dataset.jsonl
python3 verify_bundle.py path/to/bundle/ --json

python3 make_example_bundle.py example-out/
python3 verify_bundle.py example-out/bundle/ --dataset example-out/dataset.jsonl
```

The verifier prints one line per check, and a single failing check sets a non-zero exit code.

## Gates

One graded job, `verifier`, the required context on main, with a five-minute timeout. Each step is
there because a weaker suite would pass a broken verifier:

- compiles both scripts and runs each `--help`
- proves the verifier fails closed on a missing bundle
- generates the example bundle and requires `RESULT: PASS` with no `[FAIL]`, `[WARN]` or `[SKIP]`
- regenerates and `diff -r`s the two runs, so the generator must be byte-identical across runs
- tampers with five things (the ledger digest, a metric, a decision link, the verdict vocabulary,
  the commit chain) plus the dataset, and requires each to be rejected by its own named check

That last step is what proves the accept step is not a no-op, so do not weaken it. A verifier change
that keeps the happy path green while losing a rejection is exactly the defect it catches.

## Non-obvious behaviour

**The gate refuses any non-ASCII byte** in `README.md`, `SPEC.md`, `TRANSPARENCY.md`, `NOTICE`,
`LICENSE`, `verify_bundle.py` and `make_example_bundle.py`. One em dash or one curly quote in any of
them turns the required context red. That is deliberate for a document a stranger reimplements from,
so write ASCII punctuation rather than adding an exemption.

## Landing

Hosted merge queue, ruleset `Merge queue on main`, active. The one required status context is
`verifier`, through classic branch protection with `strict: false`, so a PR need not be up to date
with main. The queue mints the squash commit verbatim from the PR title and body, so get both right
before arming. From the umbrella root, `bin/kin-lane merge enqueue kin-bench-spec <lane> <pr>` then
`bin/kin-lane merge land kin-bench-spec <lane> <pr>`. Commit with `git commit -s`.
