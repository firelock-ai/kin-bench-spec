#!/usr/bin/env python3
"""Write a synthetic example bundle that verify_bundle.py accepts.

THE BUNDLE THIS WRITES CARRIES NO MEASURED RESULT. It is not a Kin run and it is
not evidence about Kin. Every scenario id is invented, every digest is the hash of
a label string, and every scoreboard number is a made-up but internally consistent
toy chosen so the verifier's arithmetic checks have something to reproduce. Its one
job is to be a well-formed bundle of the shape SPEC.md section 11 describes, so the
verifier can be exercised end to end by anyone, with no access to a Kin run.

Stdlib only, same as the verifier. Output is deterministic: timestamps are frozen
and no randomness is used, so two runs write byte-identical files.

    python3 make_example_bundle.py out/
    python3 verify_bundle.py out/bundle/ --dataset out/dataset.jsonl

The digest and metric helpers below are the ones SPEC.md section 2 and section 8.1
define. They are written out again here rather than imported, so this file doubles
as an executable reading of those definitions.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os

PROTOCOL = "merge-trust-prereg-v1"
COMMIT = "0123456789abcdef0123456789abcdef01234567"
RUN_ID = "merge-trust-example-synthetic"
SEGMENT_ID = "segment-example-0001"
ARMS = ["k", "g"]
TS = "2026-01-01T00:00:00Z"
SCENARIOS = [
    "mtrust__example_repo__benign__000001",
    "mtrust__example_repo__benign__000002",
    "mtrust__example_repo__regfix__000003",
    "mtrust__example_repo__revert__000004",
]


def label_digest(label: str) -> str:
    """A synthetic but stable 64-hex digest, derived from a label string."""
    return hashlib.sha256(("kin-bench-spec-example:" + label).encode("utf-8")).hexdigest()


def canonical_digest(obj: object) -> str:
    """SPEC.md section 2.1: compact separators, sorted keys, escaped non-ascii."""
    text = json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def dataset_records_digest(records: list) -> str:
    """SPEC.md section 2.3: default separators, sorted keys, order sensitive."""
    return hashlib.sha256(json.dumps(list(records), sort_keys=True).encode()).hexdigest()


def confusion(tp: int, fp: int, tn: int, fn: int) -> dict:
    """SPEC.md section 8.1, with the zero guard on every denominator."""
    n = tp + fp + tn + fn
    precision = tp / (tp + fp) if (tp + fp) else 0.0
    recall = tp / (tp + fn) if (tp + fn) else 0.0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) else 0.0
    specificity = tn / (tn + fp) if (tn + fp) else 0.0
    accuracy = (tp + tn) / n if n else 0.0
    return {"n": n, "tp": tp, "fp": fp, "tn": tn, "fn": fn, "precision": precision,
            "recall": recall, "f1": f1, "specificity": specificity, "accuracy": accuracy}


def build_dataset() -> list:
    """Four scenario rows of the shape SPEC.md section 3.1 describes."""
    rows = []
    for i, sid in enumerate(SCENARIOS):
        dangerous = i >= 2
        rows.append({
            "scenario_id": sid,
            "repo": "example/repo",
            "repo_url": "https://example.invalid/example/repo",
            "base_commit": label_digest(sid + ":base")[:40],
            "head_commit": label_digest(sid + ":head")[:40],
            "diff_ref": sid + ":diff",
            "language": "python",
            "extractor_version": "example-0",
            "gold": {
                "should_flag": dangerous,
                "risk_class": "behavioral-change" if dangerous else "benign-local",
                "impacted_files": ["pkg/consumer.py"] if dangerous else [],
                "impacted_basis": "symbol-referenced-repair" if dangerous else "local-self",
                "impacted_granularity": "file",
                "signature_changed": False,
            },
            "provenance": {
                "confidence": "high",
                "evidence": "synthetic example row, no real repository history",
                "label_source": "example",
                "matched_symbols": [],
            },
        })
    return rows


# Decisions are chosen first; every score below is derived to agree with them, which
# is exactly the reconciliation the verifier performs.
DECISIONS = {
    "K": ["would_block", "needs_attention", "pass", "pass"],
    "G": ["would_block", "pass", "would_block", "pass"],
}


def build_decisions() -> list:
    out = []
    for i, sid in enumerate(SCENARIOS):
        for arm in ("K", "G"):
            verdict = DECISIONS[arm][i]
            out.append({
                "scenario_id": sid,
                "arm": arm,
                "verdict": verdict,
                "flag": verdict in ("needs_attention", "would_block"),
                "impacted_files": ["pkg/consumer.py"] if verdict == "would_block" else [],
                "risk_class": "behavioral-change" if verdict != "pass" else "benign-local",
            })
    return out


def build_harness_source_manifest() -> dict:
    files = [
        {"path": "harness/run_prereg.py", "size": 1024, "sha256": label_digest("run_prereg")},
        {"path": "harness/score.py", "size": 512, "sha256": label_digest("score")},
    ]
    tools = [{"name": "git", "path": "/usr/bin/git", "sha256": label_digest("git")}]
    schema = "kin.merge-trust-harness-source.v1"
    manifest = {"schema": schema, "files": files, "tools": tools}
    manifest["content_sha256"] = canonical_digest(manifest)
    return manifest


def build_provenance(dataset_block: dict) -> dict:
    return {
        "protocol": PROTOCOL,
        "protocol_commit": COMMIT,
        "generated_at": TS,
        "run_id": RUN_ID,
        "segment_id": SEGMENT_ID,
        "platform": {"system": "Example", "release": "0", "machine": "example"},
        "arms": ARMS,
        "dataset": dataset_block,
        "binaries": {
            "kin": {"path": "<example>/kin", "sha256": label_digest("kin")},
            "kin_daemon": {"path": "<example>/kin-daemon", "sha256": label_digest("kin-daemon")},
            "harness": {"path": "<example>/run_prereg.py", "sha256": label_digest("harness")},
            "eval_runtime": {"path": "<example>/python3", "sha256": label_digest("python3")},
        },
        "command": {"argv": ["run_prereg.py", "--arms", "k,g"], "cwd": "<example>"},
        "environment": {"launch": {}, "injected": {}},
        "harness_source_manifest": build_harness_source_manifest(),
        "source_control": {
            "schema": "kin.merge-trust-source-control.v1",
            "clean": True,
            "dirty_entry_count": 0,
            "head": COMMIT,
            "expected_commit": COMMIT,
            "head_matches_expected": True,
            "git_path": "/usr/bin/git",
            "git_sha256": label_digest("git"),
            "repo_root": "<example>",
            "status_sha256": label_digest("status"),
        },
        "hygiene": {
            "allow_unclean": False,
            "block_seal": True,
            "env_scan": {"benign": [], "stray": []},
            "lmstudio": None,
            "openai_env": [],
        },
        "prep_regime": "v2.1-per-repo-block-seal",
        "model_runtime": None,
        "arm_l": None,
    }


def build_segments(provenance: dict) -> dict:
    common = {
        "protocol": PROTOCOL,
        "harness_commit": COMMIT,
        "dataset": provenance["dataset"],
        "platform": provenance["platform"],
        "environment": provenance["environment"],
        "harness_source_manifest": provenance["harness_source_manifest"],
        "source_control": provenance["source_control"],
    }
    common_sha = canonical_digest(common)
    arm_identity = {
        "k": {"kin": provenance["binaries"]["kin"],
              "kin_daemon": provenance["binaries"]["kin_daemon"]},
        "g": {},
    }
    identity = {arm: canonical_digest({"common": common, "arm": arm_identity[arm]})
                for arm in ARMS}

    arm_writes = []
    for sid in SCENARIOS:
        for arm in ARMS:
            arm_writes.append({
                "scenario_id": sid,
                "arm": arm.upper(),
                "written_at": TS,
                "identity_sha256": identity[arm],
                "provenance_path": "scenarios/%s/arm_%s/provenance.json" % (sid, arm),
                "stamp_sha256": label_digest("stamp:%s:%s" % (sid, arm)),
                "artifact_set_sha256": label_digest("artifacts:%s:%s" % (sid, arm)),
            })

    ledger = {
        "schema": "kin.merge-trust-segment-ledger.v1",
        "run_id": RUN_ID,
        "authoritative_source": "per-arm-v2-provenance",
        "selected_stamp_count": len(arm_writes),
        "readable_stamp_count": len(arm_writes),
        "validated_stamp_count": len(arm_writes),
        "segments": [{
            "segment_id": SEGMENT_ID,
            "produced_at": TS,
            "harness_commit": COMMIT,
            "common_identity_sha256": common_sha,
            "arm_writes": arm_writes,
        }],
    }
    ledger["content_sha256"] = canonical_digest(ledger)
    return ledger


def build_verdict(dataset_block: dict, ledger: dict) -> dict:
    n = dataset_block["n"]
    # Every block below is derived from DECISIONS so the verifier can reconcile it.
    # The gold column these confusion cells imply is invented; see the module docstring.
    flag = {"k": confusion(tp=1, fp=1, tn=1, fn=1), "g": confusion(tp=1, fp=1, tn=1, fn=1)}
    primary = {"k": confusion(tp=1, fp=0, tn=2, fn=1), "g": confusion(tp=2, fp=0, tn=2, fn=0)}
    soft = {
        "k": {"needs_attention_total": 1, "dangerous": 0, "benign": 1},
        "g": {"needs_attention_total": 0, "dangerous": 0, "benign": 0},
    }
    return {
        "protocol": PROTOCOL,
        "protocol_commit": COMMIT,
        "generated_at": TS,
        "dataset": dataset_block,
        "arms": ARMS,
        "scores": {arm: {"flag": flag[arm], "scored_n": n, "parse_failures": 0}
                   for arm in ARMS},
        "paired": {
            "k_vs_g": {
                "mcnemar": {"n01": 1, "n10": 1, "discordant": 2, "p_value": 1.0},
                "bootstrap": {"point_estimate": 0.0, "ci_low": -0.5, "ci_high": 0.25,
                              "excludes_zero": False, "n_resamples": 10000,
                              "seed": 20260703},
                "paired_n": n,
                "verdict": "tie",
                "direction": "none",
            },
            "k_vs_l": None,
        },
        "v8": {
            "semantics": {
                "pass": "no meaningful runtime/product risk found",
                "needs_attention": ("real behavior/surface change with consumer impact, "
                                    "insufficient evidence to block"),
                "would_block": "strong graph evidence of an unsafe/breaking merge",
            },
            "primary_block": primary,
            "secondary_soft_attention": soft,
            "legacy_overstrict": flag,
            "residual": {},
            "hard_stop": False,
            "hard_stop_reason": None,
        },
        "determinism": {
            "n_scenarios": n,
            "kin_bit_identical": True,
            "varying_scenarios": [],
            "kin_substrate_verified": True,
            "missing_substrate_trace_scenarios": [],
        },
        "hygiene_precheck": {"env_clean": True, "lmstudio_serial": True},
        "provenance_gate": {"ok": True, "reasons": [], "ledger": ledger},
        "citable_eligible_precheck": True,
        "citable_reasons": [],
        "citable_note": ("synthetic example bundle: carries no measured result and is "
                         "not citable evidence about anything"),
    }


def write(out_dir: str) -> str:
    bundle_dir = os.path.join(out_dir, "bundle")
    os.makedirs(bundle_dir, exist_ok=True)

    records = build_dataset()
    dataset_path = os.path.join(out_dir, "dataset.jsonl")
    raw = "".join(json.dumps(r, sort_keys=True) + "\n" for r in records).encode("utf-8")
    with open(dataset_path, "wb") as fh:
        fh.write(raw)
    dataset_block = {
        "path": "dataset.jsonl",
        "n": len(records),
        "sha256": dataset_records_digest(records),
        "records_array_sha256": dataset_records_digest(records),
        "raw_file_sha256": hashlib.sha256(raw).hexdigest(),
    }

    provenance = build_provenance(dataset_block)
    ledger = build_segments(provenance)
    verdict = build_verdict(dataset_block, ledger)
    decisions = build_decisions()

    def dump(name: str, obj: object) -> None:
        with open(os.path.join(bundle_dir, name), "w", encoding="utf-8") as fh:
            json.dump(obj, fh, indent=2, sort_keys=True)
            fh.write("\n")

    dump("provenance.json", provenance)
    dump("verdict.json", verdict)
    dump("segments.json", ledger)
    with open(os.path.join(bundle_dir, "decisions.jsonl"), "w", encoding="utf-8") as fh:
        for row in decisions:
            fh.write(json.dumps(row, sort_keys=True) + "\n")

    return bundle_dir


def main(argv: list = None) -> int:
    ap = argparse.ArgumentParser(
        description="Write a synthetic example bundle for verify_bundle.py. "
                    "It carries no measured result.")
    ap.add_argument("out_dir", help="directory to write bundle/ and dataset.jsonl into")
    args = ap.parse_args(argv)
    bundle_dir = write(args.out_dir)
    print("wrote synthetic example bundle: %s" % bundle_dir)
    print("dataset: %s" % os.path.join(args.out_dir, "dataset.jsonl"))
    print("this bundle carries no measured result and is not evidence about Kin")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
