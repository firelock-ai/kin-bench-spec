#!/usr/bin/env python3
"""Standalone verifier for merge-trust prereg-v1 evidence bundles.

Stdlib only. No kin, no daemon, no network, no third-party packages. Given a bundle
directory (verdict.json, provenance.json, segments.json, decisions.jsonl) it:

  (a) validates the presence and shape of each artifact,
  (b) recomputes every digest that is checkable from the bundle alone
      (segment-ledger content digest, harness-source-manifest content digest, and
      -- when the dataset file is supplied with --dataset -- both dataset digests),
  (c) checks internal consistency (scenario/stamp counts agree across files, the
      determinism block is coherent, confusion-matrix arithmetic reproduces the
      declared metrics, and the per-arm decisions reconcile with the score block
      without needing gold labels),
  (d) prints a PASS/FAIL report with one line per check, or --json.

It is deliberately conservative: anything it cannot recompute from the bundle is
reported as an explicit "declared (not recomputable from bundle)" note rather than
being trusted silently. A single FAIL sets the process exit code to 1.

Digest definitions are transcribed from the merge-trust harness source
(dataset_identity.py, harness/canonicalize.py, harness/score.py, harness/stats.py,
harness/run_prereg.py) and confirmed against a real accepted bundle.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys
from typing import Any, Optional

PASS = "PASS"
FAIL = "FAIL"
WARN = "WARN"
SKIP = "SKIP"
INFO = "INFO"

TOL = 1e-9  # float tolerance for recomputed metrics


# ----------------------------------------------------------------------------- digests
def canonical_digest(obj: Any) -> str:
    """run_prereg._canonical_digest: sha256 over compact, key-sorted, ascii JSON.

    hygiene.sha256_text(json.dumps(obj, sort_keys=True, separators=(",",":"),
    ensure_ascii=True)).  Used for the segment-ledger content_sha256 and the
    harness-source-manifest content_sha256.
    """
    text = json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def dataset_records_digest(records: list) -> str:
    """dataset_identity.dataset_sha256: sha256 over json.dumps(records, sort_keys=True).

    NOTE: default separators (", ", ": ") -- NOT the compact form used by
    canonical_digest -- and order-sensitive over the record list.
    """
    return hashlib.sha256(json.dumps(list(records), sort_keys=True).encode()).hexdigest()


def is_canonical_sha256(value: object) -> bool:
    """run_prereg._is_canonical_sha256: 64 lowercase hex chars."""
    return bool(
        isinstance(value, str)
        and len(value) == 64
        and all(c in "0123456789abcdef" for c in value)
    )


def is_git_sha(value: object) -> bool:
    """A full git object id: 40 lowercase hex chars."""
    return bool(
        isinstance(value, str)
        and len(value) == 40
        and all(c in "0123456789abcdef" for c in value)
    )


# ----------------------------------------------------------------------------- results
class Report:
    def __init__(self) -> None:
        self.results: list[dict[str, str]] = []

    def add(self, status: str, name: str, detail: str = "") -> None:
        self.results.append({"status": status, "check": name, "detail": detail})

    def counts(self) -> dict[str, int]:
        out = {PASS: 0, FAIL: 0, WARN: 0, SKIP: 0, INFO: 0}
        for r in self.results:
            out[r["status"]] = out.get(r["status"], 0) + 1
        return out

    def ok(self) -> bool:
        return self.counts()[FAIL] == 0


# ----------------------------------------------------------------------------- loading
def _load_json(path: str) -> tuple[Optional[Any], Optional[str]]:
    if not os.path.isfile(path):
        return None, "missing"
    try:
        with open(path, encoding="utf-8") as fh:
            return json.load(fh), None
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        return None, f"unreadable: {exc}"


def _load_jsonl(path: str) -> tuple[Optional[list], Optional[str]]:
    if not os.path.isfile(path):
        return None, "missing"
    try:
        rows = []
        with open(path, encoding="utf-8") as fh:
            for i, line in enumerate(fh, 1):
                line = line.strip()
                if not line:
                    continue
                rows.append(json.loads(line))
        return rows, None
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        return None, f"unreadable: {exc}"


# ----------------------------------------------------------------------------- checks
def _require_keys(rep: Report, label: str, obj: Any, keys: list[str]) -> bool:
    if not isinstance(obj, dict):
        rep.add(FAIL, f"shape:{label}", "not a JSON object")
        return False
    missing = [k for k in keys if k not in obj]
    if missing:
        rep.add(FAIL, f"shape:{label}", f"missing keys: {sorted(missing)}")
        return False
    rep.add(PASS, f"shape:{label}", f"all {len(keys)} required keys present")
    return True


def check_presence(rep: Report, files: dict[str, Any]) -> None:
    for name in ("provenance.json", "verdict.json", "segments.json", "decisions.jsonl"):
        obj, err = files[name]
        if err:
            rep.add(FAIL, f"present:{name}", err)
        else:
            rep.add(PASS, f"present:{name}", "loaded")


def check_provenance_shape(rep: Report, prov: Any) -> None:
    if prov is None:
        rep.add(SKIP, "shape:provenance", "provenance.json absent")
        return
    _require_keys(rep, "provenance", prov, [
        "arms", "binaries", "command", "dataset", "generated_at",
        "harness_source_manifest", "hygiene", "platform", "prep_regime",
        "protocol", "protocol_commit", "run_id", "segment_id", "source_control",
    ])
    ds = prov.get("dataset")
    _require_keys(rep, "provenance.dataset", ds, ["n", "path", "sha256"])
    if isinstance(ds, dict) and "raw_file_sha256" not in ds:
        rep.add(WARN, "shape:provenance.dataset.raw_file_sha256",
                "absent (pre-dual-digest sidecar; only records-array sha256 present)")
    bins = prov.get("binaries")
    if isinstance(bins, dict):
        for b in ("kin", "kin_daemon", "harness", "eval_runtime"):
            _require_keys(rep, f"provenance.binaries.{b}", bins.get(b), ["path", "sha256"])
    _require_keys(rep, "provenance.harness_source_manifest",
                  prov.get("harness_source_manifest"),
                  ["content_sha256", "files", "schema", "tools"])
    _require_keys(rep, "provenance.source_control", prov.get("source_control"),
                  ["clean", "head", "expected_commit", "head_matches_expected",
                   "status_sha256", "schema"])


def check_verdict_shape(rep: Report, verd: Any) -> None:
    if verd is None:
        rep.add(SKIP, "shape:verdict", "verdict.json absent")
        return
    _require_keys(rep, "verdict", verd, [
        "arms", "dataset", "determinism", "protocol", "protocol_commit",
        "scores", "paired", "provenance_gate",
    ])
    _require_keys(rep, "verdict.determinism", verd.get("determinism"),
                  ["kin_bit_identical", "kin_substrate_verified",
                   "missing_substrate_trace_scenarios", "n_scenarios",
                   "varying_scenarios"])
    scores = verd.get("scores")
    if isinstance(scores, dict):
        for arm, block in scores.items():
            _require_keys(rep, f"verdict.scores.{arm}.flag",
                          (block or {}).get("flag"),
                          ["n", "tp", "fp", "tn", "fn", "precision", "recall",
                           "f1", "specificity", "accuracy"])
    _require_keys(rep, "verdict.provenance_gate", verd.get("provenance_gate"),
                  ["ledger", "ok", "reasons"])
    paired = verd.get("paired")
    if isinstance(paired, dict) and isinstance(paired.get("k_vs_g"), dict):
        _require_keys(rep, "verdict.paired.k_vs_g", paired["k_vs_g"],
                      ["mcnemar", "bootstrap", "verdict", "direction", "paired_n"])


def check_segments_shape(rep: Report, segs: Any) -> None:
    if segs is None:
        rep.add(SKIP, "shape:segments", "segments.json absent")
        return
    if not _require_keys(rep, "segments", segs, [
        "schema", "run_id", "authoritative_source", "selected_stamp_count",
        "readable_stamp_count", "validated_stamp_count", "segments", "content_sha256",
    ]):
        return
    for i, seg in enumerate(segs.get("segments") or []):
        _require_keys(rep, f"segments.segments[{i}]", seg,
                      ["segment_id", "produced_at", "harness_commit",
                       "common_identity_sha256", "arm_writes"])
        for j, w in enumerate(seg.get("arm_writes") or []):
            if not isinstance(w, dict) or not all(
                k in w for k in ("scenario_id", "arm", "identity_sha256",
                                 "provenance_path", "stamp_sha256", "artifact_set_sha256")):
                rep.add(FAIL, f"segments.segments[{i}].arm_writes[{j}]",
                        "arm_write missing required keys")
                return
    rep.add(PASS, "shape:segments.arm_writes", "all arm_writes well-formed")


def check_decisions_shape(rep: Report, decs: Any) -> None:
    if decs is None:
        rep.add(SKIP, "shape:decisions", "decisions.jsonl absent")
        return
    bad = [i for i, d in enumerate(decs)
           if not isinstance(d, dict)
           or not all(k in d for k in ("arm", "flag", "scenario_id", "verdict"))]
    if bad:
        rep.add(FAIL, "shape:decisions", f"{len(bad)} record(s) missing required keys")
    else:
        rep.add(PASS, "shape:decisions",
                f"{len(decs)} records, each with arm/flag/scenario_id/verdict")


def check_sha_fields(rep: Report, prov: Any, segs: Any) -> None:
    """Every declared *_sha256 field must be a canonical 64-hex digest."""
    offenders = []
    if isinstance(prov, dict):
        ds = prov.get("dataset") or {}
        for k in ("sha256", "raw_file_sha256"):
            if k in ds and not is_canonical_sha256(ds[k]):
                offenders.append(f"dataset.{k}")
        man = prov.get("harness_source_manifest") or {}
        if not is_canonical_sha256(man.get("content_sha256")):
            offenders.append("harness_source_manifest.content_sha256")
    if isinstance(segs, dict):
        if not is_canonical_sha256(segs.get("content_sha256")):
            offenders.append("segments.content_sha256")
        for i, seg in enumerate(segs.get("segments") or []):
            for w in seg.get("arm_writes") or []:
                for k in ("identity_sha256", "stamp_sha256", "artifact_set_sha256"):
                    if not is_canonical_sha256(w.get(k)):
                        offenders.append(f"segments[{i}].arm_writes[{w.get('scenario_id')}/{w.get('arm')}].{k}")
    if offenders:
        rep.add(FAIL, "sha256:format", f"non-canonical digest field(s): {offenders[:6]}"
                + (" ..." if len(offenders) > 6 else ""))
    else:
        rep.add(PASS, "sha256:format", "all declared *_sha256 fields are 64-hex")


def check_ledger_digest(rep: Report, verd: Any, segs: Any) -> None:
    """segments.json content_sha256 == canonical_digest(ledger minus content_sha256),
    and the ledger embedded in verdict.provenance_gate.ledger recomputes identically and
    is byte-equal to segments.json."""
    if isinstance(segs, dict) and "content_sha256" in segs:
        core = {k: v for k, v in segs.items() if k != "content_sha256"}
        got = canonical_digest(core)
        if got == segs["content_sha256"]:
            rep.add(PASS, "digest:segments.content_sha256",
                    "recomputed canonical ledger digest matches declared")
        else:
            rep.add(FAIL, "digest:segments.content_sha256",
                    f"recomputed {got} != declared {segs['content_sha256']}")
    else:
        rep.add(SKIP, "digest:segments.content_sha256", "segments.json absent")

    led = (verd or {}).get("provenance_gate", {}).get("ledger") if isinstance(verd, dict) else None
    if isinstance(led, dict) and "content_sha256" in led:
        core = {k: v for k, v in led.items() if k != "content_sha256"}
        got = canonical_digest(core)
        if got == led["content_sha256"]:
            rep.add(PASS, "digest:verdict.ledger.content_sha256",
                    "recomputed embedded-ledger digest matches declared")
        else:
            rep.add(FAIL, "digest:verdict.ledger.content_sha256",
                    f"recomputed {got} != declared {led['content_sha256']}")
        if isinstance(segs, dict):
            if led == segs:
                rep.add(PASS, "consistency:ledger-copies-identical",
                        "verdict.provenance_gate.ledger is byte-equal to segments.json")
            else:
                rep.add(FAIL, "consistency:ledger-copies-identical",
                        "verdict ledger differs from segments.json")
    else:
        rep.add(SKIP, "digest:verdict.ledger.content_sha256", "verdict ledger absent")


def check_harness_manifest_digest(rep: Report, prov: Any) -> None:
    """harness_source_manifest.content_sha256 == canonical_digest({schema, files, tools})."""
    if not isinstance(prov, dict):
        rep.add(SKIP, "digest:harness_source_manifest", "provenance.json absent")
        return
    man = prov.get("harness_source_manifest")
    if not isinstance(man, dict) or "content_sha256" not in man:
        rep.add(SKIP, "digest:harness_source_manifest", "manifest absent")
        return
    core = {"schema": man.get("schema"), "files": man.get("files"), "tools": man.get("tools")}
    got = canonical_digest(core)
    if got == man["content_sha256"]:
        rep.add(PASS, "digest:harness_source_manifest.content_sha256",
                "recomputed manifest digest matches declared")
    else:
        rep.add(FAIL, "digest:harness_source_manifest.content_sha256",
                f"recomputed {got} != declared {man['content_sha256']}")


def check_dataset_digest(rep: Report, prov: Any, verd: Any, dataset_path: Optional[str]) -> None:
    """Optional: with --dataset, recompute both dataset digests from the JSONL file."""
    decl = None
    for src in (prov, verd):
        if isinstance(src, dict) and isinstance(src.get("dataset"), dict):
            decl = src["dataset"]
            break
    if decl is None:
        rep.add(SKIP, "digest:dataset", "no dataset block in bundle")
        return
    if not dataset_path:
        rep.add(INFO, "digest:dataset",
                "declared (not recomputed) -- pass --dataset PATH to recompute "
                f"sha256={str(decl.get('sha256'))[:12]}...")
        return
    if not os.path.isfile(dataset_path):
        rep.add(FAIL, "digest:dataset", f"--dataset file not found: {dataset_path}")
        return
    raw = open(dataset_path, "rb").read()
    recs = [json.loads(ln) for ln in raw.decode("utf-8").splitlines() if ln.strip()]
    got_records = dataset_records_digest(recs)
    got_raw = hashlib.sha256(raw).hexdigest()
    if got_records == decl.get("sha256"):
        rep.add(PASS, "digest:dataset.sha256",
                f"records-array digest matches declared over n={len(recs)}")
    else:
        rep.add(FAIL, "digest:dataset.sha256",
                f"recomputed {got_records} != declared {decl.get('sha256')}")
    if "raw_file_sha256" in decl:
        if got_raw == decl["raw_file_sha256"]:
            rep.add(PASS, "digest:dataset.raw_file_sha256", "raw-file digest matches declared")
        else:
            rep.add(FAIL, "digest:dataset.raw_file_sha256",
                    f"recomputed {got_raw} != declared {decl['raw_file_sha256']}")
    if len(recs) != decl.get("n"):
        rep.add(FAIL, "digest:dataset.n", f"file has {len(recs)} records, declared n={decl.get('n')}")


def _dataset_field(prov: Any, verd: Any, key: str) -> Any:
    for src in (prov, verd):
        if isinstance(src, dict) and isinstance(src.get("dataset"), dict) and key in src["dataset"]:
            return src["dataset"][key]
    return None


def check_cross_file_agreement(rep: Report, prov: Any, verd: Any, segs: Any) -> None:
    if not (isinstance(prov, dict) and isinstance(verd, dict)):
        rep.add(SKIP, "cross:dataset-agreement", "need both provenance and verdict")
    else:
        for key in ("sha256", "raw_file_sha256", "n"):
            pv = (prov.get("dataset") or {}).get(key)
            vv = (verd.get("dataset") or {}).get(key)
            if pv is None and vv is None:
                continue
            if pv == vv:
                rep.add(PASS, f"cross:dataset.{key}", f"agree ({str(pv)[:16]})")
            else:
                rep.add(FAIL, f"cross:dataset.{key}", f"provenance={pv} != verdict={vv}")
        for key in ("protocol", "protocol_commit"):
            if prov.get(key) == verd.get(key):
                rep.add(PASS, f"cross:{key}", f"agree ({prov.get(key)})")
            else:
                rep.add(FAIL, f"cross:{key}", f"provenance={prov.get(key)} != verdict={verd.get(key)}")
        if sorted(prov.get("arms") or []) == sorted(verd.get("arms") or []):
            rep.add(PASS, "cross:arms", f"agree ({prov.get('arms')})")
        else:
            rep.add(FAIL, "cross:arms", f"provenance={prov.get('arms')} != verdict={verd.get('arms')}")

    # run_id agreement across provenance / segments / verdict-ledger
    run_ids = {}
    if isinstance(prov, dict):
        run_ids["provenance"] = prov.get("run_id")
    if isinstance(segs, dict):
        run_ids["segments"] = segs.get("run_id")
    if isinstance(verd, dict):
        run_ids["verdict.ledger"] = (verd.get("provenance_gate") or {}).get("ledger", {}).get("run_id")
    present = {k: v for k, v in run_ids.items() if v is not None}
    if len(set(present.values())) <= 1 and present:
        rep.add(PASS, "cross:run_id", f"agree across {sorted(present)} ({next(iter(present.values()))})")
    elif present:
        rep.add(FAIL, "cross:run_id", f"disagree: {present}")

    # protocol_commit == source_control head/expected == segment harness_commit
    if isinstance(prov, dict):
        pc = prov.get("protocol_commit")
        sc = prov.get("source_control") or {}
        chain = {"protocol_commit": pc, "sc.head": sc.get("head"),
                 "sc.expected_commit": sc.get("expected_commit")}
        if isinstance(segs, dict):
            hcs = {seg.get("harness_commit") for seg in (segs.get("segments") or [])}
            if len(hcs) == 1:
                chain["segment.harness_commit"] = next(iter(hcs))
        vals = {v for v in chain.values() if v is not None}
        if not is_git_sha(pc):
            rep.add(WARN, "cross:protocol_commit-format", f"protocol_commit not a 40-hex git sha: {pc}")
        if len(vals) <= 1:
            rep.add(PASS, "cross:commit-chain", f"protocol_commit binds source-control + ledger ({str(pc)[:12]})")
        else:
            rep.add(FAIL, "cross:commit-chain", f"commit mismatch: {chain}")

    # ledger content digest agreement (already recomputed; here cross-check declared equality)
    if isinstance(segs, dict) and isinstance(verd, dict):
        led = (verd.get("provenance_gate") or {}).get("ledger") or {}
        if segs.get("content_sha256") and segs.get("content_sha256") == led.get("content_sha256"):
            rep.add(PASS, "cross:ledger.content_sha256",
                    "segments and verdict-ledger declare the same content digest")
        elif led:
            rep.add(FAIL, "cross:ledger.content_sha256",
                    f"segments={segs.get('content_sha256')} != verdict-ledger={led.get('content_sha256')}")

    # segment_id from provenance appears in the ledger
    if isinstance(prov, dict) and isinstance(segs, dict):
        seg_ids = {seg.get("segment_id") for seg in (segs.get("segments") or [])}
        if prov.get("segment_id") in seg_ids:
            rep.add(PASS, "cross:segment_id", f"provenance segment_id present in ledger ({prov.get('segment_id')})")
        else:
            rep.add(FAIL, "cross:segment_id",
                    f"provenance segment_id {prov.get('segment_id')} not in ledger {sorted(seg_ids)}")


def _scenario_ids_from_ledger(segs: Any) -> list[str]:
    out = []
    if isinstance(segs, dict):
        for seg in segs.get("segments") or []:
            for w in seg.get("arm_writes") or []:
                out.append(w.get("scenario_id"))
    return out


def check_counts(rep: Report, prov: Any, verd: Any, segs: Any, decs: Any) -> None:
    n = _dataset_field(prov, verd, "n")
    arms = None
    if isinstance(verd, dict):
        arms = verd.get("arms")
    elif isinstance(prov, dict):
        arms = prov.get("arms")

    # determinism.n_scenarios == dataset.n
    if isinstance(verd, dict):
        det = verd.get("determinism") or {}
        if n is not None and det.get("n_scenarios") == n:
            rep.add(PASS, "count:determinism.n_scenarios", f"== dataset.n ({n})")
        elif n is not None and "n_scenarios" in det:
            rep.add(FAIL, "count:determinism.n_scenarios", f"{det.get('n_scenarios')} != dataset.n {n}")
        # scores[arm].flag.n == n
        for arm, block in (verd.get("scores") or {}).items():
            fn = (block or {}).get("flag", {}).get("n")
            if n is not None and fn == n:
                rep.add(PASS, f"count:scores.{arm}.flag.n", f"== n ({n})")
            elif n is not None and fn is not None:
                rep.add(FAIL, f"count:scores.{arm}.flag.n", f"{fn} != n {n}")

    # decisions: len == n * |arms|, unique scenario_ids == n, one decision per arm
    if isinstance(decs, list):
        sids = [d.get("scenario_id") for d in decs]
        uniq = set(sids)
        if n is not None and arms and len(decs) == n * len(arms):
            rep.add(PASS, "count:decisions.total", f"{len(decs)} == n*|arms| ({n}*{len(arms)})")
        elif n is not None and arms:
            rep.add(FAIL, "count:decisions.total", f"{len(decs)} != n*|arms| ({n}*{len(arms)})")
        if n is not None:
            if len(uniq) == n:
                rep.add(PASS, "count:decisions.unique_scenarios", f"== n ({n})")
            else:
                rep.add(FAIL, "count:decisions.unique_scenarios", f"{len(uniq)} != n {n}")
        if arms:
            arm_upper = {str(a).upper() for a in arms}
            per = {}
            for d in decs:
                per.setdefault(d.get("scenario_id"), set()).add(str(d.get("arm")).upper())
            incomplete = [s for s, a in per.items() if a != arm_upper]
            if not incomplete:
                rep.add(PASS, "count:decisions.per-arm", f"every scenario has exactly {sorted(arm_upper)}")
            else:
                rep.add(FAIL, "count:decisions.per-arm", f"{len(incomplete)} scenario(s) missing an arm decision")

    # ledger stamp counts
    if isinstance(segs, dict):
        writes = _scenario_ids_from_ledger(segs)
        sel = segs.get("selected_stamp_count")
        read = segs.get("readable_stamp_count")
        val = segs.get("validated_stamp_count")
        if sel == read == val == len(writes):
            rep.add(PASS, "count:stamps", f"selected==readable==validated==|arm_writes| ({len(writes)})")
        else:
            rep.add(FAIL, "count:stamps",
                    f"selected={sel} readable={read} validated={val} |arm_writes|={len(writes)}")
        if n is not None and arms and len(writes) == n * len(arms):
            rep.add(PASS, "count:stamps.expected", f"|arm_writes| == n*|arms| ({n}*{len(arms)})")
        elif n is not None and arms:
            rep.add(FAIL, "count:stamps.expected", f"|arm_writes|={len(writes)} != n*|arms| {n * len(arms)}")
        uniq_led = set(writes)
        if n is not None and len(uniq_led) == n:
            rep.add(PASS, "count:ledger.unique_scenarios", f"== n ({n})")
        elif n is not None:
            rep.add(FAIL, "count:ledger.unique_scenarios", f"{len(uniq_led)} != n {n}")

    # scenario_id set agreement between decisions and ledger
    if isinstance(decs, list) and isinstance(segs, dict):
        ds = set(d.get("scenario_id") for d in decs)
        ls = set(_scenario_ids_from_ledger(segs))
        if ds == ls and ds:
            rep.add(PASS, "cross:scenario-set", f"decisions and ledger cover the same {len(ds)} scenarios")
        elif ds or ls:
            only_d = ds - ls
            only_l = ls - ds
            rep.add(FAIL, "cross:scenario-set",
                    f"mismatch: only-in-decisions={sorted(only_d)[:3]} only-in-ledger={sorted(only_l)[:3]}")


def check_determinism(rep: Report, verd: Any, decs: Any) -> None:
    if not isinstance(verd, dict):
        rep.add(SKIP, "determinism", "verdict.json absent")
        return
    det = verd.get("determinism") or {}
    bit = det.get("kin_bit_identical")
    varying = det.get("varying_scenarios")
    subst = det.get("kin_substrate_verified")
    missing = det.get("missing_substrate_trace_scenarios")
    if isinstance(bit, bool):
        if bit and varying:
            rep.add(FAIL, "determinism:bit-identical",
                    f"kin_bit_identical=true but varying_scenarios non-empty: {varying}")
        elif bit:
            rep.add(PASS, "determinism:bit-identical", "kin_bit_identical=true and no varying scenarios")
        else:
            rep.add(WARN, "determinism:bit-identical",
                    f"kin_bit_identical=false; varying_scenarios={varying}")
    else:
        rep.add(FAIL, "determinism:bit-identical", "kin_bit_identical not a boolean")
    if isinstance(subst, bool):
        if subst and missing:
            rep.add(FAIL, "determinism:substrate",
                    f"kin_substrate_verified=true but missing_substrate_trace_scenarios={missing}")
        else:
            rep.add(PASS if subst else WARN, "determinism:substrate",
                    f"kin_substrate_verified={subst}")
    # varying scenarios must be a subset of the decision scenario set
    if isinstance(decs, list) and isinstance(varying, list) and varying:
        known = set(d.get("scenario_id") for d in decs)
        stray = [s for s in varying if s not in known]
        if stray:
            rep.add(FAIL, "determinism:varying-known", f"varying scenarios not in bundle: {stray}")


def _recompute_confusion(m: dict) -> dict:
    tp, fp, tn, fn = m["tp"], m["fp"], m["tn"], m["fn"]
    n = tp + fp + tn + fn
    prec = tp / (tp + fp) if (tp + fp) else 0.0
    rec = tp / (tp + fn) if (tp + fn) else 0.0
    f1 = 2 * prec * rec / (prec + rec) if (prec + rec) else 0.0
    spec = tn / (tn + fp) if (tn + fp) else 0.0
    acc = (tp + tn) / n if n else 0.0
    return {"n": n, "precision": prec, "recall": rec, "f1": f1,
            "specificity": spec, "accuracy": acc}


def _check_block_arithmetic(rep: Report, label: str, m: dict, expect_n: Optional[int]) -> None:
    need = ("tp", "fp", "tn", "fn", "precision", "recall", "f1", "specificity", "accuracy", "n")
    if not isinstance(m, dict) or not all(k in m for k in need):
        rep.add(SKIP, f"score:{label}", "confusion block incomplete")
        return
    r = _recompute_confusion(m)
    if r["n"] != m["n"]:
        rep.add(FAIL, f"score:{label}.n", f"tp+fp+tn+fn={r['n']} != declared n={m['n']}")
        return
    if expect_n is not None and m["n"] != expect_n:
        rep.add(FAIL, f"score:{label}.n", f"n={m['n']} != dataset n={expect_n}")
    bad = [k for k in ("precision", "recall", "f1", "specificity", "accuracy")
           if abs(r[k] - m[k]) > TOL]
    if bad:
        rep.add(FAIL, f"score:{label}", f"recomputed metric(s) disagree: {bad}")
    else:
        rep.add(PASS, f"score:{label}",
                f"tp={m['tp']} fp={m['fp']} tn={m['tn']} fn={m['fn']} -> p/r/f1/spec/acc all reproduce")


def check_scores_arithmetic(rep: Report, verd: Any, prov: Any) -> None:
    if not isinstance(verd, dict):
        rep.add(SKIP, "score", "verdict.json absent")
        return
    n = _dataset_field(prov, verd, "n")
    for arm, block in (verd.get("scores") or {}).items():
        _check_block_arithmetic(rep, f"scores.{arm}.flag", (block or {}).get("flag"), n)
    v8 = verd.get("v8") or {}
    for key in ("primary_block", "legacy_overstrict"):
        for arm, block in (v8.get(key) or {}).items():
            _check_block_arithmetic(rep, f"v8.{key}.{arm}", block, n)


def check_decisions_links(rep: Report, verd: Any, decs: Any) -> None:
    """Gold-free reconciliation of decisions.jsonl against the score block:
    predicted-positive counts are independent of the gold label, so they must match."""
    if not (isinstance(verd, dict) and isinstance(decs, list)):
        rep.add(SKIP, "link:decisions-scores", "need verdict + decisions")
        return
    by_arm: dict[str, list] = {}
    for d in decs:
        by_arm.setdefault(str(d.get("arm")).upper(), []).append(d)
    scores = verd.get("scores") or {}
    v8 = verd.get("v8") or {}
    for arm_key, block in scores.items():
        recs = by_arm.get(arm_key.upper(), [])
        fl = (block or {}).get("flag") or {}
        if not recs or not all(k in fl for k in ("tp", "fp", "tn", "fn")):
            rep.add(SKIP, f"link:{arm_key}.flag", "missing decisions or flag block")
            continue
        flag_true = sum(1 for d in recs if d.get("flag") is True)
        flag_false = sum(1 for d in recs if d.get("flag") is False)
        if flag_true == fl["tp"] + fl["fp"] and flag_false == fl["tn"] + fl["fn"]:
            rep.add(PASS, f"link:{arm_key}.flag",
                    f"decisions flag+/- ({flag_true}/{flag_false}) == (tp+fp)/(tn+fn)")
        else:
            rep.add(FAIL, f"link:{arm_key}.flag",
                    f"decisions flag+={flag_true} vs tp+fp={fl['tp'] + fl['fp']}; "
                    f"flag-={flag_false} vs tn+fn={fl['tn'] + fl['fn']}")
        # V8 primary_block: predicted positive == verdict=='would_block'
        pb = (v8.get("primary_block") or {}).get(arm_key)
        if isinstance(pb, dict) and all(k in pb for k in ("tp", "fp")):
            wb = sum(1 for d in recs if d.get("verdict") == "would_block")
            if wb == pb["tp"] + pb["fp"]:
                rep.add(PASS, f"link:{arm_key}.would_block",
                        f"decisions would_block ({wb}) == primary_block tp+fp")
            else:
                rep.add(FAIL, f"link:{arm_key}.would_block",
                        f"decisions would_block={wb} != primary_block tp+fp={pb['tp'] + pb['fp']}")
        # V8 soft attention: verdict=='needs_attention' count
        sa = (v8.get("secondary_soft_attention") or {}).get(arm_key)
        if isinstance(sa, dict) and "needs_attention_total" in sa:
            na = sum(1 for d in recs if d.get("verdict") == "needs_attention")
            if na == sa["needs_attention_total"]:
                rep.add(PASS, f"link:{arm_key}.needs_attention",
                        f"decisions needs_attention ({na}) == secondary total")
            else:
                rep.add(FAIL, f"link:{arm_key}.needs_attention",
                        f"decisions needs_attention={na} != secondary total={sa['needs_attention_total']}")


def check_paired_stats(rep: Report, verd: Any, prov: Any) -> None:
    if not isinstance(verd, dict):
        rep.add(SKIP, "stats", "verdict.json absent")
        return
    n = _dataset_field(prov, verd, "n")
    pair = (verd.get("paired") or {}).get("k_vs_g")
    if not isinstance(pair, dict):
        rep.add(SKIP, "stats:k_vs_g", "no k_vs_g block")
        return
    mcn = pair.get("mcnemar") or {}
    boot = pair.get("bootstrap") or {}
    if all(k in mcn for k in ("n01", "n10", "discordant")):
        if mcn["discordant"] == mcn["n01"] + mcn["n10"]:
            rep.add(PASS, "stats:mcnemar.discordant", f"n01+n10 == discordant ({mcn['discordant']})")
        else:
            rep.add(FAIL, "stats:mcnemar.discordant",
                    f"n01+n10={mcn['n01'] + mcn['n10']} != discordant={mcn['discordant']}")
    if n is not None and pair.get("paired_n") == n:
        rep.add(PASS, "stats:paired_n", f"== n ({n})")
    elif n is not None and "paired_n" in pair:
        rep.add(FAIL, "stats:paired_n", f"{pair.get('paired_n')} != n {n}")
    if boot.get("n_resamples") == 10000:
        rep.add(PASS, "stats:bootstrap.n_resamples", "== 10000 (frozen prereg value)")
    elif "n_resamples" in boot:
        rep.add(WARN, "stats:bootstrap.n_resamples",
                f"{boot.get('n_resamples')} != frozen 10000")
    if all(k in boot for k in ("ci_low", "ci_high", "excludes_zero")):
        expect = bool(boot["ci_low"] > 0 or boot["ci_high"] < 0)
        if expect == bool(boot["excludes_zero"]):
            rep.add(PASS, "stats:bootstrap.excludes_zero", f"consistent with CI ({boot['excludes_zero']})")
        else:
            rep.add(FAIL, "stats:bootstrap.excludes_zero",
                    f"excludes_zero={boot['excludes_zero']} but CI=[{boot['ci_low']},{boot['ci_high']}]")
    # decision rule: verdict 'beats' iff excludes_zero AND p<0.05
    if "verdict" in pair and "p_value" in mcn and "excludes_zero" in boot:
        beats = bool(boot["excludes_zero"]) and mcn["p_value"] < 0.05
        want = "beats" if beats else "tie"
        if pair["verdict"] == want:
            rep.add(PASS, "stats:decision-rule", f"verdict '{pair['verdict']}' matches frozen rule")
        else:
            rep.add(FAIL, "stats:decision-rule",
                    f"verdict '{pair['verdict']}' but rule (excludes_zero AND p<0.05) implies '{want}'")


def check_ledger_identity_invariants(rep: Report, segs: Any) -> None:
    """Within a segment, all arm_writes of one arm share one identity_sha256 (the arm's
    config identity), and every segment declares one common_identity_sha256."""
    if not isinstance(segs, dict):
        rep.add(SKIP, "ledger:identity", "segments.json absent")
        return
    ok = True
    for i, seg in enumerate(segs.get("segments") or []):
        per_arm: dict[str, set] = {}
        for w in seg.get("arm_writes") or []:
            per_arm.setdefault(w.get("arm"), set()).add(w.get("identity_sha256"))
        for arm, ids in per_arm.items():
            if len(ids) != 1:
                ok = False
                rep.add(FAIL, "ledger:arm-identity-stable",
                        f"segment[{i}] arm {arm} has {len(ids)} distinct identity_sha256")
    if ok:
        rep.add(PASS, "ledger:arm-identity-stable",
                "each arm's identity_sha256 is constant across its scenarios")


def check_hygiene_and_gate(rep: Report, prov: Any, verd: Any) -> None:
    if isinstance(prov, dict):
        sc = prov.get("source_control") or {}
        if sc.get("clean") is True and sc.get("head_matches_expected") is True:
            rep.add(PASS, "gate:source-control", "clean tree, head matches expected commit")
        else:
            rep.add(WARN, "gate:source-control",
                    f"clean={sc.get('clean')} head_matches_expected={sc.get('head_matches_expected')}")
        hy = prov.get("hygiene") or {}
        stray = (hy.get("env_scan") or {}).get("stray")
        if stray:
            rep.add(WARN, "gate:hygiene.stray-env", f"stray env present: {stray}")
    if isinstance(verd, dict):
        pg = verd.get("provenance_gate") or {}
        if pg.get("ok") is True:
            rep.add(PASS, "gate:provenance", "provenance_gate.ok=true")
        elif "ok" in pg:
            rep.add(WARN, "gate:provenance", f"provenance_gate.ok={pg.get('ok')} reasons={pg.get('reasons')}")
        ce = verd.get("citable_eligible_precheck")
        if ce is True:
            rep.add(INFO, "gate:citable-precheck", "citable_eligible_precheck=true (harness precheck only)")
        elif ce is False:
            rep.add(WARN, "gate:citable-precheck",
                    f"citable_eligible_precheck=false reasons={verd.get('citable_reasons')}")


# ----------------------------------------------------------------------------- driver
def verify(bundle_dir: str, dataset_path: Optional[str] = None) -> Report:
    rep = Report()
    files = {
        "provenance.json": _load_json(os.path.join(bundle_dir, "provenance.json")),
        "verdict.json": _load_json(os.path.join(bundle_dir, "verdict.json")),
        "segments.json": _load_json(os.path.join(bundle_dir, "segments.json")),
        "decisions.jsonl": _load_jsonl(os.path.join(bundle_dir, "decisions.jsonl")),
    }
    prov = files["provenance.json"][0]
    verd = files["verdict.json"][0]
    segs = files["segments.json"][0]
    decs = files["decisions.jsonl"][0]

    check_presence(rep, files)
    check_provenance_shape(rep, prov)
    check_verdict_shape(rep, verd)
    check_segments_shape(rep, segs)
    check_decisions_shape(rep, decs)
    check_sha_fields(rep, prov, segs)
    check_ledger_digest(rep, verd, segs)
    check_harness_manifest_digest(rep, prov)
    check_dataset_digest(rep, prov, verd, dataset_path)
    check_cross_file_agreement(rep, prov, verd, segs)
    check_counts(rep, prov, verd, segs, decs)
    check_determinism(rep, verd, decs)
    check_scores_arithmetic(rep, verd, prov)
    check_decisions_links(rep, verd, decs)
    check_paired_stats(rep, verd, prov)
    check_ledger_identity_invariants(rep, segs)
    check_hygiene_and_gate(rep, prov, verd)
    return rep


def _print_human(bundle_dir: str, rep: Report) -> None:
    icons = {PASS: "PASS", FAIL: "FAIL", WARN: "WARN", SKIP: "SKIP", INFO: "INFO"}
    print(f"merge-trust prereg-v1 bundle verifier")
    print(f"bundle: {bundle_dir}")
    print("-" * 78)
    for r in rep.results:
        print(f"  [{icons[r['status']]}] {r['check']:<42} {r['detail']}")
    print("-" * 78)
    c = rep.counts()
    verdict = "PASS" if rep.ok() else "FAIL"
    print(f"RESULT: {verdict}   "
          f"({c[PASS]} pass, {c[FAIL]} fail, {c[WARN]} warn, {c[SKIP]} skip, {c[INFO]} info)")
    if not rep.ok():
        print("  failing checks:")
        for r in rep.results:
            if r["status"] == FAIL:
                print(f"    - {r['check']}: {r['detail']}")


def main(argv: Optional[list[str]] = None) -> int:
    ap = argparse.ArgumentParser(description="Verify a merge-trust prereg-v1 evidence bundle (stdlib only).")
    ap.add_argument("bundle_dir", help="directory holding verdict/provenance/segments/decisions")
    ap.add_argument("--dataset", default=None,
                    help="optional path to the run's dataset JSONL, to recompute dataset digests")
    ap.add_argument("--json", action="store_true", help="emit machine-readable JSON report")
    args = ap.parse_args(argv)

    if not os.path.isdir(args.bundle_dir):
        print(f"error: not a directory: {args.bundle_dir}", file=sys.stderr)
        return 2

    rep = verify(args.bundle_dir, args.dataset)
    if args.json:
        print(json.dumps({
            "bundle_dir": args.bundle_dir,
            "result": "PASS" if rep.ok() else "FAIL",
            "counts": rep.counts(),
            "checks": rep.results,
        }, indent=2, sort_keys=True))
    else:
        _print_human(args.bundle_dir, rep)
    return 0 if rep.ok() else 1


if __name__ == "__main__":
    raise SystemExit(main())
