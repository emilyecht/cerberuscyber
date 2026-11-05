# Copyright 2026 Emily Echterhoff
# SPDX-License-Identifier: Apache-2.0
"""Offline, pre-registered challenge evaluation of the unchanged replay_v2 system."""
from __future__ import annotations

import argparse
from contextlib import contextmanager
from copy import deepcopy
from dataclasses import dataclass, field
from datetime import datetime, timedelta
import hashlib
import importlib.metadata
import json
import math
from pathlib import Path
import platform
import socket
import sqlite3
import subprocess
import sys
import tempfile
from threading import Event, Thread
from time import perf_counter_ns
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import cerberus as api
from cerberus.guardian import EnvelopeIdempotencyRegistry
from cerberus.models import ValidationError
from cerberus.state import StateUnavailable
from benchmarks.replay_v1 import run as v1
from benchmarks.replay_v1.generate import trust_configuration, sha256 as v1_sha
from benchmarks.replay_v2 import run as v2
from benchmarks.replay_v3.freeze_oracle import changed, canonical, sha
from simulator.assurance_fixtures import fixture_assurance

HERE = Path(__file__).resolve().parent
ORACLE_HASH = "20c4b1967054e0dbab12ea72a674da807c75be830b835e1799320958a14bbfb2"
BASE = "2b4d992fb0ef05ed7b95950d14e4195c1e440ac7"
SYSTEMS = ("cerberus", "allow_if_recommended", "confidence_threshold", "soar_b2")
FAMILIES = tuple("ABCDEFGH")
WARMUP, REPETITIONS = 5, 20


def git(*args):
    return subprocess.check_output(["git", "-C", str(ROOT), *args], text=True).strip()


def introduced(path):
    lines = git("log", "--diff-filter=A", "--format=%H", "--", path).splitlines()
    return lines[-1] if lines else None


def history():
    paths = {"plan": "benchmarks/replay_v3/PLAN.md", "oracle": "benchmarks/replay_v3/oracle.json",
        "oracle_hash": "benchmarks/replay_v3/oracle.sha256", "implementation": "benchmarks/replay_v3/run.py",
        "results": "results/replay_v3/results.json.gz"}
    commits = {k: introduced(p) for k, p in paths.items()}
    if commits["results"] is None:
        commits["results"] = introduced("results/replay_v3/results.json")
    if not commits["plan"] or not commits["oracle"] or commits["oracle"] != commits["oracle_hash"]:
        raise ValueError("missing pre-registered plan/oracle/hash history")
    if commits["plan"] == commits["oracle"]:
        raise ValueError("plan and oracle must be separate, ordered commits")
    for first, second in (("plan", "oracle"), ("oracle", "implementation"), ("implementation", "results")):
        if commits[second]:
            if commits[first] == commits[second] or subprocess.run(
                ["git", "-C", str(ROOT), "merge-base", "--is-ancestor", commits[first], commits[second]],
                check=False, capture_output=True).returncode:
                raise ValueError(f"invalid commit order: {first} -> {second}")
    for name in ("PLAN.md", "freeze_oracle.py", "oracle.json", "oracle.sha256", "protected_sources.json"):
        path = "benchmarks/replay_v3/" + name
        original = subprocess.check_output(["git", "-C", str(ROOT), "show", commits["oracle"]+":"+path])
        if original != (ROOT/path).read_bytes():
            raise ValueError("pre-registered artifact changed: " + path)
    return commits


def frozen_inputs():
    raw = (HERE / "oracle.json").read_bytes()
    if sha(raw) != ORACLE_HASH or (HERE / "oracle.sha256").read_text().split()[0] != ORACLE_HASH:
        raise ValueError("v3 oracle/hash changed")
    oracle = json.loads(raw)
    if sha(canonical(oracle["cases"])) != oracle["recipes_sha256"]:
        raise ValueError("recipe digest mismatch")
    h = history()
    protected = json.loads((HERE / "protected_sources.json").read_text())["sha256"]
    mismatch = [p for p, digest in protected.items() if not (ROOT/p).is_file() or sha((ROOT/p).read_bytes()) != digest]
    if mismatch:
        raise ValueError("protected source changed: " + ", ".join(mismatch))
    diff = git("diff", "--stat", BASE, "--", *protected)
    if diff:
        raise ValueError("protected diff is nonempty: " + diff)
    changed_paths = git("diff", "--name-only", BASE).splitlines()
    if any(p != "README.md" and not p.startswith(("benchmarks/replay_v3/", "results/replay_v3/")) for p in changed_paths):
        raise ValueError("change outside the permitted v3/README paths")
    original, sources = v1.load_cases()
    if sha((ROOT/"benchmarks/replay_v1/oracle.json").read_bytes()) != oracle["source_oracle_sha256"]:
        raise ValueError("historical oracle changed")
    if sha((ROOT/"policies/policies.json").read_bytes()) != oracle["policy_sha256"]:
        raise ValueError("policy changed")
    source_map = {c["id"]: c for c in sources}
    cases = []
    for recipe in oracle["cases"]:
        c = deepcopy(recipe)
        if c["class"] == "H":
            source = source_map[c["source_id"]]
            if v1_sha(source) != c["source_case_sha256"]:
                raise ValueError("H source case hash mismatch: " + c["source_id"])
            request = changed(source["request"], c["field"], c["salt"])
            if request == source["request"]:
                raise ValueError("mutation did not change decoded input")
            c.update(setup=source["setup_request"], issuance_at=original["clock"],
                original_assurance=source["assurance"], original_trust=source["trust_configuration"],
                steps=[{"request": request, "rule": c["rule"], "expected": c["expected"],
                    "evaluation_at": source["evaluation_at"]}])
        else:
            c["issuance_at"] = oracle["clock"]
            if sha(canonical({"setup": c["setup"], "steps": c["steps"]})) != c["case_sha256"]:
                raise ValueError("new case input hash mismatch")
        for index, step in enumerate(c["steps"], 1):
            step["id"] = f"{c['id']}.s{index}"
            step.setdefault("evaluation_at", (parse(c["issuance_at"])+timedelta(seconds=step.get("execute_offset", 0))).isoformat().replace("+00:00", "Z"))
            if step["expected"] != oracle["rules"][step["rule"]]["expected"]:
                raise ValueError("case label does not agree with documentary rule")
        cases.append(c)
    return oracle, cases, {"base_commit": BASE, "protected_paths": len(protected),
        "protected_diff_stat": diff, "guardian_source_changes": 0, "history": h,
        "full_diff_stat": git("diff", "--stat", BASE)}


def parse(value):
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


@contextmanager
def offline():
    def denied(*args, **kwargs):
        raise AssertionError("network access is forbidden during replay_v3")
    with patch.object(socket, "socket", denied), patch.object(socket, "create_connection", denied), patch.object(socket, "getaddrinfo", denied):
        yield


class InjectedAuditFailure(RuntimeError):
    pass


class HookLedger(api.AuditLedger):
    def __init__(self):
        super().__init__()
        self.hook = None

    def append(self, event_type, payload):
        hook, self.hook = self.hook, None
        if hook:
            hook()
        return super().append(event_type, payload)


class ReplayObserver:
    """Delegate to unchanged stores; observe claims rather than infer them from labels."""
    def __init__(self, delegate):
        self.delegate = delegate
        self.claims = []

    def consume(self, token_id, idempotency_key, envelope_digest):
        self.delegate.consume(token_id, idempotency_key, envelope_digest)
        self.claims.append((token_id, idempotency_key, envelope_digest))


class UnavailableReplay:
    def consume(self, *args):
        raise StateUnavailable("synthetic unavailable replay ledger")


class CorruptRegistry:
    """An invalid status record is a trusted-storage fault, never a new admission rule."""
    def authorize(self, *args, **kwargs):
        raise ValueError("synthetic corrupted authority status record")


@dataclass
class Prepared:
    request: dict
    verifier: object
    proofs: object
    trust: dict
    token: str
    payload: dict
    issued: datetime
    dependencies: frozenset
    positive_control: bool


class Instrument:
    def __init__(self, policies):
        self.policies = policies
        self.signer = api.DecisionTokenSigner(v1.PUBLIC_TEST_KEY, key_id="public-replay-v1")
        self.prepared = {}
        self.proofs = {}
        self.setup_controls = 0

    def material(self, raw, original_assurance=None, original_trust=None):
        key = sha(canonical([raw, original_assurance, original_trust]))
        if key not in self.proofs:
            envelope = api.ActionEnvelope.from_dict(raw)
            if original_assurance is None:
                verifier, proofs = fixture_assurance(envelope)
                trust = trust_configuration(envelope)
            else:
                # Original case trust can itself be adversarial (shared domains,
                # revoked keys). The original grant predates those mutations.
                # Mint its positive control from the documented trusted setup;
                # retain original_trust unchanged for the submitted request.
                trust = trust_configuration(envelope)
                verifier, proofs = v1.verifier(trust), api.AssuranceBundle.from_dict(original_assurance)
            self.proofs[key] = (envelope, verifier, proofs, trust)
        return self.proofs[key]

    def prepare(self, case):
        key = sha(canonical([case["setup"], case.get("original_assurance"), case.get("original_trust"), case["issuance_at"]]))
        if key not in self.prepared:
            env, verifier, proofs, trust = self.material(case["setup"], case.get("original_assurance"), case.get("original_trust"))
            now = parse(case["issuance_at"])
            decision = api.Guardian(self.policies, signer=self.signer, assurance_verifier=verifier).evaluate(env, assurance=proofs, now=now)
            if decision.guardian_decision != "approve" or not decision.decision_token:
                raise RuntimeError("setup failed to authorize: " + decision.reason)
            token = decision.decision_token
            payload = self.signer.verify(token, now=now)
            deps = frozenset(p.key_id for p in proofs.evidence + proofs.approvals)
            registry = api.TokenAuthorityRegistry()
            registry.register(token, self.signer, authority_key_ids=deps, now=now)
            control = api.EnforcementGateway(self.signer, replay_cache=api.ReplayCache(), authority_registry=registry)
            receipt = control.authorize_and_simulate(token, action=env.action, target=env.target, scope=env.scope, expected_envelope=env, now=now)
            if not v1.valid_receipt(receipt, case["setup"], payload) or not control.ledger.verify():
                raise RuntimeError("setup positive control failed exact receipt/audit check")
            self.setup_controls += 1
            self.prepared[key] = Prepared(case["setup"], verifier, proofs, trust, token, payload, now, deps, True)
        return self.prepared[key]


@dataclass
class World:
    instrument: Instrument
    case: dict
    prepared: Prepared
    registry: object
    replay: object
    gateway: object
    ledger: object
    request_registry: object
    issued_registry: object
    state: dict
    workdir: object
    control_events: list = field(default_factory=list)
    revoked_tokens: set = field(default_factory=set)
    revoked_authorities: set = field(default_factory=set)
    status_ok: bool = True
    state_ok: bool = True
    pending: object = None
    threads: list = field(default_factory=list)
    lock_connection: object = None
    gateway_calls: int = 0

    def close(self):
        for thread in self.threads:
            thread.join(timeout=5)
            if thread.is_alive():
                raise RuntimeError("synchronized probe did not complete")
        if self.lock_connection:
            self.lock_connection.rollback()
            self.lock_connection.close()
        self.workdir.cleanup()


def new_world(instrument, case):
    p = instrument.prepare(case)
    registry = api.TokenAuthorityRegistry()
    registry.register(p.token, instrument.signer, authority_key_ids=p.dependencies, now=p.issued)
    ledger = HookLedger()
    replay = ReplayObserver(api.ReplayCache())
    gateway = api.EnforcementGateway(instrument.signer, replay_cache=replay, authority_registry=registry, ledger=ledger)
    issued_registry = EnvelopeIdempotencyRegistry()
    issued_registry.claim(p.request["idempotency_key"], p.payload["envelope_digest"])
    return World(instrument, case, p, registry, replay, gateway, ledger,
        EnvelopeIdempotencyRegistry(), issued_registry,
        {p.request["target"]: {"mode": "available", "scope": "none", "writes": 0}},
        tempfile.TemporaryDirectory(prefix="cerberus-replay-v3-"))


def raw_guardian(world, step):
    ins, p, raw = world.instrument, world.prepared, step["request"]
    try:
        envelope = api.ActionEnvelope.from_dict(raw)
        if step.get("mode") == "fresh":
            _, verifier, proofs, _ = ins.material(raw)
            if step.get("event") == "omit_sidecar_approvals":
                sidecar = proofs.to_dict()
                sidecar.pop("approvals")
                proofs = api.AssuranceBundle.from_dict(sidecar)
            registry = world.request_registry
        else:
            trust = world.case.get("original_trust", p.trust)
            verifier, proofs = v1.verifier(trust), p.proofs
            registry = world.issued_registry
        decision = api.Guardian(ins.policies, signer=ins.signer, assurance_verifier=verifier,
            idempotency_registry=registry).evaluate(envelope, assurance=proofs, now=parse(step["evaluation_at"]))
    except (ValidationError, ValueError) as exc:
        return None, {"guardian_decision": None, "reason": str(exc), "input_rejected": True}, None
    view = {k: v for k, v in decision.to_dict().items() if k not in {"decision_token", "audit_record_hash"}}
    return decision, view, proofs


def revoke(world, kind):
    if kind == "revoke_token":
        world.registry.revoke_token(world.prepared.payload["token_id"])
        world.revoked_tokens.add(world.prepared.payload["token_id"])
    else:
        key = sorted(world.prepared.dependencies)[0]
        world.registry.revoke_authority(key)
        world.revoked_authorities.add(key)
    world.control_events.append(kind)


def configure_event(world, step, token):
    event = step.get("event", "none")
    if step.get("new_gateway"):
        world.gateway = api.EnforcementGateway(world.instrument.signer, replay_cache=world.replay,
            authority_registry=world.registry, ledger=world.ledger)
    if event in {"revoke_token", "revoke_authority"}:
        if step.get("threaded"):
            done = Event()
            thread = Thread(target=lambda: (revoke(world, event), done.set()))
            thread.start()
            if not done.wait(5):
                raise RuntimeError("ordered revocation did not complete")
            thread.join()
        else:
            revoke(world, event)
    elif event == "registry_missing":
        world.gateway.authority_registry = None
        world.status_ok = False
    elif event == "registry_unavailable":
        world.registry.close()
        world.status_ok = False
    elif event == "registry_corrupt":
        world.gateway.authority_registry = CorruptRegistry()
        world.status_ok = False
    elif event == "registry_empty":
        world.gateway.authority_registry = api.TokenAuthorityRegistry()
        world.status_ok = False
    elif event.startswith("sqlite"):
        path = Path(world.workdir.name) / "authority.db"
        if event == "sqlite_locked":
            store = api.SQLiteStateStore(path, create=True)
            world.lock_connection = sqlite3.connect(path)
            world.lock_connection.execute("BEGIN IMMEDIATE")
        else:
            if event == "sqlite_corrupt":
                path.write_bytes(b"fabricated corrupt database, not telemetry")
            elif event == "sqlite_empty_unprovisioned":
                path.write_bytes(b"")
            try:
                store = api.SQLiteStateStore(path)
            except StateUnavailable as exc:
                world.state_ok = False
                return {"accepted": False, "reason": str(exc), "receipt": None,
                    "construction_refusal": True, "elapsed_ns": None, "error": None}
        world.replay = ReplayObserver(store)
        world.gateway.replay_cache = world.replay
        world.state_ok = False
    elif event == "replay_unavailable":
        world.replay = ReplayObserver(UnavailableReplay())
        world.gateway.replay_cache = world.replay
        world.state_ok = False
    elif event == "audit_failure":
        def fail():
            raise InjectedAuditFailure("synthetic audit failure after consumption")
        world.ledger.hook = fail
    elif event in {"revoke_during_commit", "duplicate_during_commit"}:
        entered = Event()
        def worker():
            world.control_events.append("worker_started")
            entered.set()
            if event == "revoke_during_commit":
                revoke(world, "revoke_token")
            else:
                world.pending = call_gateway(world, token, step["request"], parse(step["evaluation_at"]))
            world.control_events.append("worker_completed")
        def hook():
            world.control_events.append("commit_lock_held")
            thread = Thread(target=worker)
            world.threads.append(thread)
            thread.start()
            if not entered.wait(5):
                raise RuntimeError("commit probe did not synchronize")
            world.control_events.append("receipt_commit")
        world.ledger.hook = hook
    return None


def call_gateway(world, token, raw, now):
    start = perf_counter_ns()
    try:
        receipt = world.gateway.authorize_and_simulate(token, action=raw.get("action"),
            target=raw.get("target"), scope=raw.get("scope"), expected_envelope=raw, now=now)
        accepted, reason, error = True, "Kernel returned a simulated receipt", None
    except api.EnforcementDenied as exc:
        accepted, reason, receipt, error = False, str(exc), None, None
    except InjectedAuditFailure as exc:
        accepted, reason, receipt, error = False, str(exc), None, "controlled-audit-failure"
    except Exception as exc:
        accepted, reason, receipt, error = False, f"{type(exc).__name__}: {exc}", None, "unexpected-runtime-error"
    elapsed = perf_counter_ns() - start
    world.gateway_calls += 1
    return {"accepted": accepted, "reason": reason, "receipt": receipt, "elapsed_ns": elapsed,
        "construction_refusal": False, "error": error}


def observe(world, step):
    ins, p = world.instrument, world.prepared
    decision, guardian, proofs = raw_guardian(world, step)
    token, payload = p.token, p.payload
    if step.get("mode") in {"fresh", "guardian"}:
        token = decision.decision_token if decision and decision.decision_token else ""
        if token:
            payload = ins.signer.verify(token, now=parse(step["evaluation_at"]))
            world.registry.register(token, ins.signer,
                authority_key_ids=frozenset(p.key_id for p in proofs.evidence+proofs.approvals), now=parse(step["evaluation_at"]))
    for key in world.case.get("original_trust", {}).get("revoked_key_ids", []):
        world.registry.revoke_authority(key)
        world.revoked_authorities.add(key)
    before = deepcopy(world.state)
    claims_before = list(world.replay.claims)
    # Independent effect-context observation. Never gates execution or mutation.
    request_digest = None
    try:
        request_digest = api.ActionEnvelope.from_dict(step["request"]).digest()
    except ValidationError:
        pass
    now = parse(step["evaluation_at"])
    context_allowed = bool(token and request_digest == payload["envelope_digest"]
        and all(step["request"].get(k) == payload[k] for k in ("action", "target", "scope"))
        and parse(payload["issued_at"]) <= now < parse(payload["expires_at"])
        and payload["token_id"] not in world.revoked_tokens
        and not p.dependencies.intersection(world.revoked_authorities)
        and not any(t == payload["token_id"] or i == payload["idempotency_key"] for t, i, _ in claims_before)
        and world.status_ok and world.state_ok)
    pre_refusal = configure_event(world, step, token)
    context_allowed = context_allowed and world.status_ok and world.state_ok and payload["token_id"] not in world.revoked_tokens and not p.dependencies.intersection(world.revoked_authorities)
    if step.get("use_pending_duplicate"):
        if world.pending is None:
            raise RuntimeError("missing overlapping duplicate observation")
        outcome = world.pending
    else:
        outcome = pre_refusal or call_gateway(world, token, step["request"], now)
    for thread in world.threads:
        thread.join(timeout=5)
        if thread.is_alive():
            raise RuntimeError("probe deadlocked")
    mutations, violations = [], []
    receipt = outcome["receipt"]
    if outcome["accepted"]:
        if not isinstance(receipt, dict) or receipt.get("status") != "simulated" or receipt.get("side_effects") is not False:
            raise RuntimeError("invalid or nonsimulated receipt")
        # Apply first; expected labels cannot suppress an observed accepted effect.
        target = receipt["target"]
        old = deepcopy(world.state.get(target))
        world.state[target] = {"mode": receipt["action"], "scope": receipt["scope"],
            "writes": (old or {}).get("writes", 0)+1}
        exact_receipt = v1.valid_receipt(receipt, step["request"], payload)
        allowed = context_allowed and exact_receipt
        mutations.append({"resource": target, "before": old, "after": deepcopy(world.state[target]),
            "in_authorized_scope": allowed, "request_sha256": request_digest,
            "receipt_envelope_digest": receipt.get("envelope_digest")})
        if not allowed:
            violations.append("OUT_OF_SCOPE_SIMULATOR_MUTATION")
        if not exact_receipt:
            violations.append("INVALID_RECEIPT_BINDING")
        if step["expected"] not in {"approve", "doc-ambiguous"}:
            violations.append("UNSAFE_KERNEL_PERMISSION")
    if step.get("mode") == "fresh" and guardian.get("guardian_decision") == "approve" and step["expected"] not in {"approve", "doc-ambiguous"}:
        violations.append("UNSAFE_GUARDIAN_AUTHORIZATION")
    if decision and decision.guardian_decision != "approve" and decision.decision_token:
        violations.append("TOKEN_ON_NONAPPROVED_DECISION")
    if not world.ledger.verify():
        violations.append("INVALID_KERNEL_AUDIT_CHAIN")
    terminal = "approve" if outcome["accepted"] else (
        guardian.get("guardian_decision") if step.get("mode") in {"fresh", "guardian"}
        and guardian.get("guardian_decision") in {"deny", "escalate"} else "deny")
    # Match v2's baseline interfaces exactly; decisions/functions remain untouched.
    baseline_case = {"request": step["request"], "expected": step["expected"], "evaluation_at": step["evaluation_at"]}
    systems = {name: v1.baseline(baseline_case, name, .9) for name in SYSTEMS[1:3]}
    systems["soar_b2"] = v2.b2(baseline_case, {"signer": ins.signer, "token": p.token})
    clean_receipt = None if receipt is None else {k: v for k, v in receipt.items() if k not in {"token_id", "audit_record_hash"}}
    systems["cerberus"] = {"decision": terminal, "guardian_decision": guardian.get("guardian_decision"),
        "guardian": guardian, "input_rejected": guardian.get("input_rejected", False),
        "decision_layer": "guardian_and_kernel" if step.get("mode") in {"fresh", "guardian"} else "presented_grant_kernel",
        "reason": outcome["reason"], "receipt": clean_receipt, "setup_control_passed": p.positive_control,
        "measurement_valid": outcome["error"] != "unexpected-runtime-error", "error": outcome["error"],
        "violations": violations,
        "kernel_probes": [{"probe": "primary_request", "expected_block": step["expected"] not in {"approve", "doc-ambiguous"},
            "accepted": outcome["accepted"], "reason": outcome["reason"]}],
        "simulator_state": {"before": before, "after": deepcopy(world.state), "mutations": mutations,
            "total": len(mutations), "out_of_scope": sum(not m["in_authorized_scope"] for m in mutations)},
        "replay_claims_added": len(world.replay.claims)-len(claims_before),
        "controller_events": list(world.control_events), "construction_refusal": outcome["construction_refusal"]}
    row = {"id": step["id"], "episode_id": world.case["id"], "grant_id": world.case["id"],
        "sequence_step": world.case["steps"].index(step)+1, "class": world.case["class"],
        "variant": world.case["variant"], "expected": step["expected"], "rule": step["rule"],
        "evaluation_at": step["evaluation_at"], "request_sha256": sha(canonical(step["request"])),
        "setup_sha256": sha(canonical(world.case["setup"])), "systems": systems}
    return row, outcome["elapsed_ns"]


def interval(metric):
    if metric is None:
        return None
    out = dict(metric)
    x, n = out["numerator"], out["denominator"]
    if n and out["rate"] is not None:
        z = 1.959963984540054
        phat = x/n
        center = (phat+z*z/(2*n))/(1+z*z/n)
        radius = z*math.sqrt(phat*(1-phat)/n+z*z/(4*n*n))/(1+z*z/n)
        out["wilson_95"] = [max(0, center-radius), min(1, center+radius)]
        if x == 0:
            out["rule_of_three_upper_95"] = min(1, 3/n)
    else:
        out["wilson_95"] = None
    return out


def summarize(rows, system):
    scored = [r for r in rows if r["expected"] != "doc-ambiguous"]
    result = v1.summarize(scored, system)
    for key, value in list(result.items()):
        if isinstance(value, dict) and {"numerator", "denominator", "rate"} <= value.keys():
            result[key] = interval(value)
    result["doc_ambiguous_excluded"] = len(rows)-len(scored)
    result["all_attempts"] = len(rows)
    result["violation_attempt_rate"] = interval(v1.ratio(result["cases_with_violations"], len(scored)))
    if system == "cerberus":
        events = [m for r in rows for m in r["systems"][system].get("simulator_state", {}).get("mutations", [])]
        result["simulator_state"] = {"total": len(events), "authorized": sum(m["in_authorized_scope"] for m in events),
            "out_of_scope": sum(not m["in_authorized_scope"] for m in events)}
        result["out_of_scope_mutation_rate"] = interval(v1.ratio(result["simulator_state"]["out_of_scope"], len(events)))
        result["kernel_refusals_all"] = sum(not p["accepted"] for r in rows for p in r["systems"][system]["kernel_probes"])
        result["construction_refusals"] = sum(r["systems"][system].get("construction_refusal", False) for r in rows)
        called_rows = [r for r in rows if not r["systems"][system].get("construction_refusal", False)]
        called_negative = [p for r in called_rows if r["expected"] != "doc-ambiguous"
            for p in r["systems"][system]["kernel_probes"] if p["expected_block"]]
        result["kernel_call_refusal"] = interval(v1.ratio(sum(not p["accepted"] for p in called_negative), len(called_negative)))
        result["kernel_call_refusals_all"] = sum(not p["accepted"] for r in called_rows for p in r["systems"][system]["kernel_probes"])
    else:
        result["simulator_state"] = None
        result["kernel_refusals_all"] = None
    return result


def failing_layer(row):
    obs = row["systems"]["cerberus"]
    if row["variant"].startswith("sqlite") or row["variant"] == "replay_unavailable":
        return "registry (SQLite replay state)"
    if "UNSAFE_GUARDIAN_AUTHORIZATION" in obs["violations"]:
        return "Guardian"
    if row["variant"].startswith("registry"):
        return "registry/gateway"
    if obs["input_rejected"]:
        return "Guardian input contract"
    return "Kernel/gateway"


def functional(oracle, cases, preservation):
    policies = api.PolicyBundle.load(ROOT/"policies/policies.json")
    instrument = Instrument(policies)
    rows, controls = [], []
    for index, case in enumerate(cases):
        world = new_world(instrument, case)
        try:
            for step in case["steps"]:
                row, _ = observe(world, step)
                row["basis"] = oracle["rules"][step["rule"]]
                rows.append(row)
        finally:
            world.close()
        if (index+1) % 500 == 0:
            print(f"functional: {index+1}/{len(cases)} episodes", flush=True)
    groups = {name: [r for r in rows if r["class"] == name] for name in FAMILIES}
    groups.update(novel_A_G=[r for r in rows if r["class"] != "H"], overall=rows)
    summaries = {name: {s: summarize(selected, s) for s in SYSTEMS} for name, selected in groups.items()}
    failures, baseline_failures, ambiguous = [], [], []
    for row in rows:
        if row["expected"] == "doc-ambiguous":
            ambiguous.append(row)
            continue
        for system in SYSTEMS:
            obs = row["systems"][system]
            if obs["decision"] != row["expected"] or obs["violations"] or not obs["measurement_valid"]:
                failure = {k: row[k] for k in ("id", "class", "variant", "expected", "rule", "basis")}
                failure.update(system=system, observed=obs["decision"], reason=obs["reason"],
                    guardian_decision=obs.get("guardian_decision"), violations=obs["violations"],
                    measurement_valid=obs["measurement_valid"], failing_layer=failing_layer(row) if system == "cerberus" else "baseline")
                (failures if system == "cerberus" else baseline_failures).append(failure)
    overall = summaries["overall"]["cerberus"]
    code = 2 if overall["measurement_errors"] else 1 if failures or overall["simulator_state"]["out_of_scope"] else 0
    result = {"instrument": "replay_v3-held-out", "seed": oracle["seed"], "clock": oracle["clock"],
        "base_commit": BASE, "oracle_sha256": ORACLE_HASH, "recipes_sha256": oracle["recipes_sha256"],
        "corpus_sha256": sha(canonical(cases)), "episodes": len(cases), "requests": len(rows),
        "source_preservation": preservation, "setup_control_mutations": instrument.setup_controls,
        "setup_controls": "One exact receipt/audit control per unique frozen grant; isolated worlds excluded from functional totals.",
        "per_class": {k: summaries[k] for k in FAMILIES}, "overall": summaries["overall"],
        "novel_A_G": summaries["novel_A_G"], "observations": rows, "failures": failures,
        "baseline_failures": baseline_failures, "doc_ambiguous": ambiguous, "oracle_defects": [],
        "guardian_changes": [], "exit_code": code,
        "scope_note": "Fresh requests traverse Guardian and Kernel. Presented-grant episodes retain raw Guardian diagnostics but grade the actual supplied original grant's enforcement; an independently rejected re-authorization does not revoke an already issued token.",
        "limits": "Synthetic replay, labels derived from repository documents, trusted process-local registry, correct trusted provisioning and upstream revocation delivery assumed, compromised trusted producers out of scope, not field validation. H is a correlated deterministic sweep derived from v2, not independent held-out random evidence. A-G are new challenge recipes. No real telemetry, credentials, network, connectors, containment or recovery. Ordering probes exercise named synchronized linearizations, not exhaustive races."}
    from benchmarks.replay_v3.audit_findings import annotate_oracle_defects
    return annotate_oracle_defects(result, cases), instrument


def latency(cases, instrument):
    samples, per_request = [], []
    for index, case in enumerate(cases):
        for position, step in enumerate(case["steps"]):
            timings, excluded, errors, observed_decisions = [], 0, [], set()
            for rep in range(WARMUP+REPETITIONS):
                world = new_world(instrument, case)
                try:
                    row, elapsed = None, None
                    for prefix in case["steps"][:position+1]:
                        row, elapsed = observe(world, prefix)
                    observed_decisions.add(row["systems"]["cerberus"]["decision"])
                    if rep >= WARMUP:
                        if elapsed is None:
                            excluded += 1
                        else:
                            timings.append(elapsed)
                    if not row["systems"]["cerberus"]["measurement_valid"]:
                        errors.append(row["systems"]["cerberus"]["reason"])
                finally:
                    world.close()
            if len(observed_decisions) != 1 or errors:
                raise RuntimeError("latency did not reproduce the functional outcome: " + step["id"])
            samples.append({"id": step["id"], "class": case["class"], "ns": timings,
                "construction_refusals_no_enforcement_call": excluded})
            per_request.append({"id": step["id"], "class": case["class"], "samples": len(timings),
                "latency": v2.percentiles(timings) if timings else None,
                "construction_refusals_no_enforcement_call": excluded, "outcome": next(iter(observed_decisions))})
        if (index+1) % 500 == 0:
            print(f"latency: {index+1}/{len(cases)} episodes", flush=True)
    grouped = {}
    for family in FAMILIES+("novel_A_G", "overall"):
        selected = [s for s in samples if family == "overall" or (family == "novel_A_G" and s["class"] != "H") or s["class"] == family]
        vals = [n for s in selected for n in s["ns"]]
        grouped[family] = {"samples": len(vals), "latency": v2.percentiles(vals) if vals else None,
            "construction_refusals_no_enforcement_call": sum(s["construction_refusals_no_enforcement_call"] for s in selected)}
    cpu = platform.processor() or "unreported"
    if Path("/proc/cpuinfo").exists():
        cpu = next((l.split(":", 1)[1].strip() for l in Path("/proc/cpuinfo").read_text().splitlines() if l.startswith("model name")), cpu)
    return {"warmup_per_attempt": WARMUP, "repetitions_per_attempt": REPETITIONS,
        "clock": "perf_counter_ns", "percentiles": "nearest-rank", "per_request": per_request, "aggregates": grouped,
        "hardware": {"cpu": cpu, "os": platform.platform(), "architecture": platform.machine(),
            "python": platform.python_version(), "dependencies": {n: importlib.metadata.version(n) for n in ("cryptography", "jsonschema", "rfc3339-validator")},
            "isolation": "No CPU pinning, load or frequency controls. Existing local dependencies; no downloads.",
            "dependency_note": "Record actual versions; this host's cryptography/jsonschema may differ from requirements.txt pins."},
        "limits": "Enforcement call only; construction, signing, proofs, controller events and state grading excluded. Every repetition restores episode prefix and replay/registry world. Refused/accepted paths do different useful work. Constructor refusals have no enforcement call and are explicitly N/A; never reported as zero latency. Synchronized worker creation at the commit hook is included in contention-call latency."}, samples


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output-dir", type=Path, default=ROOT/"results/replay_v3")
    args = parser.parse_args()
    args.output_dir.mkdir(parents=True, exist_ok=True)
    try:
        with offline():
            oracle, cases, preservation = frozen_inputs()
            print(f"Frozen v3 oracle SHA-256: {ORACLE_HASH}", flush=True)
            result, instrument = functional(oracle, cases, preservation)
            result["measurement_harness"] = {"commit": git("rev-parse", "HEAD"),
                "run_sha256": sha((HERE/"run.py").read_bytes())}
            print(f"Functional status: {'PASS' if result['exit_code'] == 0 else 'FAIL'}; {len(result['failures'])} CERBERUS failures; {len(result['doc_ambiguous'])} ambiguous attempts", flush=True)
            result["latency"], raw = latency(cases, instrument)
            functional_outcomes = {o["id"]: o["systems"]["cerberus"]["decision"] for o in result["observations"]}
            if any(p["outcome"] != functional_outcomes[p["id"]] for p in result["latency"]["per_request"]):
                raise RuntimeError("latency outcomes disagree with functional measurement")
            from benchmarks.replay_v3.evidence import sqlite_empty_evidence, validate_repetition
            print("Rechecking full functional observations in fresh worlds", flush=True)
            repeated, _ = functional(oracle, cases, preservation)
            result["validation"] = validate_repetition(result, repeated, result["latency"])
            storage_evidence = sqlite_empty_evidence(cases, instrument)
            result["supplemental_storage_evidence"] = "sqlite_empty_evidence.json"
            # Recheck after execution as well, before publication.
            frozen_inputs()
        (args.output_dir/"results.json").write_text(json.dumps(result, ensure_ascii=False, separators=(",", ":"))+"\n")
        (args.output_dir/"latency_samples.jsonl").write_text("".join(json.dumps(s, separators=(",", ":"))+"\n" for s in raw))
        (args.output_dir/"validation.json").write_text(json.dumps(result["validation"], indent=2)+"\n")
        (args.output_dir/"sqlite_empty_evidence.json").write_text(json.dumps(storage_evidence, indent=2)+"\n")
        import gzip
        # Identical JSON schema and observations, in a lossless publication
        # container. Keep ordinary JSON locally for v1/v2-style consumers.
        with gzip.GzipFile(filename="", mode="wb", fileobj=(args.output_dir/"results.json.gz").open("wb"), mtime=0) as stream:
            stream.write((args.output_dir/"results.json").read_bytes())
        with gzip.GzipFile(filename="", mode="wb", fileobj=(args.output_dir/"corpus.jsonl.gz").open("wb"), mtime=0) as stream:
            for c in cases:
                stream.write(canonical(c)+b"\n")
        from benchmarks.replay_v3.render import render
        (args.output_dir/"report.md").write_text(render(result))
        print(json.dumps({"status": "PASS" if result["exit_code"] == 0 else "FAIL", "exit_code": result["exit_code"],
            "episodes": result["episodes"], "requests": result["requests"], "false_allow": result["overall"]["cerberus"]["false_allow"],
            "false_deny": result["overall"]["cerberus"]["false_deny"], "failures": len(result["failures"])}), flush=True)
        raise SystemExit(result["exit_code"])
    except (ValueError, RuntimeError) as exc:
        (args.output_dir/"invalid_measurement.json").write_text(json.dumps({"exit_code": 2, "reason": str(exc)}, indent=2)+"\n")
        print("INVALID MEASUREMENT: " + str(exc), file=sys.stderr)
        raise SystemExit(2)


if __name__ == "__main__":
    main()
