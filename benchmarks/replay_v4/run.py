# Copyright 2026 Emily Echterhoff
# SPDX-License-Identifier: Apache-2.0
"""Post-repair synthetic challenge; never an independent or blinded field trial.

The four Stage A files are immutable. Expected labels enter grading only, never
fixture construction, authority, fault delivery, or simulated effect application.
"""
from __future__ import annotations

import argparse
from collections import Counter
from contextlib import contextmanager
from copy import deepcopy
from datetime import datetime, timezone
import errno
import gzip
import hashlib
import importlib.metadata
import json
import math
import os
from pathlib import Path
import platform
import socket
import sqlite3
import stat
import subprocess
import sys
import tempfile
from time import perf_counter_ns
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
import cerberus as api
from cerberus.assurance import (ApprovalAuthority, ApprovalProof, AssuranceBundle,
    AssuranceError, AssuranceVerifier, EvidenceAuthority, EvidenceProof,
    approval_message, evidence_message)
from cerberus.models import ValidationError
from cerberus.state import SQLiteStateStore, StateUnavailable
from benchmarks.replay_v1 import run as v1
from benchmarks.replay_v2 import run as v2
from simulator.assurance_fixtures import fixture_key

HERE = Path(__file__).resolve().parent
FREEZE = "93f70d4603d06d323675456f90f2629b6b0d3b52"
TARGET = "6fe417400ff4844d7647dddd9435288c3485ffc0"
BASE = "f0ebd38c58e9d40af35d35c5cc32b5614eb60439"
ORACLE_SHA256 = "18539d829f7f95ef0a3e93bde607b253b76b15085c184816b862574c48b217a0"
SYSTEMS = ("cerberus", "allow_if_recommended", "confidence_0.9", "soar_b2")
WARMUP, REPETITIONS = 5, 20


def canonical(x):
    return json.dumps(x, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()


def sha(x):
    return hashlib.sha256(x).hexdigest()


def git(*args):
    return subprocess.check_output(["git", "-C", str(ROOT), *args])


def frozen_inputs():
    for name in ("PLAN.md", "ORACLE.md", "oracle.json", "oracle.sha256"):
        path = "benchmarks/replay_v4/" + name
        if (ROOT/path).read_bytes() != git("show", FREEZE+":"+path):
            raise ValueError("frozen v4 artifact changed: " + path)
    raw = (HERE/"oracle.json").read_bytes()
    if sha(raw) != ORACLE_SHA256 or (HERE/"oracle.sha256").read_text().split()[0] != ORACLE_SHA256:
        raise ValueError("v4 oracle digest mismatch")
    oracle = json.loads(raw)
    protected = git("ls-tree", "-r", "--name-only", TARGET).decode().splitlines()
    checked = []
    for p in protected:
        if p.startswith(("cerberus/", "sdk/", "policies/", "schemas/", "benchmarks/", "results/")):
            if (ROOT/p).read_bytes() != git("show", TARGET+":"+p):
                raise ValueError("evaluated source or historical evidence changed: " + p)
            checked.append(p)
    for source in oracle["inputs"]["source_documents"].values():
        if git("hash-object", source["path"]).decode().strip() != source["git_blob"]:
            raise ValueError("documentary source changed: " + source["path"])
    if git("hash-object", "cerberus/guardian.py").decode().strip() != oracle["guardian_baseline_git_blob"]:
        raise ValueError("Guardian changed")
    for key, template in oracle["templates"].items():
        if canonical(template["envelope"]) != template["canonical_json"].encode():
            raise ValueError("template canonicalization mismatch: " + key)
    for case in oracle["cases"]:
        if case["family"] == "W":
            candidate = wire_candidate(case, oracle["templates"][case["template_ref"]]["envelope"])
            original = oracle["templates"][case["template_ref"]]["canonical_json"].encode()
            guard = case["identity_guard"]
            if canonical(candidate) != case["candidate_canonical_json"].encode():
                raise ValueError("W candidate canonical bytes changed")
            if (canonical(candidate) == original) != guard["canonical_bytes_equal"]:
                raise ValueError("W identity guard changed")
            if guard["original_utf8_bytes"] != len(original) or guard["candidate_utf8_bytes"] != len(canonical(candidate)):
                raise ValueError("W identity byte count changed")
    labels = Counter(a["expected"] for c in oracle["cases"] for a in c["attempts"])
    if dict(labels) != oracle["coverage"]["attempt_labels"] or len(oracle["cases"]) != 1005:
        raise ValueError("coverage mismatch")
    return oracle, {"v4_oracle_sha256": sha(raw), "protected_paths": len(checked),
        "target_commit": TARGET, "freeze_commit": FREEZE,
        "source_diff_stat": git("diff", "--stat", TARGET, "--", "cerberus", "sdk", "policies", "schemas").decode(),
        "historical_diff_stat": git("diff", "--stat", TARGET, "--", "benchmarks/replay_v1", "benchmarks/replay_v2", "benchmarks/replay_v3", "results/replay_v1", "results/replay_v2", "results/replay_v3").decode()}


def parse(s):
    return datetime.fromisoformat(s.replace("Z", "+00:00"))


def wire_candidate(case, original):
    candidate = json.loads(case["candidate_canonical_json"])
    variant = case["variant"]
    if variant == "identity_object_order_and_whitespace":
        candidate = json.loads(json.dumps(dict(reversed(list(candidate.items()))), indent=3))
    elif variant == "identity_escaped_ASCII_identifier":
        wire = json.dumps(candidate)
        encoded = '"' + ''.join("\\u%04x" % ord(c) for c in candidate["target"]) + '"'
        candidate = json.loads(wire.replace(json.dumps(candidate["target"]), encoded))
    elif variant == "identity_change_then_restore":
        target = candidate["target"]
        candidate["target"] += ":intermediate-only"
        candidate["target"] = target
    elif variant == "identity_noop_assignment":
        candidate["target"] = original["target"]
    return candidate


def material(template, raw=None):
    """Only frozen operator allowlists confer trust; candidate data never does."""
    recipe = template["assurance_recipe"]
    env = api.ActionEnvelope.from_dict(raw if raw is not None else template["envelope"])
    evidence, approvals = recipe["evidence_authorities"], recipe["approval_authorities"]
    verifier = AssuranceVerifier(
        evidence_authorities=tuple(EvidenceAuthority(
            a["key_id"], fixture_key(a["key_id"]).public_key().public_bytes_raw(),
            frozenset({a["source_id"]}), frozenset(a["allowed_signals"]),
            frozenset(a["allowed_targets"]), a["independence_domain"]) for a in evidence),
        approval_authorities=tuple(ApprovalAuthority(
            a["key_id"], fixture_key(a["key_id"]).public_key().public_bytes_raw(),
            a["principal"], frozenset(a["allowed_labels"]), frozenset(a["allowed_actions"]),
            frozenset(a["allowed_targets"])) for a in approvals))
    by_source = {a["source_id"]: a for a in evidence}
    by_label = {label: a for a in approvals for label in a["allowed_labels"]}
    proofs = []
    for item in env.evidence:
        a = by_source[item.source_id]
        key = a["key_id"]
        proofs.append(EvidenceProof(key, fixture_key(key).sign(evidence_message(env, item, key)).hex()))
    approval_proofs = []
    for label in env.human_approvals:
        key = by_label[label]["key_id"]
        expiry = recipe["approval_expiry"]
        approval_proofs.append(ApprovalProof(key, expiry,
            fixture_key(key).sign(approval_message(env, label, key, expiry)).hex()))
    return env, verifier, AssuranceBundle(tuple(proofs), tuple(approval_proofs))


@contextmanager
def offline():
    def forbidden(*a, **k):
        raise AssertionError("evaluation networking is forbidden")
    with patch.object(socket, "socket", forbidden), patch.object(socket, "create_connection", forbidden), patch.object(socket, "getaddrinfo", forbidden):
        yield


class FixtureInvalid(RuntimeError):
    pass


class InjectedAuditFailure(RuntimeError):
    pass


class FaultLedger(api.AuditLedger):
    fail_next = False

    def append(self, event_type, payload):
        if self.fail_next:
            self.fail_next = False
            raise InjectedAuditFailure("synthetic audit failure after durable consumption")
        return super().append(event_type, payload)


def permission_probe(path, readonly=False):
    caps = next((line.split(":")[1].strip() for line in Path("/proc/self/status").read_text().splitlines() if line.startswith("CapEff:")), None)
    if os.geteuid() == 0 or caps is None or int(caps, 16):
        raise FixtureInvalid("permission fixture requires non-root identity and no effective capabilities")
    results = {}
    for name, flags in (("read", os.O_RDONLY), ("write", os.O_WRONLY), ("read_write", os.O_RDWR)):
        try:
            fd = os.open(path, flags)
        except OSError as exc:
            results[name] = {"denied": exc.errno in (errno.EACCES, errno.EPERM), "errno": exc.errno}
        else:
            os.close(fd)
            results[name] = {"denied": False}
    # SQLite mode=rw requires combined O_RDWR access. Frozen modes 0200/0300
    # intentionally allow write-only while denying that required combined access.
    if not results["read_write"]["denied"] or (readonly and
        (not results["write"]["denied"] or results["read"]["denied"])):
        raise FixtureInvalid("OS access denial was not confirmed: " + str(results))
    return {"euid": os.geteuid(), "egid": os.getegid(), "effective_capabilities": caps, "os_open": results}


def db_snapshot(path):
    if not path.exists() and not path.is_symlink():
        return {"kind": "missing", "claims": None}
    mode = path.lstat().st_mode
    info = {"kind": "symlink" if stat.S_ISLNK(mode) else "directory" if stat.S_ISDIR(mode) else "file",
        "mode": oct(stat.S_IMODE(mode)), "claims": None}
    if info["kind"] != "file":
        return info
    try:
        raw = path.read_bytes()
        info.update(size=len(raw), sha256=sha(raw))
        con = sqlite3.connect(path.as_uri()+"?mode=ro", uri=True, timeout=0)
        try:
            rows = con.execute("SELECT kind, claim_key, digest FROM claims ORDER BY kind, claim_key").fetchall()
            # Token UUIDs are public run-specific values, retained in raw snapshots.
            info["claims"] = rows
            info["claim_counts"] = dict(Counter(r[0] for r in rows))
        finally:
            con.close()
    except (OSError, sqlite3.Error) as exc:
        info["observation_error"] = type(exc).__name__ + ": " + str(exc)
    return info


class Instrument:
    def __init__(self, oracle):
        self.oracle = oracle
        self.now = parse(oracle["clock"])
        self.policies = api.PolicyBundle.load(ROOT/"policies/policies.json")
        self.signer = api.DecisionTokenSigner(v1.PUBLIC_TEST_KEY, key_id="public-replay-v1")
        self.materials = {}
        self.baseline_tokens = {}
        self.setup_controls = {}

    def get_material(self, ref, raw=None):
        key = (ref, sha(canonical(raw)) if raw is not None else "original")
        if key not in self.materials:
            self.materials[key] = material(self.oracle["templates"][ref], raw)
        return self.materials[key]

    def control(self, ref):
        if ref in self.baseline_tokens:
            return self.baseline_tokens[ref]
        env, verifier, proofs = self.get_material(ref)
        with tempfile.TemporaryDirectory(prefix="v4-control-") as d:
            store = SQLiteStateStore(Path(d)/"control.db", create=True)
            decision = api.Guardian(self.policies, signer=self.signer, assurance_verifier=verifier,
                idempotency_registry=store).evaluate(env, assurance=proofs, now=self.now)
            if decision.guardian_decision != "approve" or not decision.decision_token:
                raise FixtureInvalid("genuine control did not authorize: " + decision.reason)
            registry = api.TokenAuthorityRegistry()
            registry.register(decision.decision_token, self.signer, authority_key_ids=frozenset(p.key_id for p in proofs.evidence+proofs.approvals), now=self.now)
            gw = api.EnforcementGateway(self.signer, replay_cache=store, authority_registry=registry)
            receipt = gw.authorize_and_simulate(decision.decision_token, action=env.action, target=env.target,
                scope=env.scope, expected_envelope=env, now=self.now)
            payload = self.signer.verify(decision.decision_token, now=self.now)
            if not v1.valid_receipt(receipt, env.to_canonical_dict(), payload) or not gw.ledger.verify():
                raise FixtureInvalid("genuine exact receipt or audit control failed")
            self.baseline_tokens[ref] = decision.decision_token
            self.setup_controls[ref] = {"guardian": "approve", "receipt": "simulated", "exact_binding": True, "audit_valid": True}
        return decision.decision_token


class World:
    def __init__(self, ins, case):
        self.ins, self.case = ins, case
        self.temp = tempfile.TemporaryDirectory(prefix="v4-case-")
        self.path = Path(self.temp.name)/case["store_path"]
        self.path.parent.mkdir(parents=True)
        self.namespace = case["namespace"]
        self.lock = None
        self.store = None
        self.constructor_refusal = None
        self.constructor_ns = None
        self.events = []
        self.permissions = []
        self.token = ""
        self.payload = None
        self.used_tokens, self.used_executions = set(), set()
        self.revoked_tokens, self.revoked_authorities = set(), set()
        self.status_available = True
        self.registry = api.TokenAuthorityRegistry()
        self.ledger = FaultLedger()
        self.gateway = None
        self.original, self.verifier, self.proofs = ins.get_material(case["template_ref"])
        self.dependencies = frozenset(p.key_id for p in self.proofs.evidence+self.proofs.approvals)
        self.state = {self.original.target: {"mode": "available", "scope": "none", "writes": 0}}
        self.saved_snapshot = None

    def provision(self, path=None):
        return SQLiteStateStore(path or self.path, namespace=self.namespace, create=True)

    def reopen(self):
        start = perf_counter_ns()
        try:
            self.store = SQLiteStateStore(self.path, namespace=self.namespace, create=False)
        except StateUnavailable as exc:
            self.constructor_refusal = str(exc)
        else:
            self.constructor_refusal = None
            self.gateway = api.EnforcementGateway(self.ins.signer, replay_cache=self.store,
                authority_registry=self.registry, ledger=self.ledger)
        self.constructor_ns = perf_counter_ns()-start

    def start(self):
        c = self.case
        if c["family"] == "S":
            v, recipe = c["variant"], c["store_recipe"]
            if v == "missing_file":
                pass
            elif v == "zero_byte_file":
                self.path.touch()
            elif v == "truncated_file":
                self.provision()
                self.path.write_bytes(self.path.read_bytes()[:recipe["truncate_to_bytes"]])
            elif v == "wrong_schema":
                con = sqlite3.connect(self.path)
                con.execute(recipe["unrelated_table_ddl"])
                con.commit(); con.close()
            elif v == "directory_in_place":
                self.path.mkdir()
            elif v == "symlink":
                target = self.path.with_name("target.db")
                kind = recipe["target_state"]
                if kind == "correctly_provisioned_file":
                    self.provision(target)
                elif kind == "zero_byte_file":
                    target.touch()
                elif kind == "directory_in_place":
                    target.mkdir()
                elif kind != "missing_file":
                    raise FixtureInvalid("unknown symlink target state")
                self.path.symlink_to(target if recipe["link_kind"] == "absolute" else target.name)
            else:
                self.provision()
                if v in ("wrong_permissions", "read_only_file"):
                    self.path.chmod(int(recipe["mode_octal"], 8))
                    self.permissions.append(permission_probe(self.path, readonly=v == "read_only_file"))
                elif v == "locked_file":
                    self.hold_lock()
                elif v not in ("correctly_provisioned_file", "explicit_provision_then_use"):
                    raise FixtureInvalid("unimplemented S state: " + v)
        else:
            if c["variant"] == "empty_then_explicit_provision":
                self.path.touch()
            self.provision()
        self.reopen()
        if c["submission_mode"] == "present_original_grant":
            if self.constructor_refusal:
                raise FixtureInvalid("original issuance store unavailable")
            decision = api.Guardian(self.ins.policies, signer=self.ins.signer, assurance_verifier=self.verifier,
                idempotency_registry=self.store).evaluate(self.original, assurance=self.proofs, now=self.ins.now)
            if decision.guardian_decision != "approve" or not decision.decision_token:
                raise FixtureInvalid("original grant could not be issued: " + decision.reason)
            self.set_token(decision.decision_token, self.proofs, self.ins.now)

    def set_token(self, token, proofs, now):
        self.token = token
        self.payload = self.ins.signer.verify(token, now=now)
        self.registry.register(token, self.ins.signer,
            authority_key_ids=frozenset(p.key_id for p in proofs.evidence+proofs.approvals), now=now)

    def hold_lock(self):
        self.lock = sqlite3.connect(self.path, timeout=0)
        self.lock.execute("BEGIN IMMEDIATE")

    def release_lock(self):
        if self.lock is not None:
            self.lock.rollback(); self.lock.close(); self.lock = None

    def event(self, event):
        if event == "unlink_database":
            self.path.unlink()
        elif event in ("truncate_database_to_zero", "leave_or_replace_path_as_zero_byte_file", "replace_test_path_with_zero_byte_file"):
            self.release_lock()
            self.path.write_bytes(b"")
        elif event == "replace_with_fabricated_corrupt_bytes":
            self.path.write_bytes(b"FABRICATED-V4-CORRUPT-STATE")
        elif event in ("ordinary_reopen_create_false_without_provisioning", "ordinary_reopen_still_without_access"):
            self.reopen()
        elif event == "effective_OS_access_denied":
            self.path.chmod(0)
            self.permissions.append(permission_probe(self.path))
        elif event == "hold_conflicting_lock":
            self.hold_lock()
        elif event == "save_exact_preexecution_provisioned_snapshot":
            self.saved_snapshot = self.path.read_bytes()
        elif event == "restore_exact_snapshot_without_documented_operator_reconciliation":
            if self.saved_snapshot is None:
                raise FixtureInvalid("snapshot not saved")
            self.path.write_bytes(self.saved_snapshot)
            self.reopen()
        elif event == "retain_valid_schema_but_erase_persisted_claim_history":
            con = sqlite3.connect(self.path)
            con.execute("DELETE FROM claims"); con.commit(); con.close()
        elif event in ("revoke_original_token", "token_revoked"):
            self.registry.revoke_token(self.payload["token_id"])
            self.revoked_tokens.add(self.payload["token_id"])
        elif event in ("revoke_one_attesting_authority", "authority_revoked"):
            key = sorted(self.dependencies)[0]
            self.registry.revoke_authority(key)
            self.revoked_authorities.add(key)
        elif event == "status_unavailable":
            self.registry.close(); self.status_available = False
        elif event == "inject_audit_failure_after_claim_before_receipt":
            self.ledger.fail_next = True
        else:
            raise FixtureInvalid("unimplemented event: " + event)
        self.events.append(event)

    def close(self):
        self.release_lock()
        if self.path.is_file() and not self.path.is_symlink():
            self.path.chmod(0o600)
        self.temp.cleanup()


def request_for(ins, case, attempt):
    if attempt["request_ref"] == "candidate_canonical_json":
        return wire_candidate(case, ins.oracle["templates"][case["template_ref"]]["envelope"])
    if attempt["request_ref"] == "candidate":
        return deepcopy(case["candidate_envelope"])
    raw = deepcopy(ins.oracle["templates"][attempt["request_ref"]]["envelope"])
    if case.get("wire_control"):
        raw = json.loads(json.dumps(dict(reversed(list(raw.items()))), indent=2))
    return raw


def baseline(ins, case, raw, now):
    original_token = ins.control(case["template_ref"])
    # Alias only: invoke the existing fixed v1/v2 functions without editing them.
    bc = {"request": raw, "evaluation_at": now.isoformat(), "expected": "approve"}
    rows = {}
    for name in SYSTEMS[1:]:
        start = perf_counter_ns()
        if name == "soar_b2":
            obs = v2.b2(bc, {"signer": ins.signer, "token": original_token})
        else:
            obs = v1.baseline(bc, "confidence_threshold" if name == "confidence_0.9" else name, .9)
        elapsed = perf_counter_ns()-start
        rows[name] = {"decision": "allow" if obs["decision"] == "approve" else obs["decision"],
            "measurement_valid": obs["measurement_valid"], "reason": obs["reason"],
            "decision_ns": elapsed, "receipt": None, "effects_measured": False}
    return rows


def observe(world, index):
    ins, case = world.ins, world.case
    attempt = case["attempts"][index]
    raw = request_for(ins, case, attempt)
    now = parse(case.get("execute_at", ins.oracle["clock"]))
    if index == 0:
        for event in case.get("events_before", []):
            world.event(event)
        ordered = case.get("ordered_events", [])
        for event in ordered[1:]:
            if event in ("enforcement_attempt", "receipt_commit", "first_receipt_commit", "duplicate_attempt"):
                break
            world.event(event)
    for event in attempt.get("events_before", []):
        world.event(event)
    constructor_elapsed = world.constructor_ns
    world.constructor_ns = None  # A startup/reopen call belongs to one attempt only.
    systems = baseline(ins, case, raw, now)
    before = db_snapshot(world.path)
    state_before = deepcopy(world.state)
    audit_before = len(world.ledger.records)
    guardian = None
    receipt = None
    guardian_ns, kernel_ns = None, None
    valid, reason, layer = True, "", "constructor"
    violations = []
    token, payload = world.token, world.payload
    consumed_now = False
    try:
        if world.constructor_refusal:
            reason = world.constructor_refusal
        else:
            if case["submission_mode"] == "fresh_authorization":
                try:
                    env = api.ActionEnvelope.from_dict(raw)
                    _, verifier, proofs = ins.get_material(case["template_ref"], raw)
                    if case.get("sidecar_variant"):
                        sidecar = proofs.to_dict(); sidecar.pop("approvals")
                        proofs = AssuranceBundle.from_dict(sidecar)
                    g = api.Guardian(ins.policies, signer=ins.signer, assurance_verifier=verifier, idempotency_registry=world.store)
                    start = perf_counter_ns()
                    decision = g.evaluate(env, assurance=proofs, now=now)
                    guardian_ns = perf_counter_ns()-start
                    guardian = {"decision": decision.guardian_decision, "reason": decision.reason,
                        "policy": decision.policy, "token_issued": bool(decision.decision_token), "audit_valid": g.ledger.verify()}
                    if not g.ledger.verify():
                        violations.append("INVALID_GUARDIAN_AUDIT_CHAIN")
                    if decision.guardian_decision != "approve" and decision.decision_token:
                        violations.append("TOKEN_ON_NONAPPROVED_DECISION")
                    token = decision.decision_token or ""
                    if token:
                        world.set_token(token, proofs, now)
                        payload = world.payload
                    reason = decision.reason
                except (ValidationError, AssuranceError) as exc:
                    token = ""
                    guardian = {"decision": "deny", "reason": str(exc), "input_refusal": True, "token_issued": False}
                    reason = str(exc)
            layer = "kernel"
            start = perf_counter_ns()
            try:
                receipt = world.gateway.authorize_and_simulate(token, expected_envelope=raw,
                    action=raw.get("action"), target=raw.get("target"), scope=raw.get("scope"), now=now)
            except (api.EnforcementDenied, InjectedAuditFailure) as exc:
                reason = type(exc).__name__ + ": " + str(exc)
            finally:
                kernel_ns = perf_counter_ns()-start
            if receipt is not None:
                # Mutation is unconditional on receipt; neither labels nor validity suppress it.
                target = receipt["target"]
                old = world.state.get(target, {})
                world.state[target] = {"mode": receipt["action"], "scope": receipt["scope"], "writes": old.get("writes", 0)+1}
                exact = bool(payload and v1.valid_receipt(receipt, raw, payload))
                context_ok = bool(payload and canonical(raw) == ins.oracle["templates"][case["template_ref"]]["canonical_json"].encode()) if case["submission_mode"] == "present_original_grant" else bool(payload and sha(canonical(raw)) == payload["envelope_digest"])
                temporal = bool(payload and parse(payload["issued_at"]) <= now < parse(payload["expires_at"]))
                replay_ok = bool(payload and payload["token_id"] not in world.used_tokens and payload["idempotency_key"] not in world.used_executions)
                status_ok = bool(payload and world.status_available and payload["token_id"] not in world.revoked_tokens and not world.dependencies.intersection(world.revoked_authorities))
                if not exact: violations.append("INVALID_RECEIPT_BINDING")
                if not context_ok: violations.append("REQUEST_BINDING_VIOLATION")
                if not temporal: violations.append("TEMPORAL_VIOLATION")
                if not replay_ok: violations.append("REPLAY_HISTORY_VIOLATION")
                if not status_ok: violations.append("REVOKED_OR_UNAVAILABLE_AUTHORITY")
                if not (exact and context_ok and temporal and replay_ok and status_ok):
                    violations.append("OUT_OF_SCOPE_SIMULATOR_MUTATION")
                world.used_tokens.add(payload["token_id"])
                world.used_executions.add(payload["idempotency_key"])
                reason = "exact simulated receipt returned"
        after = db_snapshot(world.path)
        counts_before, counts_after = before.get("claim_counts", {}), after.get("claim_counts", {})
        consumed_now = counts_after.get("execution", 0) > counts_before.get("execution", 0)
        if consumed_now and payload:
            world.used_tokens.add(payload["token_id"])
            world.used_executions.add(payload["idempotency_key"])
        if not world.ledger.verify(): violations.append("INVALID_ENFORCEMENT_AUDIT_CHAIN")
        if receipt is not None and case.get("ordered_events", [])[-1:] == ["token_revoked"]:
            world.event("token_revoked")
    except Exception as exc:
        valid = False
        reason = type(exc).__name__ + ": " + str(exc)
        layer = "unexpected_runtime_error"
        after = db_snapshot(world.path)
    decision = "allow" if receipt is not None else "escalate" if guardian and guardian["decision"] == "escalate" else "deny"
    clean_receipt = None if receipt is None else {k:v for k,v in receipt.items() if k not in ("token_id", "audit_record_hash")}
    systems["cerberus"] = {"decision": decision, "measurement_valid": valid, "reason": reason,
        "layer": layer, "guardian": guardian, "receipt": clean_receipt,
        "constructor_refusal": bool(world.constructor_refusal), "constructor_ns": constructor_elapsed,
        "guardian_ns": guardian_ns, "kernel_ns": kernel_ns, "violations": violations,
        "store_before": before, "store_after": after, "state_before": state_before,
        "state_after": deepcopy(world.state), "symbolic_writes": int(receipt is not None),
        "execution_claim_added": consumed_now, "audit_records_added": len(world.ledger.records)-audit_before,
        "controller_events": list(world.events), "permission_probes": deepcopy(world.permissions)}
    return {"id": case["id"]+".s"+str(index+1), "case_id": case["id"], "family": case["family"],
        "subfamily": case.get("subfamily"), "variant": case["variant"], "parent_cluster": case.get("parent_cluster"),
        "request_sha256": sha(canonical(raw)), "expected": attempt["expected"], "citations": attempt["citations"],
        "logical_time": now.isoformat(), "systems": systems}


def invalid_rows(case, exc):
    return [{"id": case["id"]+".s"+str(i+1), "case_id": case["id"], "family": case["family"],
        "subfamily": case.get("subfamily"), "variant": case["variant"], "expected": a["expected"],
        "citations": a["citations"], "systems": {s:{"decision": None, "measurement_valid": False,
            "reason": type(exc).__name__+": "+str(exc), "violations": [], "layer": "invalid_setup"} for s in SYSTEMS}}
        for i,a in enumerate(case["attempts"])]


def episode(ins, case):
    world = None
    try:
        ins.control(case["template_ref"])
        world = World(ins, case)
        world.start()
        return [observe(world, i) for i in range(len(case["attempts"]))]
    except Exception as exc:
        return invalid_rows(case, exc)
    finally:
        if world is not None: world.close()


def rate(n, d):
    if not d: return {"numerator": n, "denominator": d, "rate": None, "wilson95": None, "rule_of_three_upper": None}
    z = 1.959963984540054
    p = n/d; den = 1+z*z/d
    center = (p+z*z/(2*d))/den
    half = z*math.sqrt(p*(1-p)/d+z*z/(4*d*d))/den
    return {"numerator": n, "denominator": d, "rate": p,
        "wilson95": [max(0,center-half), min(1,center+half)], "rule_of_three_upper": min(1,3/d) if n == 0 else None}


def summarize(rows, system):
    scored = [r for r in rows if r["expected"] != "doc-ambiguous"]
    valid = [r for r in scored if r["systems"][system]["measurement_valid"]]
    unsafe = [r for r in valid if r["expected"] in ("deny", "escalate")]
    positive = [r for r in valid if r["expected"] == "allow"]
    return {"attempts": len(rows), "planned_scored": len(scored), "valid_scored": len(valid),
        "ambiguous": len(rows)-len(scored), "measurement_errors": len(scored)-len(valid),
        "correct": sum(r["expected"] == r["systems"][system]["decision"] for r in valid),
        "false_allows": rate(sum(r["systems"][system]["decision"] == "allow" for r in unsafe), len(unsafe)),
        "false_denies": rate(sum(r["systems"][system]["decision"] != "allow" for r in positive), len(positive)),
        "observed_decisions": dict(Counter(r["systems"][system]["decision"] for r in valid)),
        "invariant_violations_scored": sum(len(r["systems"][system].get("violations",[])) for r in valid) if system == "cerberus" else None,
        "symbolic_writes_scored": sum(r["systems"][system].get("symbolic_writes",0) for r in valid) if system == "cerberus" else None,
        "constructor_refusals_scored": sum(r["systems"][system].get("constructor_refusal",False) for r in valid) if system == "cerberus" else None}


def signature(row):
    o = row["systems"]["cerberus"]
    return (o["decision"], o["measurement_valid"], tuple(o.get("violations",[])),
        o.get("constructor_refusal"), o.get("symbolic_writes"), o.get("execution_claim_added"),
        o.get("state_after"), o.get("guardian"), o.get("audit_records_added"),
        o.get("store_after",{}).get("claim_counts"),
        {s:(row["systems"][s]["decision"],row["systems"][s]["measurement_valid"]) for s in SYSTEMS[1:]})


def environment():
    cpu = next((s.split(":",1)[1].strip() for s in Path("/proc/cpuinfo").read_text().splitlines() if s.startswith("model name")), "unknown")
    return {"python": sys.version, "sqlite": sqlite3.sqlite_version, "sqlite_source_id": sqlite3.connect(":memory:").execute("select sqlite_source_id()").fetchone()[0],
        "platform": platform.platform(), "cpu": cpu, "cpu_count": os.cpu_count(), "euid": os.geteuid(),
        "dependencies": {p:importlib.metadata.version(p) for p in ("cryptography","jsonschema","rfc3339-validator","pytest")},
        "pip_freeze": subprocess.check_output([sys.executable,"-m","pip","freeze"],text=True).splitlines(),
        "git_head": git("rev-parse","HEAD").decode().strip(), "git_tree": git("rev-parse","HEAD^{tree}").decode().strip(),
        "git_status": git("status","--porcelain=v1").decode(), "runner_sha256": sha(Path(__file__).read_bytes()),
        "timing_controls": "Sequential single-process measurement; no CPU affinity, frequency or host-load control; SQLite fsync retained. Baselines time decision functions only, not a durable enforcement pipeline."}


def run(output, warmup=WARMUP, repetitions=REPETITIONS):
    oracle, preservation = frozen_inputs()
    output.mkdir(parents=True, exist_ok=True)
    started = datetime.now(timezone.utc).isoformat()
    env = environment()
    ins = Instrument(oracle)
    rows, timings, mismatches = [], [], []
    with offline():
        for i,case in enumerate(oracle["cases"]):
            primary = episode(ins,case)
            rows.extend(primary)
            samples = {r["id"]:{"id":r["id"], "family":r["family"], "kernel_ns":[],
                "guardian_ns":[], "constructor_ns":[], "baseline_ns":{s:[] for s in SYSTEMS[1:]},
                "no_kernel_call":0} for r in primary}
            for repetition in range(warmup+repetitions):
                repeated = episode(ins,case)
                for first, other in zip(primary,repeated):
                    if signature(first) != signature(other):
                        mismatches.append({"id":first["id"],"repetition":repetition,"observed":other})
                    if repetition >= warmup:
                        sample, obs = samples[first["id"]], other["systems"]["cerberus"]
                        for field in ("kernel_ns","guardian_ns","constructor_ns"):
                            if obs.get(field) is not None: sample[field].append(obs[field])
                        sample["no_kernel_call"] += obs.get("kernel_ns") is None
                        for s in SYSTEMS[1:]:
                            if other["systems"][s].get("decision_ns") is not None:
                                sample["baseline_ns"][s].append(other["systems"][s]["decision_ns"])
            timings.extend(samples.values())
            if (i+1)%25 == 0: print(f"v4: {i+1}/{len(oracle['cases'])} episodes complete",flush=True)
            # Recoverable checkpoint; the final file carries complete metadata.
            with gzip.open(output/"checkpoint.json.gz","wt") as f:
                json.dump({"completed_cases":i+1,"rows":rows,"latency_samples":timings},f,separators=(",",":"))
    failures = []
    for row in rows:
        obs = row["systems"]["cerberus"]
        if row["expected"] != "doc-ambiguous" and (not obs["measurement_valid"] or obs["decision"] != row["expected"] or obs.get("violations")):
            failures.append({"id":row["id"],"expected":row["expected"],"observed":obs["decision"],
                "valid":obs["measurement_valid"],"reason":obs["reason"],"layer":obs.get("layer"),
                "violations":obs.get("violations",[]),"citations":row["citations"]})
    groups = {f:[r for r in rows if r["family"] == f] for f in "STUVW"}
    groups.update({"U/"+f:[r for r in rows if r.get("subfamily") == f] for f in ("compound","token_replay","race_ordering","clock_edges","partial_widening")})
    groups.update(overall_descriptive_only=rows)
    summaries = {group:{s:summarize(selected,s) for s in SYSTEMS} for group,selected in groups.items()}
    errors = sum(not r["systems"]["cerberus"]["measurement_valid"] for r in rows)
    code = 2 if errors or mismatches else 1 if failures else 0
    result = {"instrument":"replay_v4_post_repair_2", "target_commit":TARGET, "freeze_commit":FREEZE,
        "seed":oracle["seed"],"clock":oracle["clock"],"started_utc":started,"finished_utc":datetime.now(timezone.utc).isoformat(),
        "preservation":preservation,"environment":env,"cases":len(oracle["cases"]),"primary_attempts":len(rows),
        "summaries":summaries,"failures":failures,"observations":rows,
        "ambiguous_ids":[r["id"] for r in rows if r["expected"] == "doc-ambiguous"],
        "setup_controls":ins.setup_controls,"repeat_mismatches":mismatches,
        "latency":{"warmup":warmup,"measured_repetitions":repetitions,"samples":timings,
            "kernel_percentiles_ns":v2.percentiles([n for s in timings for n in s["kernel_ns"]]),
            "method":"perf_counter_ns. Entire episode reset per repetition; ordered prefixes retained inside episode. Only actual enforcement calls have kernel samples; constructor refusals are N/A, separately timed. Signing, fixture setup, events, snapshots and grading excluded from call timing. Fresh Guardian decision calls separately timed. Baseline decision calls separately timed; no baseline durability/effects measurement."},
        "exit_code":code,"gate":"INVALID_MEASUREMENT" if code == 2 else "FAIL" if code else "PASS",
        "provenance":"Unmodified PR19 target, public precommitted oracle; runner developed after repair and oracle access. Prior failures inform this post-repair challenge. Not blinded, independent human validation, field validation, or operational generalization. W is 25 correlated clusters; overall is descriptive arithmetic only."}
    raw = json.dumps(result,indent=2,sort_keys=True).encode()+b"\n"
    with open(output/"results.json.gz","wb") as f: f.write(gzip.compress(raw,mtime=0))
    (output/"results.sha256").write_text(sha(raw)+"  results.json (decompressed)\n"+sha((output/"results.json.gz").read_bytes())+"  results.json.gz\n")
    (output/"checkpoint.json.gz").unlink()
    print(json.dumps({"gate":result["gate"],"exit_code":code,"primary_attempts":len(rows),"failures":failures,"summary":summaries["overall_descriptive_only"]},indent=2),flush=True)
    return code


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output-dir",type=Path,default=ROOT/"results/replay_v4/pr19_2026-11-11_v2")
    parser.add_argument("--verify-inputs-only",action="store_true")
    args = parser.parse_args()
    if args.verify_inputs_only:
        oracle, preservation = frozen_inputs()
        print(json.dumps({"coverage":oracle["coverage"],"preservation":preservation},indent=2)); return 0
    return run(args.output_dir)


if __name__ == "__main__":
    raise SystemExit(main())
