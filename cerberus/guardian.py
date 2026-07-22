"""Deterministic Guardian policy engine."""

from __future__ import annotations

from dataclasses import replace
from datetime import datetime
from typing import Any

from .audit import AuditLedger
from .models import ActionEnvelope, GuardianDecision
from .policy import PolicyBundle
from .token import DecisionTokenSigner


class EnvelopeIdempotencyRegistry:
    """In-memory exact-once registry for evaluated ActionEnvelope keys.

    This is a prototype interface. A production Guardian must replace it with a
    durable, atomic store shared by all Guardian replicas.
    """

    def __init__(self) -> None:
        self._seen: dict[str, str] = {}

    def claim(self, idempotency_key: str, envelope_digest: str) -> bool:
        if idempotency_key in self._seen:
            return False
        self._seen[idempotency_key] = envelope_digest
        return True


class Guardian:
    """Small, deterministic authorization core.

    The Guardian does not call models, retrieve context, or execute actions. It validates
    a typed request, evaluates explicit policy, optionally mints a short-lived decision
    token, and records the decision.
    """

    def __init__(
        self,
        policy_set: PolicyBundle | dict[str, Any],
        *,
        signer: DecisionTokenSigner | None = None,
        ledger: AuditLedger | None = None,
        idempotency_registry: EnvelopeIdempotencyRegistry | None = None,
    ) -> None:
        bundle = (
            policy_set
            if isinstance(policy_set, PolicyBundle)
            else PolicyBundle.from_dict(policy_set)
        )
        self.policy_bundle = bundle
        self.policy_set = bundle.to_dict()
        self.signer = signer
        self.ledger = ledger or AuditLedger()
        self.idempotency_registry = idempotency_registry or EnvelopeIdempotencyRegistry()
        self.policy_version = bundle.version
        self.policy_digest = bundle.digest
        self.scope_order = list(self.policy_set["scope_order"])

    def _scope_within_limit(self, requested: str, maximum: str) -> bool:
        try:
            return self.scope_order.index(requested) <= self.scope_order.index(maximum)
        except ValueError:
            return False

    def _finalize(
        self,
        envelope: ActionEnvelope,
        *,
        decision: str,
        reason: str,
        policy_id: str | None,
        authorized_action: str = "none",
        scope: str = "none",
        reversible: bool = False,
        human_approval_required: bool = False,
        now: datetime | None = None,
    ) -> GuardianDecision:
        envelope_digest = envelope.digest()
        result = GuardianDecision(
            incident_id=envelope.incident_id,
            envelope_id=envelope.envelope_id,
            guardian_decision=decision,
            reason=reason,
            policy=policy_id,
            policy_version=self.policy_version,
            policy_digest=self.policy_digest,
            proposed_action=envelope.proposed_action,
            authorized_action=authorized_action,
            target=envelope.target,
            scope=scope,
            reversible=reversible,
            human_approval_required=human_approval_required,
            evidence=tuple(sorted(envelope.evidence_signals)),
            independent_source_count=len(envelope.independent_sources),
            envelope_digest=envelope_digest,
            idempotency_key=envelope.idempotency_key,
            actor=envelope.actor,
        )
        token: str | None = None
        if decision == "approve" and self.signer is not None:
            token = self.signer.issue(
                result,
                envelope,
                ttl_seconds=int(self.policy_set["decision_ttl_seconds"]),
                now=now,
            )
        record = self.ledger.append(
            "guardian.decision",
            {
                "incident_id": result.incident_id,
                "envelope_id": result.envelope_id,
                "envelope_digest": result.envelope_digest,
                "idempotency_key": result.idempotency_key,
                "actor": result.actor,
                "decision": result.guardian_decision,
                "policy": result.policy,
                "policy_version": result.policy_version,
                "policy_digest": result.policy_digest,
                "proposed_action": result.proposed_action,
                "authorized_action": result.authorized_action,
                "target": result.target,
                "scope": result.scope,
                "reason": result.reason,
                "token_issued": token is not None,
            },
        )
        return replace(result, decision_token=token, audit_record_hash=record.record_hash)

    def evaluate(self, envelope: ActionEnvelope, *, now: datetime | None = None) -> GuardianDecision:
        envelope.validate()

        if envelope.is_expired(now):
            return self._finalize(
                envelope,
                decision="deny",
                reason="action envelope expired",
                policy_id="GLOBAL-FRESHNESS-INVARIANT",
                now=now,
            )

        if envelope.policy_version != self.policy_version:
            return self._finalize(
                envelope,
                decision="deny",
                reason=(
                    "action envelope requires policy version "
                    f"{envelope.policy_version}; Guardian loaded {self.policy_version}"
                ),
                policy_id="GLOBAL-POLICY-VERSION-INVARIANT",
                now=now,
            )

        envelope_digest = envelope.digest()
        if not self.idempotency_registry.claim(
            envelope.idempotency_key, envelope_digest
        ):
            return self._finalize(
                envelope,
                decision="deny",
                reason="action envelope idempotency key was already evaluated",
                policy_id="GLOBAL-IDEMPOTENCY-INVARIANT",
                now=now,
            )

        forbidden = set(self.policy_set["forbidden_actions"])
        if envelope.proposed_action in forbidden:
            return self._finalize(
                envelope,
                decision="deny",
                reason="proposed action is globally forbidden",
                policy_id="GLOBAL-INVARIANT",
                now=now,
            )

        escalation_signals = set(self.policy_set["escalation_signals"])
        present_escalation_signals = sorted(
            escalation_signals.intersection(envelope.evidence_signals)
        )
        if present_escalation_signals:
            return self._finalize(
                envelope,
                decision="escalate",
                reason=(
                    "conflicting evidence requires review: "
                    + ", ".join(present_escalation_signals)
                ),
                policy_id="GLOBAL-EVIDENCE-CONFLICT",
                human_approval_required=True,
                now=now,
            )

        for policy in self.policy_set["policies"]:
            match = policy["match"]
            if envelope.threat != match["threat"]:
                continue
            # Confidence remains advisory and can never authorize by itself. A minimum
            # threshold may force escalation, but all required behavior and provenance
            # conditions must still be independently satisfied.
            if envelope.confidence < float(match["min_confidence"]):
                continue
            required_signals = set(match["required_signals"])
            if not required_signals.issubset(envelope.evidence_signals):
                continue

            required_sources = int(match["min_independent_sources"])
            if len(envelope.independent_sources) < required_sources:
                return self._finalize(
                    envelope,
                    decision="escalate",
                    reason="insufficient independent evidence sources",
                    policy_id=policy["id"],
                    human_approval_required=True,
                    now=now,
                )

            policy_decision = str(policy["decision"])
            allowed_action = str(policy["allowed_action"])
            max_scope = str(policy["max_scope"])
            reversible_required = bool(policy["reversible_required"])
            approval_required = bool(policy["human_approval_required"])
            approval_count = int(policy["required_approval_count"])
            expected_approval_mode = (
                "dual" if approval_count >= 2 else "single" if approval_count == 1 else "none"
            )

            if approval_count > 0 and envelope.required_approval_mode != expected_approval_mode:
                return self._finalize(
                    envelope,
                    decision="escalate",
                    reason=(
                        "envelope approval mode does not match policy requirement: "
                        f"expected {expected_approval_mode}"
                    ),
                    policy_id=policy["id"],
                    human_approval_required=True,
                    now=now,
                )

            if policy_decision == "approve" and envelope.proposed_action != allowed_action:
                return self._finalize(
                    envelope,
                    decision="deny",
                    reason="proposed action does not match the policy allowlist",
                    policy_id=policy["id"],
                    now=now,
                )

            if not self._scope_within_limit(envelope.requested_scope, max_scope):
                return self._finalize(
                    envelope,
                    decision="deny",
                    reason="requested scope exceeds policy maximum",
                    policy_id=policy["id"],
                    now=now,
                )

            if reversible_required and not envelope.reversible:
                return self._finalize(
                    envelope,
                    decision="deny",
                    reason="policy requires a reversible action",
                    policy_id=policy["id"],
                    now=now,
                )

            if approval_required and len(envelope.human_approvals) < approval_count:
                return self._finalize(
                    envelope,
                    decision="escalate",
                    reason="required human approval not present",
                    policy_id=policy["id"],
                    scope=max_scope,
                    reversible=envelope.reversible,
                    human_approval_required=True,
                    now=now,
                )

            if policy_decision == "escalate" and approval_required:
                policy_decision = str(policy["decision_on_approval"])

            return self._finalize(
                envelope,
                decision=policy_decision,
                reason="policy requirements satisfied",
                policy_id=policy["id"],
                authorized_action=allowed_action if policy_decision == "approve" else "none",
                scope=max_scope if policy_decision == "approve" else "none",
                reversible=envelope.reversible,
                human_approval_required=approval_required,
                now=now,
            )

        return self._finalize(
            envelope,
            decision="escalate",
            reason="no policy satisfied evidence, confidence, and provenance requirements",
            policy_id=None,
            human_approval_required=True,
            now=now,
        )
