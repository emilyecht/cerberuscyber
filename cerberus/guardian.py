"""Deterministic Guardian policy engine."""

from __future__ import annotations

from dataclasses import replace
from datetime import datetime
from typing import Any

from .audit import AuditLedger
from .models import ActionEnvelope, GuardianDecision
from .token import DecisionTokenSigner


class Guardian:
    """Small, deterministic authorization core.

    The Guardian does not call models, retrieve context, or execute actions. It validates
    a typed request, evaluates explicit policy, optionally mints a short-lived decision
    token, and records the decision.
    """

    def __init__(
        self,
        policy_set: dict[str, Any],
        *,
        signer: DecisionTokenSigner | None = None,
        ledger: AuditLedger | None = None,
    ) -> None:
        self.policy_set = policy_set
        self.signer = signer
        self.ledger = ledger or AuditLedger()
        self.policy_version = str(policy_set.get("version", "unknown"))
        self.scope_order = list(
            policy_set.get(
                "scope_order",
                [
                    "none",
                    "single_identity",
                    "single_endpoint",
                    "single_workload",
                    "single_segment",
                    "enterprise",
                ],
            )
        )

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
        result = GuardianDecision(
            incident_id=envelope.incident_id,
            envelope_id=envelope.envelope_id,
            guardian_decision=decision,
            reason=reason,
            policy=policy_id,
            policy_version=self.policy_version,
            proposed_action=envelope.proposed_action,
            authorized_action=authorized_action,
            target=envelope.target,
            scope=scope,
            reversible=reversible,
            human_approval_required=human_approval_required,
            evidence=tuple(sorted(envelope.evidence_signals)),
            independent_source_count=len(envelope.independent_sources),
        )
        token: str | None = None
        if decision == "approve" and self.signer is not None:
            token = self.signer.issue(
                result,
                envelope,
                ttl_seconds=int(self.policy_set.get("decision_ttl_seconds", 120)),
                now=now,
            )
        record = self.ledger.append(
            "guardian.decision",
            {
                "incident_id": result.incident_id,
                "envelope_id": result.envelope_id,
                "decision": result.guardian_decision,
                "policy": result.policy,
                "policy_version": result.policy_version,
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

        forbidden = set(self.policy_set.get("forbidden_actions", []))
        if envelope.proposed_action in forbidden:
            return self._finalize(
                envelope,
                decision="deny",
                reason="proposed action is globally forbidden",
                policy_id="GLOBAL-INVARIANT",
                now=now,
            )

        escalation_signals = set(self.policy_set.get("escalation_signals", []))
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

        for policy in self.policy_set.get("policies", []):
            match = policy.get("match", {})
            if envelope.threat != match.get("threat"):
                continue
            if envelope.confidence < float(match.get("min_confidence", 1.0)):
                continue
            required_signals = set(match.get("required_signals", []))
            if not required_signals.issubset(envelope.evidence_signals):
                continue

            required_sources = int(
                match.get(
                    "min_independent_sources",
                    self.policy_set.get("min_independent_sources", 1),
                )
            )
            if len(envelope.independent_sources) < required_sources:
                return self._finalize(
                    envelope,
                    decision="escalate",
                    reason="insufficient independent evidence sources",
                    policy_id=policy.get("id"),
                    human_approval_required=True,
                    now=now,
                )

            policy_decision = str(policy.get("decision", "deny"))
            allowed_action = str(policy.get("allowed_action", "none"))
            max_scope = str(policy.get("max_scope", "none"))
            reversible_required = bool(policy.get("reversible_required", False))
            approval_required = bool(policy.get("human_approval_required", False))
            approval_count = int(policy.get("required_approval_count", 1 if approval_required else 0))

            if policy_decision == "approve" and envelope.proposed_action != allowed_action:
                return self._finalize(
                    envelope,
                    decision="deny",
                    reason="proposed action does not match the policy allowlist",
                    policy_id=policy.get("id"),
                    now=now,
                )

            if not self._scope_within_limit(envelope.requested_scope, max_scope):
                return self._finalize(
                    envelope,
                    decision="deny",
                    reason="requested scope exceeds policy maximum",
                    policy_id=policy.get("id"),
                    now=now,
                )

            if reversible_required and not envelope.reversible:
                return self._finalize(
                    envelope,
                    decision="deny",
                    reason="policy requires a reversible action",
                    policy_id=policy.get("id"),
                    now=now,
                )

            if approval_required and len(envelope.human_approvals) < approval_count:
                return self._finalize(
                    envelope,
                    decision="escalate",
                    reason="required human approval not present",
                    policy_id=policy.get("id"),
                    scope=max_scope,
                    reversible=envelope.reversible,
                    human_approval_required=True,
                    now=now,
                )

            if policy_decision == "escalate" and approval_required:
                policy_decision = str(policy.get("decision_on_approval", "approve"))

            return self._finalize(
                envelope,
                decision=policy_decision,
                reason="policy requirements satisfied",
                policy_id=policy.get("id"),
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
