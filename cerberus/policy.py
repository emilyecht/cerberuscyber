"""Strict, canonical policy-bundle loading for the Guardian trust boundary."""

from __future__ import annotations

import hashlib
import json
import math
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

POLICY_BUNDLE_SCHEMA_VERSION = "1.0.0"

_SEMVER_RE = re.compile(
    r"^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)"
    r"(?:-([0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?"
    r"(?:\+([0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?$"
)
_TOP_LEVEL_REQUIRED = {
    "schema_version",
    "version",
    "decision_ttl_seconds",
    "min_independent_sources",
    "escalation_signals",
    "scope_order",
    "policies",
    "forbidden_actions",
}
_POLICY_REQUIRED = {
    "id",
    "name",
    "match",
    "decision",
    "allowed_action",
    "max_scope",
    "reversible_required",
    "human_approval_required",
    "required_approval_count",
}
_POLICY_OPTIONAL = {"decision_on_approval"}
_MATCH_REQUIRED = {
    "threat",
    "min_confidence",
    "required_signals",
    "min_independent_sources",
}


class PolicyBundleError(ValueError):
    """Raised when a Guardian policy bundle is malformed or ambiguous."""


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise PolicyBundleError(f"duplicate JSON object key: {key}")
        result[key] = value
    return result


def _canonical_json(data: dict[str, Any]) -> str:
    try:
        return json.dumps(
            data,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            allow_nan=False,
        )
    except (TypeError, ValueError) as exc:
        raise PolicyBundleError("policy bundle must contain canonical JSON values") from exc


def _require_exact_keys(
    value: dict[str, Any],
    *,
    required: set[str],
    optional: set[str] | None = None,
    context: str,
) -> None:
    allowed = required | (optional or set())
    missing = sorted(required.difference(value))
    unknown = sorted(set(value).difference(allowed))
    if missing:
        raise PolicyBundleError(f"{context} missing fields: {', '.join(missing)}")
    if unknown:
        raise PolicyBundleError(f"{context} has unknown fields: {', '.join(unknown)}")


def _require_string(value: Any, *, context: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise PolicyBundleError(f"{context} must be a non-empty string")
    if value != value.strip():
        raise PolicyBundleError(f"{context} must not contain surrounding whitespace")
    return value


def _require_int(
    value: Any,
    *,
    context: str,
    minimum: int,
    maximum: int,
) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise PolicyBundleError(f"{context} must be an integer")
    if not minimum <= value <= maximum:
        raise PolicyBundleError(f"{context} must be between {minimum} and {maximum}")
    return value


def _require_number(
    value: Any,
    *,
    context: str,
    minimum: float,
    maximum: float,
) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise PolicyBundleError(f"{context} must be a number")
    number = float(value)
    if not math.isfinite(number) or not minimum <= number <= maximum:
        raise PolicyBundleError(
            f"{context} must be finite and between {minimum} and {maximum}"
        )
    return number


def _require_string_list(
    value: Any,
    *,
    context: str,
    minimum_items: int = 0,
) -> list[str]:
    if not isinstance(value, list):
        raise PolicyBundleError(f"{context} must be an array")
    if len(value) < minimum_items:
        raise PolicyBundleError(
            f"{context} must contain at least {minimum_items} item(s)"
        )
    items = [
        _require_string(item, context=f"{context}[{index}]")
        for index, item in enumerate(value)
    ]
    if len(set(items)) != len(items):
        raise PolicyBundleError(f"{context} must not contain duplicates")
    return items


def _validate_policy(
    policy: Any,
    *,
    index: int,
    scope_order: list[str],
    forbidden_actions: set[str],
) -> tuple[str, str]:
    context = f"policies[{index}]"
    if not isinstance(policy, dict):
        raise PolicyBundleError(f"{context} must be an object")
    _require_exact_keys(
        policy,
        required=_POLICY_REQUIRED,
        optional=_POLICY_OPTIONAL,
        context=context,
    )

    policy_id = _require_string(policy["id"], context=f"{context}.id")
    _require_string(policy["name"], context=f"{context}.name")

    match = policy["match"]
    if not isinstance(match, dict):
        raise PolicyBundleError(f"{context}.match must be an object")
    _require_exact_keys(match, required=_MATCH_REQUIRED, context=f"{context}.match")
    threat = _require_string(match["threat"], context=f"{context}.match.threat")
    _require_number(
        match["min_confidence"],
        context=f"{context}.match.min_confidence",
        minimum=0.0,
        maximum=1.0,
    )
    _require_string_list(
        match["required_signals"],
        context=f"{context}.match.required_signals",
        minimum_items=1,
    )
    _require_int(
        match["min_independent_sources"],
        context=f"{context}.match.min_independent_sources",
        minimum=1,
        maximum=64,
    )

    decision = _require_string(policy["decision"], context=f"{context}.decision")
    if decision not in {"approve", "escalate", "deny"}:
        raise PolicyBundleError(
            f"{context}.decision must be approve, escalate, or deny"
        )
    allowed_action = _require_string(
        policy["allowed_action"], context=f"{context}.allowed_action"
    )
    max_scope = _require_string(policy["max_scope"], context=f"{context}.max_scope")
    if max_scope not in scope_order:
        raise PolicyBundleError(
            f"{context}.max_scope is not present in the bundle scope_order"
        )
    if allowed_action in forbidden_actions:
        raise PolicyBundleError(f"{context}.allowed_action is globally forbidden")

    reversible_required = policy["reversible_required"]
    human_approval_required = policy["human_approval_required"]
    if not isinstance(reversible_required, bool):
        raise PolicyBundleError(f"{context}.reversible_required must be boolean")
    if not isinstance(human_approval_required, bool):
        raise PolicyBundleError(f"{context}.human_approval_required must be boolean")

    approval_count = _require_int(
        policy["required_approval_count"],
        context=f"{context}.required_approval_count",
        minimum=0,
        maximum=8,
    )
    if human_approval_required and approval_count == 0:
        raise PolicyBundleError(
            f"{context} requires human approval but approval count is zero"
        )
    if not human_approval_required and approval_count != 0:
        raise PolicyBundleError(
            f"{context} has approval count without a human approval requirement"
        )

    decision_on_approval = policy.get("decision_on_approval")
    if decision == "deny":
        if allowed_action != "none" or max_scope != "none":
            raise PolicyBundleError(
                f"{context} deny policy must authorize action and scope 'none'"
            )
        if human_approval_required or approval_count:
            raise PolicyBundleError(f"{context} deny policy cannot be approval gated")
        if decision_on_approval is not None:
            raise PolicyBundleError(
                f"{context} deny policy cannot define decision_on_approval"
            )
    elif decision == "approve":
        if allowed_action == "none":
            raise PolicyBundleError(
                f"{context} approve policy must name an allowed action"
            )
        if decision_on_approval is not None:
            raise PolicyBundleError(
                f"{context} approve policy cannot define decision_on_approval"
            )
    else:
        if allowed_action == "none":
            raise PolicyBundleError(
                f"{context} escalation policy must name the bounded action under review"
            )
        if human_approval_required:
            if decision_on_approval not in {"approve", "deny"}:
                raise PolicyBundleError(
                    f"{context}.decision_on_approval must be approve or deny"
                )
        elif decision_on_approval is not None:
            raise PolicyBundleError(
                f"{context} cannot define decision_on_approval without approval gating"
            )

    return policy_id, threat


def validate_policy_bundle(data: dict[str, Any]) -> None:
    """Validate the closed-world v1 policy contract before Guardian starts."""

    if not isinstance(data, dict):
        raise PolicyBundleError("policy bundle must be a JSON object")
    _require_exact_keys(data, required=_TOP_LEVEL_REQUIRED, context="policy bundle")

    if data["schema_version"] != POLICY_BUNDLE_SCHEMA_VERSION:
        raise PolicyBundleError(
            "unsupported policy-bundle schema version: "
            f"{data['schema_version']!r}"
        )
    version = _require_string(data["version"], context="policy bundle.version")
    if _SEMVER_RE.fullmatch(version) is None:
        raise PolicyBundleError("policy bundle.version must be valid SemVer")

    _require_int(
        data["decision_ttl_seconds"],
        context="policy bundle.decision_ttl_seconds",
        minimum=1,
        maximum=3600,
    )
    _require_int(
        data["min_independent_sources"],
        context="policy bundle.min_independent_sources",
        minimum=1,
        maximum=64,
    )
    escalation_signals = _require_string_list(
        data["escalation_signals"], context="policy bundle.escalation_signals"
    )
    scope_order = _require_string_list(
        data["scope_order"], context="policy bundle.scope_order", minimum_items=2
    )
    if scope_order[0] != "none":
        raise PolicyBundleError("policy bundle.scope_order must begin with 'none'")

    forbidden_actions = set(
        _require_string_list(
            data["forbidden_actions"], context="policy bundle.forbidden_actions"
        )
    )
    if "none" in forbidden_actions:
        raise PolicyBundleError("policy bundle cannot forbid the sentinel action 'none'")

    policies = data["policies"]
    if not isinstance(policies, list) or not policies:
        raise PolicyBundleError("policy bundle.policies must be a non-empty array")

    policy_ids: set[str] = set()
    threats: set[str] = set()
    for index, policy in enumerate(policies):
        policy_id, threat = _validate_policy(
            policy,
            index=index,
            scope_order=scope_order,
            forbidden_actions=forbidden_actions,
        )
        if policy_id in policy_ids:
            raise PolicyBundleError(f"duplicate policy id: {policy_id}")
        if threat in threats:
            raise PolicyBundleError(
                f"multiple policies match threat {threat!r}; v1 forbids "
                "order-dependent first-match evaluation"
            )
        policy_ids.add(policy_id)
        threats.add(threat)

    policy_signals = {
        signal
        for policy in policies
        for signal in policy["match"]["required_signals"]
    }
    overlap = sorted(set(escalation_signals).intersection(policy_signals))
    if overlap:
        raise PolicyBundleError(
            "escalation signals cannot also satisfy policy evidence requirements: "
            + ", ".join(overlap)
        )


@dataclass(frozen=True)
class PolicyBundle:
    """Validated, immutable-by-serialization Guardian policy bundle."""

    _canonical: str
    source: str
    digest: str

    @classmethod
    def from_dict(
        cls,
        data: dict[str, Any],
        *,
        source: str = "<memory>",
    ) -> "PolicyBundle":
        if not isinstance(data, dict):
            raise PolicyBundleError("policy bundle must be a dictionary")
        canonical = _canonical_json(data)
        normalized = json.loads(canonical)
        validate_policy_bundle(normalized)
        digest = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
        return cls(_canonical=canonical, source=source, digest=digest)

    @classmethod
    def load(cls, path: str | Path) -> "PolicyBundle":
        policy_path = Path(path)
        try:
            raw = policy_path.read_text(encoding="utf-8")
        except OSError as exc:
            raise PolicyBundleError(
                f"unable to read policy bundle {policy_path}: {exc}"
            ) from exc
        try:
            data = json.loads(raw, object_pairs_hook=_reject_duplicate_keys)
        except json.JSONDecodeError as exc:
            raise PolicyBundleError(
                f"invalid policy JSON at line {exc.lineno}, column {exc.colno}"
            ) from exc
        if not isinstance(data, dict):
            raise PolicyBundleError("policy bundle must be a JSON object")
        return cls.from_dict(data, source=str(policy_path))

    @property
    def version(self) -> str:
        return str(self.to_dict()["version"])

    @property
    def schema_version(self) -> str:
        return str(self.to_dict()["schema_version"])

    @property
    def canonical_json(self) -> str:
        return self._canonical

    def to_dict(self) -> dict[str, Any]:
        return json.loads(self._canonical)


__all__ = [
    "POLICY_BUNDLE_SCHEMA_VERSION",
    "PolicyBundle",
    "PolicyBundleError",
    "validate_policy_bundle",
]
