"""Fixed, fail-closed evidence lifetime for the assurance prototype."""

from datetime import datetime, timedelta

from .models import ActionEnvelope, parse_time

MAX_EVIDENCE_AGE_SECONDS = 60
MAX_FUTURE_SKEW_SECONDS = 5


class FreshnessError(ValueError):
    """An observation cannot support authority at the supplied clock."""


def evidence_deadline(envelope: ActionEnvelope, now: datetime) -> datetime:
    """Return the earliest exclusive deadline; never refresh nested evidence.

    Age 60 seconds is expired, consistently with the token's exclusive expiry.
    A timestamp up to five seconds ahead is tolerated. The clock is trusted input.
    """
    if now.tzinfo is None or now.utcoffset() is None:
        raise FreshnessError("the authorization clock must be timezone-aware")
    future_limit = now + timedelta(seconds=MAX_FUTURE_SKEW_SECONDS)
    if parse_time(envelope.created_at) > future_limit:
        raise FreshnessError("action envelope timestamp exceeds forward-skew allowance")
    deadlines = [parse_time(envelope.expires_at)]
    for item in envelope.evidence:
        observed = parse_time(item.observed_at)
        if observed > future_limit:
            raise FreshnessError("evidence timestamp exceeds forward-skew allowance")
        deadline = observed + timedelta(seconds=MAX_EVIDENCE_AGE_SECONDS)
        if deadline <= now:
            raise FreshnessError("evidence observation expired")
        deadlines.append(deadline)
    deadline = min(deadlines)
    if deadline <= now:
        raise FreshnessError("action envelope expired")
    return deadline
