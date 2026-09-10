"""Trusted-upstream preconditions for the original policy regression tests.

These tests exercise policy/action/schema behavior, not authenticity. The new
assurance security tests use the real Guardian and freeze trust before mutations.
"""

from cerberus import Guardian
from simulator.assurance_fixtures import fixture_assurance


class FixtureGuardian(Guardian):
    def evaluate(self, envelope, *, now=None):
        self.assurance_verifier, bundle = fixture_assurance(envelope)
        return super().evaluate(envelope, now=now, assurance=bundle)
