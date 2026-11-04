# Copyright 2026 Emily Echterhoff
# SPDX-License-Identifier: Apache-2.0

"""Trusted-upstream preconditions for the original policy regression tests.

These tests exercise policy/action/schema behavior, not authenticity. The new
assurance security tests use the real Guardian and freeze trust before mutations.
"""

from cerberus import Guardian, EnforcementGateway, TokenAuthorityRegistry
from simulator.assurance_fixtures import fixture_assurance


class FixtureGuardian(Guardian):
    def evaluate(self, envelope, *, now=None):
        self.assurance_verifier, bundle = fixture_assurance(envelope)
        return super().evaluate(envelope, now=now, assurance=bundle)


def registered_gateway(signer, token, *, now=None, **kwargs):
    """Trusted test-controller provisioning, separate from request enforcement."""
    registry = TokenAuthorityRegistry()
    registry.register(token, signer, now=now)
    return EnforcementGateway(signer, authority_registry=registry, **kwargs)
