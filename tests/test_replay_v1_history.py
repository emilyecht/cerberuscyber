# Copyright 2026 Emily Echterhoff
# SPDX-License-Identifier: Apache-2.0

"""Historical tests stay attached to the API and source they originally measured."""

from benchmarks.replay_v2.verify_history import verify


def test_frozen_v1_instrument_still_reproduces_its_original_failure():
    result = verify()
    assert result["historical_status"] == "FAIL"
    assert result["instrument_checks_passed"] == 14
    assert result["safety_gates_failed"] == 1
