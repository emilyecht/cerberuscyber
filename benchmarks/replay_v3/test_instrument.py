"""Checks of the measurement instrument; never patch evaluated implementation."""
from collections import Counter
from copy import deepcopy
import json
import socket

import pytest

from benchmarks.replay_v3 import run as v3


def test_frozen_coverage_labels_and_history():
    oracle, cases, preservation = v3.frozen_inputs()
    assert Counter(c['class'] for c in cases) == dict(A=40, B=40, C=40, D=40, E=60, F=40, G=40, H=3240)
    assert preservation['protected_diff_stat'] == ''
    assert preservation['guardian_source_changes'] == 0
    assert len({c['id'] for c in cases}) == 3540
    assert sum(s['expected'] == 'doc-ambiguous' for c in cases for s in c['steps']) == 8
    sweep = [c for c in cases if c['class'] == 'H']
    assert len({c['source_id'] for c in sweep}) == 135
    assert Counter(c['field'] for c in sweep) == {p: 135 for p in oracle['fields']}


def test_wilson_and_rule_of_three_known_values():
    m = v3.interval(dict(numerator=0, denominator=100, rate=0))
    assert m['wilson_95'][0] == pytest.approx(0)
    assert m['wilson_95'][1] == pytest.approx(.03699349820698568)
    assert m['rule_of_three_upper_95'] == .03
    assert v3.interval(dict(numerator=0, denominator=0, rate=None))['wilson_95'] is None


def test_network_is_blocked():
    with v3.offline(), pytest.raises(AssertionError, match='network access is forbidden'):
        socket.socket()


@pytest.fixture(scope='module')
def episodes():
    oracle, cases, _ = v3.frozen_inputs()
    return oracle, cases


def exercise(case):
    instrument = v3.Instrument(v3.api.PolicyBundle.load(v3.ROOT/'policies/policies.json'))
    world = v3.new_world(instrument, case)
    try:
        return [v3.observe(world, s)[0] for s in case['steps']]
    finally:
        world.close()


def test_partial_claim_is_not_erased_before_retry(episodes):
    case = next(c for c in episodes[1] if c['variant'] == 'partial_audit_then_retry')
    rows = exercise(case)
    assert rows[0]['systems']['cerberus']['error'] == 'controlled-audit-failure'
    assert rows[0]['systems']['cerberus']['replay_claims_added'] == 1
    assert rows[1]['systems']['cerberus']['decision'] == 'deny'
    assert 'replay' in rows[1]['systems']['cerberus']['reason']
    assert all(r['systems']['cerberus']['simulator_state']['total'] == 0 for r in rows)


def test_named_ordering_and_overlapping_duplicates(episodes):
    for name in ['enforcement_wins_order', 'overlapping_duplicates']:
        rows = exercise(next(c for c in episodes[1] if c['variant'] == name))
        assert [r['systems']['cerberus']['decision'] for r in rows] == ['approve', 'deny']
        events = rows[0]['systems']['cerberus']['controller_events']
        assert events.index('commit_lock_held') < events.index('receipt_commit') < events.index('worker_completed')
        assert sum(r['systems']['cerberus']['simulator_state']['total'] for r in rows) == 1


def test_scoring_excludes_ambiguity_and_does_not_hide_unsafe_allow(episodes):
    row = exercise(next(c for c in episodes[1] if c['class'] == 'G' and c['variant'] == 'exact_independence'))[0]
    unsafe = deepcopy(row)
    unsafe['expected'] = 'deny'
    unsafe['systems']['cerberus']['violations'] = ['UNSAFE_KERNEL_PERMISSION']
    ambiguous = deepcopy(row)
    ambiguous['expected'] = 'doc-ambiguous'
    result = v3.summarize([unsafe, ambiguous], 'cerberus')
    assert result['accuracy']['numerator'] == 0
    assert result['false_allow']['numerator'] == 1
    assert result['false_allow']['denominator'] == 1
    assert result['doc_ambiguous_excluded'] == 1
    assert result['cases_with_violations'] == 1


def test_baselines_are_original_functions_and_no_shadow_policy(episodes):
    case = next(c for c in episodes[1] if c['class'] == 'A')
    row = exercise(case)[0]
    request = case['steps'][0]
    source = {'request': request['request'], 'expected': request['expected'], 'evaluation_at': request['evaluation_at']}
    for name in ('allow_if_recommended', 'confidence_threshold'):
        assert row['systems'][name] == v3.v1.baseline(source, name, .9)


def test_h_uses_trusted_original_grant_before_mutated_trust(episodes):
    case = next(c for c in episodes[1] if c['class'] == 'H' and
        len({a['independence_domain'] for a in c['original_trust']['evidence_authorities']}) == 1)
    rows = exercise(case)
    assert rows[0]['systems']['cerberus']['setup_control_passed']
    assert rows[0]['systems']['cerberus']['measurement_valid']
    assert rows[0]['systems']['cerberus']['decision'] == 'deny'


def test_committed_results_retain_original_labels_and_every_failure():
    path = v3.ROOT/'results/replay_v3/results.json'
    if not path.exists():
        pytest.skip('measurement not yet written')
    r = json.loads(path.read_text())
    oracle = json.loads((v3.HERE/'oracle.json').read_text())
    expected = {f"{c['id']}.s{i}": s['expected'] for c in oracle['cases']
        for i, s in enumerate(c.get('steps', [c]), 1)}
    assert {row['id']: row['expected'] for row in r['observations']} == expected
    failures = [row for row in r['observations'] if row['expected'] != 'doc-ambiguous' and (
        row['expected'] != row['systems']['cerberus']['decision'] or row['systems']['cerberus']['violations']
        or not row['systems']['cerberus']['measurement_valid'])]
    assert {row['id'] for row in failures} == {f['id'] for f in r['failures']}
    assert all(f['failing_layer'] and f['basis']['document'] for f in r['failures'])
    assert len(r['oracle_defects']) == 7
    assert all(d['request_sha256'] == d['original_setup_sha256'] and d['frozen_expected'] == 'deny'
        and d['retained_in_frozen_scores'] for d in r['oracle_defects'])
    assert r['failure_counts']['failures_without_proven_oracle_defect'] == 2
    assert all(o['systems']['cerberus']['decision'] == p['outcome'] for o, p in
        zip(r['observations'], r['latency']['per_request']))
    assert r['latency']['warmup_per_attempt'] == 5
    assert r['latency']['repetitions_per_attempt'] == 20
