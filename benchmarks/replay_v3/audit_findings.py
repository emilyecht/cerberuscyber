"""Flag documentary label defects by input equality, without relabelling/scoring.

This diagnostic is independent of the pipeline's observed decision. A mutation
can restore a previously modified v2 field to the original approved value.
The blanket binding-denial rule then has a false premise. Preserve its original
label and every score; show the exact documentary refutation separately.
"""
from benchmarks.replay_v3.freeze_oracle import canonical, sha


def annotate_oracle_defects(result, cases):
    defects = []
    for case in cases:
        if case['class'] != 'H':
            continue
        for step in case['steps']:
            if step['rule'] != 'binding' or step['expected'] != 'deny' or step['request'] != case['setup']:
                continue
            request_hash = sha(canonical(step['request']))
            setup_hash = sha(canonical(case['setup']))
            assert request_hash == setup_hash
            defects.append({
                'id': step['id'], 'frozen_expected': 'deny', 'retained_in_frozen_scores': True,
                'document': 'docs/ASSURANCE_BOUNDARY.md',
                'section': 'Strict gateway execution context and live token status',
                'frozen_rule': 'binding', 'source_case': case['source_id'], 'field': case['field'],
                'request_sha256': request_hash, 'original_setup_sha256': setup_hash,
                'basis_refutation': 'The H transform changes the v2 attack input but restores the complete original approved envelope. The documentary denial requires a digest mismatch against that grant; identical canonical inputs do not satisfy that premise.',
                'production_failure_established': False,
                'remediation_in_this_evaluation': 'None: oracle, expected labels, failure records and frozen-gate scores remain unchanged.',
            })
    lookup = {d['id']: d for d in defects}
    for failure in result['failures']:
        if failure['id'] in lookup:
            failure['documentary_basis_defect'] = True
            failure['failing_layer'] = 'oracle premise (Kernel accepted the original approved envelope); no CERBERUS layer shown failing'
            failure['basis_refutation'] = lookup[failure['id']]['basis_refutation']
    result['oracle_defects'] = defects
    result['failure_counts'] = {
        'frozen_oracle_discrepancies': len(result['failures']),
        'proven_documentary_basis_defects_retained': len(defects),
        'failures_without_proven_oracle_defect': sum(f['id'] not in lookup for f in result['failures']),
    }
    return result
