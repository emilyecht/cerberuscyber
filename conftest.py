"""Frozen replay-v1 tests target their original implementation, not the new API.

They are executed unchanged by test_replay_v1_history.py, which preserves and
checks the original failing safety gate. Current enforcement is gated by v2.
"""

collect_ignore = ["tests/test_replay_v1.py"]
