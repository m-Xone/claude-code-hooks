"""Check registry. Order matters only for output ordering: security first."""

from . import (
    cost_ledger,
    custom_rules,
    destructive_commands,
    egress_guard,
    injection_tripwire,
    loop_detector,
    prompt_gate,
    secret_leaks,
    sensitive_paths,
    slop_detector,
    subagent_governor,
    tamper_guard,
    verification_gate,
)

ALL = [
    tamper_guard,          # 7
    prompt_gate,           # 1
    sensitive_paths,       # 2
    destructive_commands,  # 3
    secret_leaks,          # 6
    injection_tripwire,    # 4
    egress_guard,          # 5
    custom_rules,          # 13: user-written rules, after the built-in security checks
    subagent_governor,     # 9
    loop_detector,         # 12
    cost_ledger,           # 8
    verification_gate,     # 11
    slop_detector,         # 10
]
