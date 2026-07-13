# Contributing to CERBERUS Cyber

Thank you for helping build a safer defensive architecture.

## Contribution Principles

Contributions should preserve the project's central separation of responsibility:

- the intelligence layer may observe, infer, and recommend
- the guardian layer authorizes or rejects actions through explicit policy
- the enforcement layer executes only approved, bounded, auditable actions

## Welcome Contributions

- architecture documentation
- defensive simulations
- policy examples and tests
- telemetry normalization
- detection logic
- safety invariants
- audit and explanation tooling
- rollback and recovery validation
- privacy and governance improvements

## Not Accepted

- malware or destructive payloads
- exploit development targeting real systems
- credential theft or phishing kits
- unauthorized scanning
- automated retaliation
- irreversible autonomous remediation

## Pull Requests

Keep changes small and explain:

1. the problem being addressed
2. the layer affected
3. the authority required
4. failure modes and rollback behavior
5. tests or evidence supporting the change

By contributing, you agree that your contribution is licensed under Apache License 2.0.
