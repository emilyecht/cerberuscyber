# CERBERUS Cyber Threat Model

## Purpose

CERBERUS Cyber protects users, identities, endpoints, cloud workloads, AI agents, and recovery systems by separating threat interpretation from action authority.

## Protected assets

- user and service identities
- endpoint and cloud workloads
- credentials, tokens, and API keys
- sensitive files and databases
- backups and recovery infrastructure
- security telemetry and audit logs
- AI-agent tools, connectors, and secrets

## Trust boundaries

1. **Telemetry boundary** — incoming events may be incomplete, spoofed, delayed, or poisoned.
2. **Sentinel boundary** — Layer 1 may be wrong, manipulated, or compromised.
3. **Guardian boundary** — Layer 2 must remain deterministic, testable, and independently auditable.
4. **Enforcement boundary** — Layer 3 receives only narrowly scoped, time-limited authority.
5. **Human boundary** — operators may make mistakes or act maliciously; sensitive actions require dual control where practical.

## Adversary assumptions

CERBERUS assumes an attacker may control one or more of the following:

- a user account or active session
- an endpoint process
- a cloud workload
- an AI prompt or retrieved document
- a plugin, connector, or MCP-style tool source
- a telemetry source
- a Layer 1 model response

CERBERUS does **not** assume that network location, valid credentials, or model confidence imply trust.

## Primary abuse cases

- credential theft and session hijacking
- ransomware and destructive file modification
- privilege escalation
- persistence and lateral movement
- data exfiltration
- cloud control-plane abuse
- prompt injection and excessive AI-agent agency
- policy bypass attempts
- compromised security automation

## Required security properties

- Layer 1 cannot directly invoke enforcement credentials.
- Every proposed action is evaluated by Layer 2.
- High-impact actions require corroborating evidence.
- Broad or irreversible actions require human approval.
- Automated actions must be scoped, logged, and preferably reversible.
- Missing or unhealthy telemetry reduces authority rather than increasing it.
- Policy changes are versioned, signed, and auditable.

## Failure handling

### If Layer 1 is compromised

Guardian rejects any proposal that violates policy, exceeds scope, lacks evidence, or requests a forbidden action.

### If telemetry is poisoned

CERBERUS requires independent evidence sources for high-confidence containment and marks sensor disagreement explicitly.

### If Guardian is unavailable

Enforcement fails closed for high-impact actions. Read-only monitoring may continue.

### If enforcement is compromised

Connectors use least privilege, short-lived credentials, action allowlists, and independent audit logging.

## Out of scope

- offensive exploitation
- retaliation or hack-back
- credential harvesting
- destructive payloads
- autonomous wiping or irreversible remediation
- unauthorized scanning of third-party systems
