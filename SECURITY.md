# Security Policy

This repository contains **documentation**, not executable software. “Vulnerabilities” here means incorrect or dangerous security advice that could weaken an OpenClaw agent's security posture.

## Reporting an Issue

If you find advice in this runbook that is wrong, outdated, or could lead to a less secure configuration:

1. **Open a public issue.** Since this is documentation, there is no exploit risk from public disclosure. Use the label `correction` if available.
2. **Describe the problem clearly:** which section, what the current advice says, and why it is incorrect or dangerous.
3. **Suggest a fix** if you have one.

## Scope

In scope:
- Recommended configurations that weaken security instead of hardening it
- Missing deny-list entries that leave an attack vector open
- Incorrect CLI commands or JSON snippets
- Outdated information due to OpenClaw version changes

Out of scope:
- Vulnerabilities in OpenClaw itself (report those to [OpenClaw](https://openclaw.ai) directly)
- General feature requests (use regular issues)
