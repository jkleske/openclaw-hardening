# Security Policy

This repository contains **documentation**, not executable software. “Vulnerabilities” here means incorrect or dangerous security advice that could weaken an OpenClaw agent's security posture.

## Reporting an Issue

If you find advice in this runbook that is wrong, outdated, or could lead to a less secure configuration:

1. **For most issues: open a public issue.** Since this is documentation, public disclosure is usually fine. Use the label `correction` if available.
2. **For sensitive cases:** if you believe the flawed advice is actively being relied upon and public disclosure could cause harm before a fix is ready, use [GitHub's private vulnerability reporting](https://github.com/jkleske/openclaw-hardening/security/advisories/new) instead.
3. **Describe the problem clearly:** which section, what the current advice says, and why it is incorrect or dangerous.
4. **Suggest a fix** if you have one.

## Scope

In scope:
- Recommended configurations that weaken security instead of hardening it
- Missing deny-list entries that leave an attack vector open
- Incorrect CLI commands or JSON snippets
- Outdated information due to OpenClaw version changes

Out of scope:
- Vulnerabilities in OpenClaw itself (report those to [OpenClaw](https://openclaw.ai) directly)
- General feature requests (use regular issues)
