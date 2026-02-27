# Contributing

Thanks for your interest in improving this runbook. Contributions are welcome.

## How to contribute

- **Found a mistake?** Open an issue describing what's wrong and where.
- **Have a new gotcha or learning?** Open an issue or PR with a description of the problem, what you tried, and what the fix was.
- **Want to add an example config?** PRs for new `examples/` configs are welcome. Please follow the existing format and include comments explaining the security rationale.

## Guidelines

- Keep it practical. This runbook exists because the official docs don't cover every edge case. Your contribution should save someone real debugging time.
- Generalize personal details. No real API keys, bot tokens, phone numbers, or usernames. Use placeholders like `YOUR_AGENT_ID`, `YOUR_BOT_TOKEN`, `+1234567890`.
- Test your commands. If you're adding a CLI snippet, verify it works on a current OpenClaw version. Note the version if behavior is version-specific.
- One PR per topic. Don't bundle unrelated changes.

## What we're looking for

- New gotchas discovered through hands-on hardening
- Corrections to existing advice (OpenClaw evolves, things change)
- Example configs for agent types not yet covered
- Verification tests for new attack vectors
- Links to relevant OpenClaw docs or changelog entries

## What doesn't belong here

- Feature requests for OpenClaw itself (use their issue tracker)
- Theoretical vulnerabilities without practical demonstration
- Platform-specific deployment guides (Docker, Kubernetes, etc.) -- those deserve their own repos
