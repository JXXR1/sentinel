# Security Policy

## Supported Versions

| Version | Supported |
|---------|-----------|
| 1.3.x   | ✅ Active  |
| < 1.3   | ❌ EOL     |

## Reporting a Vulnerability

If you find a bypass, false negative, or detection gap in SENTINEL:

1. **Do not open a public issue.**
2. Open a [GitHub Security Advisory](https://github.com/JXXR1/sentinel-v2/security/advisories/new) (private disclosure).
3. Include:
   - Which script and check is affected
   - A minimal reproduction (e.g. a port binding or process that should alert but doesn't)
   - Suggested fix if you have one

Expect a response within 48 hours.

## Scope

In scope:
- Detection bypasses in any of the 5 scripts
- False negatives on port exposure, process monitoring, or file access
- Logic errors in the delta-detection state machine
- Escalation JSON not being written when it should be

Out of scope:
- False positives (open a regular issue)
- Feature requests (open a regular issue)

## Philosophy

SENTINEL exists to catch real threats on real servers. Any gap that lets a genuine exposure go undetected is treated as a critical vulnerability.
