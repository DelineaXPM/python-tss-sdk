# Security Policy

## Supported Versions

Security fixes are released against the latest published version of `python-tss-sdk` on PyPI. We do not backport fixes to older minor/major versions; please upgrade to the latest release to receive security patches.

## Reporting a Vulnerability

If you believe you have found a security vulnerability in this SDK, please report it responsibly through Delinea's coordinated disclosure program rather than opening a public GitHub issue:

- **Trust Portal (preferred):** <https://trust.delinea.com/>
- **Email:** <security@delinea.com>

Please include:

- A description of the vulnerability and its potential impact.
- Steps to reproduce, including a minimal code sample against this SDK if applicable.
- The SDK version (`delinea.__version__`) and Python version in use.

Do not include real credentials, tokens, or secret values from a live Secret Server/Platform tenant in a report.

## What to Expect

Delinea's security team acknowledges and triages reports submitted through the channels above; response times and disclosure timelines are governed by the program terms published at <https://trust.delinea.com/>. Please do not disclose a suspected vulnerability publicly until it has been addressed.

## Scope

This policy covers the SDK code in this repository (`delinea/secrets/server.py` and related packaging). Vulnerabilities in Secret Server, Delinea Platform, or other Delinea products should be reported through the same channels above, which will route them to the appropriate team.
