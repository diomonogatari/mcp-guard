# Security policy

mcp-guard is a security tool, so we take its own correctness seriously.

## Reporting a vulnerability

If you find a vulnerability in mcp-guard itself — for example a way to make the analyzer miss a
poisoned description it should catch, or to break a consumer's build — please report it privately via
[GitHub Security Advisories](https://github.com/diomonogatari/mcp-guard/security/advisories/new)
rather than a public issue. We aim to acknowledge reports promptly.

## Scope

mcp-guard performs **build-time static analysis** of MCP tool descriptions. It is one layer of
defense and does not replace runtime protections — see the [threat model](docs/THREAT-MODEL.md) for
what is in and out of scope.
