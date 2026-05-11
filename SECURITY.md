# Security Policy

AgentBox is a security tool. We take vulnerabilities seriously and respond quickly.

## Supported versions

| Version | Supported |
|---------|-----------|
| 1.x     | ✅ Yes    |
| < 1.0   | ❌ No     |

## Reporting a vulnerability

**Do not open a public GitHub issue for security vulnerabilities.**

Report vulnerabilities privately:

1. Go to the [Security tab](../../security) on GitHub
2. Click "Report a vulnerability"
3. Fill in the details

Or email: `msiyad254@gmail.com` with subject: `[AgentBox] Security Vulnerability`

### What to include

- Description of the vulnerability
- Steps to reproduce
- Affected versions
- Potential impact
- Suggested fix (optional but appreciated)

### What happens next

- **24 hours**: We acknowledge receipt
- **72 hours**: We confirm the vulnerability and assess severity
- **7 days**: We provide a fix timeline
- **30 days**: We aim to have a patch released

We follow coordinated disclosure — we'll work with you on the timing of public disclosure.

## Threat model

AgentBox is designed to defend against:

- **Malicious agent skills** — code that tries to escape its declared permissions
- **Credential theft** — agents attempting to read secrets beyond their scope
- **Prompt injection** — LLM output attempting to modify policy or escalate privileges
- **Resource abuse** — runaway agents consuming unbounded time, memory, or API calls
- **Audit tampering** — modification of the audit log after the fact

AgentBox does NOT defend against:

- **Host kernel exploits** (use gVisor/Firecracker backends for this protection)
- **Physical access to the machine**
- **Compromised AgentBox binary** — verify checksums on downloaded binaries
- **Weak vault passwords** — use strong passwords or system keychain integration

## Security architecture

### Deny-first policy engine
Every agent starts with zero permissions. The policy engine evaluates deny lists before allow lists. An explicit deny cannot be overridden.

### AES-256-GCM credential vault
Credentials are encrypted with AES-256-GCM. Each encryption uses a unique random nonce. The master key never touches disk — derived from password at runtime.

### Hash-chained audit log
The audit log uses SHA-256 hash chaining. Every entry includes the hash of the previous entry. Tampering with any entry invalidates all subsequent entries.

### Sandbox isolation
- Docker: namespace isolation, dropped capabilities, no-new-privileges
- gVisor (runsc): user-space kernel intercepts all syscalls — kernel exploits are structurally blocked
- Firecracker: dedicated MicroVM kernel per agent — cross-agent exploitation is structurally impossible

## Known limitations

- **WSL2**: Network namespace isolation is not available on WSL2 due to Microsoft's kernel restrictions. Network isolation is fully enforced on production Linux.
- **SHA-256 key derivation**: The vault uses SHA-256 for key derivation. Production deployments should use Argon2 or bcrypt for stronger password-based key derivation. A future release will address this.
- **Docker socket**: Requires access to the Docker socket, which is privileged. Run AgentBox with the minimum required permissions.

## Acknowledgements

We thank the security researchers who have responsibly disclosed vulnerabilities. Contributors will be credited in release notes unless they prefer anonymity.
