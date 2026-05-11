<div align="center">

# 🛡️ AgentBox

**The open-source sandboxed runtime for AI agents**

*Run AI agents with confidence. Every agent gets its own permission scope, credential vault, audit trail, and kill switch.*

[![Build](https://github.com/siyad01/agentbox/actions/workflows/build.yml/badge.svg)](https://github.com/siyad01/agentbox/actions/workflows/build.yml)
[![License: Apache 2.0](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE)
[![Go Version](https://img.shields.io/badge/Go-1.26-00ADD8?logo=go)](go.mod)
[![Tests](https://img.shields.io/badge/Tests-27%20passing-22c55e)](internal/)
[![Platform](https://img.shields.io/badge/platform-Linux%20%7C%20macOS%20%7C%20Windows-0ea5e9)](#download)

</div>

---

## Why AgentBox exists

On January 27, 2026, **CVE-2026-25253** became the first CVE ever assigned to an agentic AI system. A critical WebSocket hijacking vulnerability in OpenClaw enabled one-click remote code execution against any exposed instance — including those bound only to localhost.

That same week, the **ClawHavoc campaign** infiltrated 341+ malicious skills into OpenClaw's marketplace. Every skill installed from ClawHub ran with the same permissions as OpenClaw itself — full disk access, OAuth tokens, API keys. No sandbox. No audit trail. No kill switch.

> *"Installing a skill from ClawHub grants it access to the same resources as OpenClaw itself. There is no sandbox isolation between skills by default."*
> — DEV Community security analysis, April 2026

**The numbers:**
- 138+ CVEs in OpenClaw in 2026 alone
- 135,000+ exposed instances across 82 countries
- 341 confirmed malicious skills (12% of the entire registry)
- 1.5 million agent API tokens exposed in plaintext
- Microsoft: *"It is not appropriate to run it on a standard personal or corporate machine."*

AgentBox is the structural fix. Not a patch — a runtime.

---

## What AgentBox does

Every agent you run gets:

| Protection | How |
|-----------|-----|
| **Zero-trust permissions** | Agents declare exactly what they need. Nothing else is accessible. |
| **Kernel-level isolation** | gVisor intercepts every syscall. Prompt injection cannot cross this boundary. |
| **Credential vault** | AES-256-GCM encryption. Agents never see raw secrets — only scoped tokens. |
| **Immutable audit log** | SHA-256 hash chain. Every action logged. Tamper-evident. |
| **Kill switch** | Terminate any agent in under 100ms. Auto-kill on limit breach. |
| **Resource limits** | Time, memory, request count — enforced at runtime, not at config. |

```
Before AgentBox                    After AgentBox
─────────────────                  ──────────────
Agent → full disk ❌               Agent → allowed paths only ✅
Agent → all network ❌             Agent → allowed hosts only ✅
Agent → raw secrets ❌             Agent → scoped tokens ✅
No audit trail ❌                  Every action logged ✅
No kill switch ❌                  Kill in <100ms ✅
Skills run as root ❌              Kernel-isolated sandbox ✅
```

---

## Quick start

```bash
# Install
go install github.com/siyad01/agentbox/cmd/agentbox@latest

# Validate a manifest before running
agentbox validate manifests/email-sorter.yaml

# Run an agent in a sandbox
agentbox run --manifest manifests/email-sorter.yaml python agent.py

# View what the agent did
agentbox audit --log logs/email-sorter-audit.log

# Verify the log hasn't been tampered with
agentbox verify logs/email-sorter-audit.log

# Manage secrets
agentbox vault add ANTHROPIC_API_KEY
agentbox vault list
```

---

## The manifest

Every agent declares exactly what it needs. **Nothing not listed is accessible.**

```yaml
name: "email-sorter"
version: "1.0.0"
description: "Reads inbox, categorizes emails, writes to sorted folder"
runtime: docker        # or: gvisor (kernel-level), firecracker (MicroVM)

permissions:
  filesystem:
    read:
      - "~/Documents/inbox"
    write:
      - "~/Documents/sorted"
    deny:                      # ALWAYS blocked — even if in read list
      - "~/.ssh"
      - "~/.aws"
      - "~/.config"
      - "/etc"

  network:
    allow:
      - "api.anthropic.com"
      - "gmail.googleapis.com"
    deny:
      - "*"                    # block everything else

  tools:
    allow:
      - "read_file"
      - "write_file"
      - "list_*"
    deny:
      - "execute_shell"        # no shell access, ever
      - "*_delete"             # no deletion tools

  credentials:
    - ANTHROPIC_API_KEY        # injected from vault at runtime
    - GMAIL_TOKEN              # agent never sees the raw value

limits:
  max_tokens:    50000         # LLM token budget
  max_duration:  "30m"         # killed after 30 minutes
  max_memory_mb: 256           # RAM ceiling
  max_requests:  500           # max tool invocations

audit:
  log_level: full
  alert_on:
    - filesystem_deny
    - network_deny
    - token_budget_80pct
  log_path: "logs/email-sorter-audit.log"
```

---

## How it works

```
agentbox run --manifest agent.yaml python agent.py
         │
         ▼
┌─────────────────────────────────────────────────────┐
│                 Policy Engine                        │
│  Parses manifest → builds allow/deny lists          │
│  Validates signatures → rejects unsigned skills     │
│  Injects credentials from vault                     │
└──────────────────────┬──────────────────────────────┘
                       │
                       ▼
┌─────────────────────────────────────────────────────┐
│              Isolation Layer                         │
│                                                     │
│  Docker  → container + seccomp + cap-drop           │
│  gVisor  → user-space kernel, syscall interception  │
│  Firecracker → dedicated MicroVM kernel per agent   │
│                                                     │
│  Filesystem: only declared paths mounted            │
│  Network:    only declared hosts reachable          │
│  Capabilities: ALL dropped, none added back         │
└──────────────────────┬──────────────────────────────┘
                       │
          ┌────────────┼────────────┐
          ▼            ▼            ▼
   Audit Logger   Credential    Resource
   (hash-chain)     Vault       Monitor
   every action   AES-256-GCM  auto-kill
   logged         scoped tokens on limit
```

### Why gVisor stops prompt injection

Every other sandbox stops at the container boundary. An agent exploiting a kernel vulnerability can escape.

gVisor intercepts every syscall **before it reaches the host kernel**:

```
Agent tries: write("/home/user/.ssh/id_rsa")
                    │
                    ▼
         gVisor user-space kernel
                    │
         Path in deny list? → YES
                    │
                    ▼
         EPERM returned immediately
         Host kernel never sees this syscall
         Prompt injection cannot cross this layer
```

---

## CLI reference

```
agentbox <command> [options]

Commands:
  run       Run an agent in a sandbox
  validate  Validate a manifest file
  kill      Terminate a running agent
  audit     View agent audit logs
  verify    Verify audit log integrity
  vault     Manage encrypted credentials
  serve     Start the REST API server
  version   Show version

Examples:
  agentbox validate manifests/email-sorter.yaml
  agentbox run --manifest manifests/email-sorter.yaml python agent.py
  agentbox kill agent-abc123
  agentbox audit --log logs/email-sorter.log --deny
  agentbox audit --log logs/email-sorter.log --last 1h
  agentbox verify logs/email-sorter.log
  agentbox vault add ANTHROPIC_API_KEY
  agentbox vault list
  agentbox vault delete OLD_KEY
  agentbox serve :8081
```

---

## REST API

Start with `agentbox serve` (default: `:8081`).

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/health` | Health check |
| GET | `/dashboard` | Web dashboard |
| GET | `/api/agents` | List all agents |
| POST | `/api/agents` | Start a new agent |
| DELETE | `/api/agents/:id` | Kill an agent |
| GET | `/api/audit` | Query audit log |

---

```bash
# List running agents
curl http://localhost:8081/api/agents

# Start an agent
curl -X POST http://localhost:8081/api/agents \
  -H "Content-Type: application/json" \
  -d '{"manifest":"manifests/email-sorter.yaml","command":["python","agent.py"]}'

# Kill an agent
curl -X DELETE http://localhost:8081/api/agents/abc123

# Query audit log
curl "http://localhost:8081/api/audit?deny=true&agent=email-sorter"
```

---

## Audit log

Every agent action is logged in an append-only, hash-chained JSON Lines file:

```json
{"id":1,"hash":"a3f2...","prev_hash":"genesis","timestamp":"2026-05-05T09:00:00Z","agent_id":"abc123","agent_name":"email-sorter","event_type":"agent_start","allowed":true,"resource":"manifests/email-sorter.yaml"}
{"id":2,"hash":"b7c1...","prev_hash":"a3f2...","timestamp":"2026-05-05T09:00:01Z","agent_id":"abc123","agent_name":"email-sorter","event_type":"filesystem_allow","allowed":true,"resource":"read:/home/user/Documents/inbox/mail.txt","rule":"filesystem.read: ~/Documents/inbox"}
{"id":3,"hash":"d9e4...","prev_hash":"b7c1...","timestamp":"2026-05-05T09:00:01Z","agent_id":"abc123","agent_name":"email-sorter","event_type":"filesystem_deny","allowed":false,"resource":"read:/home/user/.ssh/id_rsa","rule":"filesystem.deny: ~/.ssh","reason":"path is explicitly denied"}
```

**Tamper detection:**
```bash
agentbox verify logs/email-sorter-audit.log

✅ Audit log is intact
   Entries: 47 (IDs 1–47)
   Hash chain: unbroken
```

Change any character in any entry and verification fails immediately — the chain is broken.

---

## Credential vault

```bash
# Store a secret (never logged, never in env plaintext)
agentbox vault add ANTHROPIC_API_KEY

# List stored credential names (values never shown)
agentbox vault list

# Verify a credential can be decrypted
agentbox vault test ANTHROPIC_API_KEY

# Rotate a credential
agentbox vault add ANTHROPIC_API_KEY   # add updates existing
```

Credentials are encrypted with AES-256-GCM. The master key is derived from your vault password — never stored on disk. At agent startup, AgentBox injects credentials as scoped environment variables. The agent calls `os.getenv("ANTHROPIC_API_KEY")` normally — it never touches the vault.

---

## Resource limits

AgentBox kills agents that exceed their declared limits:

```bash
# This agent is configured with max_duration: 5s
agentbox run --manifest manifests/timeout-test.yaml python long_running_agent.py

Agent started
tick 1
tick 2
tick 3
tick 4
tick 5
🛑 Killing agent timeout-test: duration limit exceeded: 5s
⚠️  Agent timeout-test exited code 137 in 5.2s
```

Exit code 137 = SIGKILL. Clean shutdown, final audit entry written.

---

## Build from source

```bash
# Clone
git clone https://github.com/siyad01/agentbox
cd agentbox

# Build
go build -o agentbox ./cmd/agentbox/

# Run tests (27 tests, all passing)
go test ./...

# Install globally
go install ./cmd/agentbox/
```

**Requirements:**
- Go 1.26+
- Docker (for Docker and gVisor backends)
- Linux kernel 5.15+ (for gVisor — auto-detected, falls back to Docker)

---

## Project structure

```
agentbox/
├── cmd/agentbox/main.go          ← CLI entry point
├── internal/
│   ├── policy/
│   │   ├── manifest.go           ← YAML manifest schema
│   │   ├── parser.go             ← validation + defaults
│   │   └── engine.go             ← deny-first decision engine (20 tests)
│   ├── audit/
│   │   ├── logger.go             ← append-only SHA-256 hash-chained log
│   │   ├── verifier.go           ← tamper detection
│   │   └── reader.go             ← query + filter
│   ├── vault/
│   │   ├── store.go              ← AES-256-GCM encrypted credential store
│   │   └── injector.go           ← runtime injection (7 tests)
│   ├── sandbox/
│   │   ├── sandbox.go            ← Sandbox interface
│   │   ├── docker.go             ← Docker backend
│   │   ├── gvisor.go             ← gVisor backend (kernel-level)
│   │   ├── manager.go            ← agent lifecycle management
│   │   └── util.go               ← WSL2 detection, path helpers
│   ├── monitor/
│   │   └── enforcer.go           ← resource limits + auto-kill
│   └── api/
│       └── server.go             ← REST API on :8081
└── manifests/
    ├── email-sorter.yaml         ← production example
    └── timeout-test.yaml         ← limit enforcement example
```

---

## Security model

**Deny-first by default.** Agents start with zero permissions. Every capability must be explicitly declared.

**Deny list always wins.** Even if a path appears in the read list and the deny list, the deny list takes precedence. No exceptions.

**Kernel-level enforcement with gVisor.** Seccomp filters and capability dropping operate at the syscall boundary. Model output — which is attacker-controllable — runs in user space and cannot modify kernel-level policy.

**Credential isolation.** The vault master key is never stored on disk. Credentials are injected as short-lived scoped tokens at sandbox start and discarded on exit. Compromise of an agent process does not compromise the credential vault.

**Immutable audit trail.** The SHA-256 hash chain means retroactive log modification is detectable. Any change to any entry breaks the chain from that point forward.

See [SECURITY.md](SECURITY.md) for vulnerability reporting.

---

## Comparison

| Feature | AgentBox | OpenClaw sandbox | Docker only | AccuKnox |
|---------|----------|-----------------|-------------|----------|
| Open source (Apache 2.0) | ✅ | ✅ | ✅ | ❌ |
| Self-hostable | ✅ | ✅ | ✅ | K8s only |
| gVisor / kernel isolation | ✅ | ❌ | ❌ | ✅ |
| Credential vault | ✅ | ❌ | ❌ | ✅ |
| Immutable audit log | ✅ | ❌ | ❌ | ✅ |
| Auto-kill on limit breach | ✅ | ❌ | ❌ | ✅ |
| Framework agnostic | ✅ | ❌ (OpenClaw only) | ✅ | ✅ |
| Single binary deploy | ✅ | ❌ | ✅ | ❌ |

---

## Roadmap

- [ ] Firecracker MicroVM backend (dedicated Linux kernel per agent)
- [ ] eBPF syscall monitoring (real-time behavioral analysis)
- [ ] OPA/Rego policy-as-code (complex rule sets in Git)
- [ ] Prometheus metrics endpoint
- [ ] AgentBox Cloud (managed hosting, SOC2-ready)
- [ ] Manifest signing (Ed25519, provenance verification)
- [ ] DLP (data loss prevention — scan agent output for PII)

---

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md).

## License

Apache 2.0 — free to use, modify, and distribute. See [LICENSE](LICENSE).

---

<div align="center">

Built with Go · Zero external dependencies for core security features · Self-hostable in one command

**If CVE-2026-25253 concerned you, this is the fix. Give it a ⭐**

</div>