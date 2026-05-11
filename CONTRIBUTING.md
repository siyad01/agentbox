## Getting started

```bash
git clone https://github.com/siyad01/agentbox
cd agentbox
go build -o agentbox ./cmd/agentbox/
go test ./...
```

## Project structure

- `internal/policy/` — Manifest parsing, deny-first engine
- `internal/audit/` — Append-only hash-chained logger
- `internal/vault/` — AES-256-GCM credential store
- `internal/sandbox/` — Docker + gVisor backends
- `internal/monitor/` — Resource limits + kill switch
- `internal/api/` — REST API server

## How to contribute

1. **Open an issue first** for anything larger than a bug fix — discuss the approach before writing code
2. **Fork the repo** and create a branch: `git checkout -b feature/your-feature`
3. **Write tests** — all new code needs tests. Run with `go test ./...`
4. **Keep it focused** — one feature or fix per PR
5. **Open a Pull Request** with a clear description of what and why

## Good first issues

These are well-scoped and don't require deep knowledge of the codebase:

- **Firecracker backend** — implement `internal/sandbox/firecracker.go` using the Firecracker Go SDK
- **Prometheus metrics** — add `/metrics` endpoint to the API server
- **Manifest examples** — add more example manifests to `manifests/` (code-reviewer, research-agent, web-scraper)
- **CLI colors** — add color output to the audit display using a terminal color library
- **`agentbox ps`** — a `ps`-style command showing resource usage of running agents
- **Manifest linting** — warn about overly permissive manifests (e.g. `allow: ["*"]`)

## Code style

- Standard Go formatting: `gofmt` before committing
- Error messages start lowercase: `fmt.Errorf("cannot open file: %w", err)`
- Security-critical code gets a comment explaining the security property
- No external dependencies without discussion — the core must stay lean

## Testing

```bash
# Run all tests
go test ./...

# Run with verbose output
go test ./... -v

# Run a specific package
go test ./internal/policy/... -v

# Run a specific test
go test ./internal/audit/... -run TestLogger_TamperDetection -v
```

## Security contributions

If you find a security vulnerability, **do not open a public issue**.
See [SECURITY.md](SECURITY.md) for responsible disclosure.

## Questions?

Open a GitHub Discussion. We respond within 48 hours.
EOF