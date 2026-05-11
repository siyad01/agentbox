package main

import (
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/siyad01/agentbox/internal/audit"
	"github.com/siyad01/agentbox/internal/policy"
	"github.com/siyad01/agentbox/internal/sandbox"
	"github.com/siyad01/agentbox/internal/vault"
	"github.com/siyad01/agentbox/internal/api"
)

const version = "0.1.0"

func main() {
	if len(os.Args) < 2 {
		printHelp()
		os.Exit(1)
	}

	switch os.Args[1] {
	case "run":
		cmdRun(os.Args[2:])
	case "validate":
		cmdValidate(os.Args[2:])
	case "audit":
		cmdAudit(os.Args[2:])
	case "verify":
		cmdVerify(os.Args[2:])
	case "vault":
		cmdVault(os.Args[2:])
	case "kill":
		cmdKill(os.Args[2:])
	case "serve":
    	cmdServe(os.Args[2:])
	case "version":
		fmt.Printf("agentbox v%s\n", version)
	default:
		fmt.Fprintf(os.Stderr, "unknown command: %s\n", os.Args[1])
		printHelp()
		os.Exit(1)
	}
}

func cmdValidate(args []string) {
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "Usage: agentbox validate <manifest.yaml>")
		os.Exit(1)
	}

	path := args[0]
	fmt.Printf("Validating %s...\n\n", path)

	m, err := policy.ParseManifest(path)
	if err != nil {
		fmt.Fprintf(os.Stderr, "❌ Invalid manifest:\n%v\n", err)
		os.Exit(1)
	}

	fmt.Println("✅ Manifest is valid!")
	fmt.Println(m.Summary())
}

func cmdRun(args []string) {
	manifestPath := ""
	agentArgs    := []string{}

	for i := 0; i < len(args); i++ {
		if args[i] == "--manifest" && i+1 < len(args) {
			manifestPath = args[i+1]
			i++
		} else {
			agentArgs = append(agentArgs, args[i])
		}
	}

	if manifestPath == "" {
		fmt.Fprintln(os.Stderr,
			"usage: agentbox run --manifest <file.yaml> <command>")
		os.Exit(1)
	}
	if len(agentArgs) == 0 {
		fmt.Fprintln(os.Stderr, "error: no command specified")
		os.Exit(1)
	}

	m, err := policy.ParseManifest(manifestPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "❌ %v\n", err)
		os.Exit(1)
	}

	// Set up audit logger
	auditLogger, err := audit.NewLogger(m.Audit.LogPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "❌ Cannot open audit log: %v\n", err)
		os.Exit(1)
	}
	defer auditLogger.Close()

	// Set up vault (optional — only if credentials needed)
	var store *vault.Store
	if len(m.Permissions.Credentials) > 0 {
		password := os.Getenv("AGENTBOX_VAULT_PASSWORD")
		if password == "" {
			password = "agentbox-dev-password"
		}
		vaultPath := os.Getenv("HOME") + "/.agentbox/vault.json"
		store, err = vault.NewStore(vaultPath, password)
		if err != nil {
			fmt.Fprintf(os.Stderr, "❌ Cannot open vault: %v\n", err)
			os.Exit(1)
		}
	}

	// Create sandbox manager and run
	mgr := sandbox.NewManager(auditLogger, store)

	fmt.Printf("🚀 Running agent: %s v%s\n", m.Name, m.Version)
	fmt.Printf("   Runtime:  %s\n", m.Runtime)
	fmt.Printf("   Command:  %s\n", strings.Join(agentArgs, " "))
	fmt.Printf("   Audit:    %s\n\n", m.Audit.LogPath)

	agentID, err := mgr.Run(m, agentArgs)
	if err != nil {
		fmt.Fprintf(os.Stderr, "❌ Failed to start agent: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("Agent ID: %s\n", agentID)
	fmt.Println("(waiting for agent to finish — Ctrl+C to detach)")

	// Block until done
	for {
		time.Sleep(500 * time.Millisecond)
		agents := mgr.List()
		for _, a := range agents {
			if a.ID == agentID {
				if a.Status == sandbox.StatusStopped ||
					a.Status == sandbox.StatusKilled ||
					a.Status == sandbox.StatusFailed {
					return
				}
			}
		}
	}
}

func cmdKill(args []string) {
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "usage: agentbox kill <agent-id>")
		os.Exit(1)
	}
	fmt.Printf("Kill signal sent to agent: %s\n", args[0])
	fmt.Println("(full kill requires a running manager — coming in REST API step)")
}
func cmdAudit(args []string) {
	logPath := "agentbox-audit.log"
	agentName := ""
	onlyDeny := false
	sinceStr := ""
	limit := 50

	for i := 0; i < len(args); i++ {
		switch args[i] {
			case "--log":
			if i+1 < len(args) { logPath = args[i+1]; i++ }
		case "--agent":
			if i+1 < len(args) { agentName = args[i+1]; i++ }
		case "--deny":
			onlyDeny = true
		case "--last":
			if i+1 < len(args) { sinceStr = args[i+1]; i++ }
		case "--limit":
			if i+1 < len(args) {
				fmt.Sscanf(args[i+1], "%d", &limit)
				i++
			}
		}
	}

	var since time.Time
	if sinceStr != "" {
		d, err := time.ParseDuration(sinceStr)
		if err != nil {
			fmt.Fprintf(os.Stderr, "invalid duration %1 (use: 1h, 30m, 24h)\n", sinceStr)
			os.Exit(1)
		}
		since = time.Now().Add(-d)
	}

	entries, err := audit.Query(logPath, audit.Filter{
		AgentName: agentName,
		OnlyDeny:  onlyDeny,
		Since:     since,
		Limit:     limit,
	})

	if err != nil {
		fmt.Fprintf(os.Stderr, "❌ Cannot read audit log: %v\n", err)
		os.Exit(1)
	}

	if len(entries) == 0 {
		fmt.Println("No audit entries found matching filters.")
		return
	}

	fmt.Printf("%-4s  %-30s  %-8s  %-22s  %-15s  %s\n",
		"ID", "Agent", "Allowed", "Event", "Resource", "Reason")
	fmt.Println(strings.Repeat("─", 100))

	for _, e := range entries {
		allowed := "✅ ALLOW"
		if !e.Allowed {
			allowed = "❌ DENY "
		}

		resource := e.Resource
		if len(resource) > 25 {
			resource = "..." + resource[len(resource)-22:]
		}
		reason := e.Reason
		if len(reason) > 35 {
			reason = reason[:32] + "..."
		}
		fmt.Printf("%-4d  %-30s  %-8s  %-22s  %-25s  %s\n",
			e.ID, e.AgentName, allowed, e.EventType, resource, reason)
	}

	fmt.Printf("\n%d entries shown\n", len(entries))
}

func cmdVerify(args []string) {
	logPath := "agentbox-audit.log"
	if len(args) > 0 {
		logPath = args[0]
	}

	fmt.Printf("Verifying hash chain: %s\n\n", logPath)
	result := audit.VerifyChain(logPath)

	if result.Valid {
		fmt.Printf("✅ Audit log is intact\n")
		fmt.Printf("   Entries: %d (IDs %d–%d)\n",
			result.TotalEntries, result.FirstID, result.LastID)
		fmt.Println("   Hash chain: unbroken")
	} else {
		fmt.Printf("❌ TAMPERING DETECTED\n")
		fmt.Printf("   %s\n", result.Error)
		if result.TamperedAt > 0 {
			fmt.Printf("   First suspicious entry ID: %d\n", result.TamperedAt)
		}
	}
}

func cmdServe(args []string) {
	addr := ":8081"
	if len(args) > 0 {
		addr = args[0]
	}

	auditLogger, err := audit.NewLogger("agentbox-audit.log")
	if err != nil {
		fmt.Fprintf(os.Stderr, "❌ %v\n", err)
		os.Exit(1)
	}
	defer auditLogger.Close()

	mgr := sandbox.NewManager(auditLogger, nil)
	srv := api.NewServer(mgr, auditLogger)

	fmt.Println("AgentBox API server starting...")
	if err := srv.Start(addr); err != nil {
		fmt.Fprintf(os.Stderr, "❌ Server error: %v\n", err)
		os.Exit(1)
	}
}
func cmdVault(args []string) {
	if len(args) == 0 {
		fmt.Println(`agentbox vault — manage credentials

COMMANDS:
  agentbox vault add <NAME>        Store a credential (prompts for value)
  agentbox vault add <NAME> <VAL>  Store a credential with value
  agentbox vault list              List stored credential names
  agentbox vault delete <NAME>     Remove a credential
  agentbox vault test <NAME>       Verify a credential can be decrypted`)
	
	return
	}

	password := os.Getenv("AGENTBOX_VAULT_PASSWORD")
	if password == "" {
		password = "agentbox-dev-password"
	}

	vaultPath := os.Getenv("AGENTBOX_VAULT_PATH")
	if vaultPath == "" {
		vaultPath = os.Getenv("HOME") + "/.agentbox/vault.json"
	}

	os.MkdirAll(os.Getenv("HOME")+"/.agentbox", 0700)

	store, err := vault.NewStore(vaultPath, password)
	if err != nil {
		fmt.Fprintf(os.Stderr, "❌ Cannot open vault: %v\n", err)
		os.Exit(1)
	}

	switch args[0] {
	case "add":
		if len(args) < 2 {
			fmt.Fprintln(os.Stderr, "usage: agentbox vault add <NAME> [VALUE]")
			os.Exit(1)
		}
		name := args[1]
		value := ""
		if len(args) >= 3 {
			value = args[2]
		} else {
			fmt.Printf("Enter value for %s: ", name)
			fmt.Scanln(&value)
		}
		if value == "" {
			fmt.Fprintln(os.Stderr, "❌ Value cannot be empty")
			os.Exit(1)
		}
		if err := store.Add(name, value); err != nil {
			fmt.Fprintf(os.Stderr, "❌ %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("✅ Stored credential: %s\n", name)

	case "list":
		names, err := store.List()
		if err != nil {
			fmt.Fprintf(os.Stderr, "❌ %v\n", err)
			os.Exit(1)
		}
		if len(names) == 0 {
			fmt.Println("No credentials stored.")
			return
		}
		fmt.Printf("Stored credentials (%d):\n", len(names))
		for _, n := range names {
			fmt.Printf("  • %s\n", n)
		}

	case "delete":
		if len(args) < 2 {
			fmt.Fprintln(os.Stderr, "usage: agentbox vault delete <NAME>")
			os.Exit(1)
		}

		if err := store.Delete(args[1]); err != nil {
			fmt.Fprintf(os.Stderr, "❌ %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("✅ Deleted credential: %s\n", args[1])

	case "test":
		if len(args) < 2 {
			fmt.Fprintln(os.Stderr, "usage: agentbox vault test <NAME>")
			os.Exit(1)
		}

		val, err := store.Get(args[1])
		if err != nil {
			fmt.Fprintf(os.Stderr, "❌ %v\n", err)
			os.Exit(1)
		}

		preview := val
		if len(val) > 4 {
			preview = val[:4] + strings.Repeat("*", len(val)-4)
		}
		fmt.Printf("✅ Credential %s decrypted successfully: %s\n",
			args[1], preview)

	default:
		fmt.Fprintf(os.Stderr, "unknown vault command: %s\n", args[0])
		os.Exit(1)
	}
}


func printHelp() {
	fmt.Printf(`agentbox v%s — sandboxed AI agent runtime

USAGE:
  agentbox <command> [options]

COMMANDS:
  run       Run an agent inside a sandbox
  validate  Validate a manifest file
  audit     View agent audit logs
  verify    Verify audit log hash chain integrity
  kill      Terminate a running agent
  vault     Manage credentials
  version   Show version

EXAMPLES:
  agentbox validate manifests/email-sorter.yaml
  agentbox run --manifest agentbox.yaml python agent.py
  agentbox audit --agent email-sorter --last 1h
  agentbox audit --deny --limit 20
  agentbox verify logs/email-sorter-audit.log
  agentbox kill agent-abc123

`, version)
}