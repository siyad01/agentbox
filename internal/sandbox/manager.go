package sandbox

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"sync"
	"time"

	"github.com/siyad01/agentbox/internal/audit"
	"github.com/siyad01/agentbox/internal/monitor"
	"github.com/siyad01/agentbox/internal/policy"
	"github.com/siyad01/agentbox/internal/vault"
)

// RunningAgent tracks a live sandbox with its metadata.
type RunningAgent struct {
	ID        string
	Name      string
	Runtime   string
	StartedAt time.Time
	Status    Status
	Sandbox   Sandbox
}

// Manager owns all running sandboxes.
// It's the single source of truth for what agents are alive.
type Manager struct {
	mu     sync.RWMutex
	agents map[string]*RunningAgent
	logger *audit.Logger
	store  *vault.Store
}

// NewManager creates a sandbox manager.
func NewManager(logger *audit.Logger, store *vault.Store) *Manager {
	return &Manager{
		agents: make(map[string]*RunningAgent),
		logger: logger,
		store:  store,
	}
}

// Run starts a new agent sandbox from a manifest.
// Returns the agent ID immediately — the agent runs in background.
func (m *Manager) Run(manifest *policy.Manifest, command []string) (string, error) {
	agentID, err := generateID()
	if err != nil {
		return "", fmt.Errorf("cannot generate agent ID: %w", err)
	}

	// Inject credentials
	var env map[string]string
	if len(manifest.Permissions.Credentials) > 0 && m.store != nil {
		inj := vault.NewInjector(m.store)
		injected, err := inj.InjectForAgent(manifest.Permissions.Credentials)
		if err != nil {
			return "", fmt.Errorf("credential injection failed: %w", err)
		}
		env = map[string]string(injected)
	}

	// Parse duration limit
	var maxDuration time.Duration
	if manifest.Limits.MaxDuration != "" {
		maxDuration, _ = time.ParseDuration(manifest.Limits.MaxDuration)
	}

	// In the Run function, replace the sandbox creation:
	var sb Sandbox
	switch manifest.Runtime {
	case "gvisor":
		sb = NewGVisorSandbox(agentID)
		fmt.Println("🛡️  Runtime: gVisor (kernel-level isolation)")
	case "firecracker":
		// Firecracker needs a full Linux VM setup
		// Falls back to gVisor which falls back to Docker
		sb = NewGVisorSandbox(agentID)
		fmt.Println("⚠️  Firecracker: using gVisor fallback")
	default: // "docker" or empty
		sb = NewDockerSandbox(agentID)
		fmt.Println("🐳 Runtime: Docker")
	}

	cfg := RunConfig{
		AgentID:   agentID,
		AgentName: manifest.Name,
		Command:   command,
		Manifest:  manifest,
		Env:       env,
		Logger:    m.logger,
	}

	agent := &RunningAgent{
		ID:        agentID,
		Name:      manifest.Name,
		Runtime:   manifest.Runtime,
		StartedAt: time.Now(),
		Status:    StatusPending,
		Sandbox:   sb,
	}

	m.mu.Lock()
	m.agents[agentID] = agent
	m.mu.Unlock()

	if err := sb.Start(cfg); err != nil {
		m.mu.Lock()
		agent.Status = StatusFailed
		m.mu.Unlock()
		return agentID, fmt.Errorf("sandbox start failed: %w", err)
	}

	agent.Status = StatusRunning

	// Start resource enforcer
	limits := monitor.Limits{
		MaxDuration: maxDuration,
		MaxMemoryMB: manifest.Limits.MaxMemoryMB,
		MaxRequests: manifest.Limits.MaxRequests,
	}

	containerName := sanitizeContainerName(agentID)
	enforcer := monitor.NewEnforcer(
		agentID, manifest.Name, containerName, limits, m.logger)
	killCh := enforcer.Start()

	go func() {
		select {
		case reason := <-killCh:
			// Enforcer killed the agent
			m.mu.Lock()
			agent.Status = StatusKilled
			m.mu.Unlock()
			fmt.Printf("🛑 Agent %s auto-killed: %s\n",
				manifest.Name, reason)
		case result := <-func() chan RunResult {
			ch := make(chan RunResult, 1)
			go func() { ch <- sb.Wait() }()
			return ch
		}():
			// Agent finished normally
			m.mu.Lock()
			agent.Status = StatusStopped
			m.mu.Unlock()

			if result.ExitCode == 0 {
				fmt.Printf("✅ Agent %s finished in %s\n",
					manifest.Name, result.Duration)
			} else {
				fmt.Printf("⚠️  Agent %s exited code %d in %s\n",
					manifest.Name, result.ExitCode, result.Duration)
			}
		}
	}()

	return agentID, nil
}

// Kill terminates a running agent by ID.
func (m *Manager) Kill(agentID, reason string) error {
	m.mu.RLock()
	agent, ok := m.agents[agentID]
	m.mu.RUnlock()

	if !ok {
		return fmt.Errorf("agent %s not found", agentID)
	}

	if agent.Status != StatusRunning {
		return fmt.Errorf("agent %s is not running (status: %s)",
			agentID, agent.Status)
	}

	return agent.Sandbox.Kill(reason)
}

// List returns all tracked agents (running and finished).
func (m *Manager) List() []*RunningAgent {
	m.mu.RLock()
	defer m.mu.RUnlock()

	result := make([]*RunningAgent, 0, len(m.agents))
	for _, a := range m.agents {
		a.Status = a.Sandbox.Status() // refresh status
		result = append(result, a)
	}
	return result
}

// generateID creates a random 8-byte hex agent ID.
func generateID() (string, error) {
	b := make([]byte, 8)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}