package sandbox

import (
	"github.com/siyad01/agentbox/internal/audit"
	"github.com/siyad01/agentbox/internal/policy"
)

// Status represents the current state of a sandbox.
type Status string

const (
	StatusPending  Status = "pending"
	StatusRunning  Status = "running"
	StatusStopped  Status = "stopped"
	StatusKilled   Status = "killed"
	StatusFailed   Status = "failed"
)

// RunConfig holds everything needed to start an agent sandbox.
type RunConfig struct {
	// Identity
	AgentID   string
	AgentName string

	// What to run
	Command []string // e.g. ["python", "agent.py"]
	WorkDir string   // working directory inside sandbox

	// Policy + secrets
	Manifest *policy.Manifest
	Env      map[string]string // injected credentials as env vars

	// Observability
	Logger *audit.Logger
}

// RunResult holds the outcome after a sandbox finishes.
type RunResult struct {
	AgentID  string
	ExitCode int
	Error    error
	Duration string
}

// Sandbox is the interface every backend must implement.
// DockerSandbox, GVisorSandbox, FirecrackerSandbox all satisfy this.
type Sandbox interface {
	// Start launches the agent in the sandbox.
	// Returns immediately — the agent runs in the background.
	Start(cfg RunConfig) error

	// Wait blocks until the agent finishes or is killed.
	Wait() RunResult

	// Kill terminates the agent immediately.
	Kill(reason string) error

	// Status returns the current sandbox state.
	Status() Status

	// ID returns the unique sandbox identifier.
	ID() string
}