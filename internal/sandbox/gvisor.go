package sandbox

import (
	"fmt"
	"os"
	"os/exec"
	"strings"
	"sync"
	"time"

)

// GVisorSandbox runs agents under gVisor (runsc).
// gVisor intercepts every syscall in user space — the agent
// cannot reach the host kernel even with a kernel exploit.
// Falls back to Docker if gVisor is not installed.
type GVisorSandbox struct {
	mu        sync.RWMutex
	id        string
	status    Status
	cfg       RunConfig
	resultCh  chan RunResult
	startTime time.Time
}

// NewGVisorSandbox creates a gVisor sandbox.
func NewGVisorSandbox(agentID string) *GVisorSandbox {
	return &GVisorSandbox{
		id:       agentID,
		status:   StatusPending,
		resultCh: make(chan RunResult, 1),
	}
}

// IsAvailable checks if gVisor (runsc) is installed and configured.
func IsGVisorAvailable() bool {
	// Check if runsc binary exists
	_, err := exec.LookPath("runsc")
	if err != nil {
		return false
	}

	// Check if Docker is configured to use gVisor runtime
	cmd := exec.Command("docker", "info", "--format",
		"{{range .Runtimes}}{{.}}{{end}}")
	out, err := cmd.Output()
	if err != nil {
		return false
	}

	return strings.Contains(string(out), "runsc") ||
		strings.Contains(string(out), "gvisor")
}

// Start launches the agent under gVisor isolation.
func (s *GVisorSandbox) Start(cfg RunConfig) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.cfg       = cfg
	s.startTime = time.Now()

	if cfg.Logger != nil {
		cfg.Logger.AgentStart(cfg.AgentID, cfg.AgentName,
			"gvisor", cfg.Manifest.Name)
	}

	// Check gVisor availability
	if !IsGVisorAvailable() {
		fmt.Println("⚠️  gVisor not found — falling back to Docker")
		fmt.Println("   Install gVisor: https://gvisor.dev/docs/user_guide/install/")

		// Delegate to Docker backend
		dockerSandbox := NewDockerSandbox(s.id)
		if err := dockerSandbox.Start(cfg); err != nil {
			return err
		}

		// Proxy all methods to Docker sandbox
		go func() {
			result := dockerSandbox.Wait()
			s.mu.Lock()
			s.status = StatusStopped
			s.mu.Unlock()
			s.resultCh <- result
		}()

		s.status = StatusRunning
		return nil
	}

	fmt.Printf("🛡️  Starting gVisor sandbox: %s\n", cfg.AgentName)

	args := s.buildGVisorArgs(cfg)

	cmd := exec.Command("docker", args...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	if err := cmd.Start(); err != nil {
		s.status = StatusFailed
		return fmt.Errorf("cannot start gVisor container: %w", err)
	}

	s.status = StatusRunning

	go func() {
		err      := cmd.Wait()
		exitCode := 0
		if err != nil {
			if exitErr, ok := err.(*exec.ExitError); ok {
				exitCode = exitErr.ExitCode()
			}
		}

		duration := time.Since(s.startTime).Round(time.Millisecond).String()

		s.mu.Lock()
		if s.status == StatusRunning {
			s.status = StatusStopped
		}
		s.mu.Unlock()

		if cfg.Logger != nil {
			cfg.Logger.AgentStop(cfg.AgentID, cfg.AgentName, exitCode)
		}

		s.resultCh <- RunResult{
			AgentID:  cfg.AgentID,
			ExitCode: exitCode,
			Duration: duration,
		}
	}()

	return nil
}

// buildGVisorArgs builds docker run args with --runtime=runsc
func (s *GVisorSandbox) buildGVisorArgs(cfg RunConfig) []string {
	m := cfg.Manifest
	args := []string{
		"run", "--rm",
		"--runtime", "runsc", // THE key difference from Docker
		"--name", sanitizeContainerName(cfg.AgentID),
	}

	// Resource limits
	if m.Limits.MaxMemoryMB > 0 {
		args = append(args,
			"--memory", fmt.Sprintf("%dm", m.Limits.MaxMemoryMB))
	}
	args = append(args, "--cpus", "1.0")

	// Network — gVisor supports proper network namespacing
	if isWSL2() {
		args = append(args, "--network", "host")
	} else if len(m.Permissions.Network.Allow) == 0 {
		args = append(args, "--network", "none")
	} else {
		args = append(args, "--network", "bridge")
	}

	// Filesystem mounts
	for _, p := range m.Permissions.Filesystem.Read {
		expanded := expandHomePath(p)
		if pathExists(expanded) {
			args = append(args, "--volume",
				fmt.Sprintf("%s:%s:ro", expanded, expanded))
		}
	}
	for _, p := range m.Permissions.Filesystem.Write {
		expanded := expandHomePath(p)
		os.MkdirAll(expanded, 0755)
		args = append(args, "--volume",
			fmt.Sprintf("%s:%s:rw", expanded, expanded))
	}

	// gVisor security — more restrictive than Docker
	args = append(args,
		"--security-opt", "no-new-privileges",
		"--cap-drop", "ALL",
	)

	// Environment
	for k, v := range cfg.Env {
		args = append(args, "--env", fmt.Sprintf("%s=%s", k, v))
	}

	args = append(args, "python:3.12-slim")
	args = append(args, cfg.Command...)

	return args
}

func (s *GVisorSandbox) Wait() RunResult   { return <-s.resultCh }
func (s *GVisorSandbox) Status() Status {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.status
}
func (s *GVisorSandbox) ID() string { return s.id }
func (s *GVisorSandbox) Kill(reason string) error {
	s.mu.Lock()
	s.status = StatusKilled
	s.mu.Unlock()

	if s.cfg.Logger != nil {
		s.cfg.Logger.AgentKilled(s.id, s.cfg.AgentName, reason)
	}

	containerName := sanitizeContainerName(s.id)
	cmd := exec.Command("docker", "kill", containerName)
	cmd.Run()
	return nil
}

// Ensure GVisorSandbox implements Sandbox interface.
var _ Sandbox = (*GVisorSandbox)(nil)

// Ensure DockerSandbox implements Sandbox interface.
var _ Sandbox = (*DockerSandbox)(nil)
