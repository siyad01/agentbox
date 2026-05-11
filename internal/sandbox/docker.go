package sandbox

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/siyad01/agentbox/internal/policy"
)

// DockerSandbox runs an agent inside a Docker container
// with filesystem, network, and resource restrictions
// derived from the agent's manifest.
type DockerSandbox struct {
	mu          sync.RWMutex
	id          string          // agentbox agent ID
	containerID string          // Docker container ID
	status      Status
	cfg         RunConfig
	resultCh    chan RunResult
	startTime   time.Time
}

// NewDockerSandbox creates a Docker sandbox (not yet started).
func NewDockerSandbox(agentID string) *DockerSandbox {
	return &DockerSandbox{
		id:       agentID,
		status:   StatusPending,
		resultCh: make(chan RunResult, 1),
	}
}

// Start launches the agent inside a Docker container.
// The container is configured from the manifest policy.
func (s *DockerSandbox) Start(cfg RunConfig) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.cfg       = cfg
	s.startTime = time.Now()

	// Build the docker run command from the manifest
	args, err := s.buildDockerArgs(cfg)
	if err != nil {
		return fmt.Errorf("cannot build docker args: %w", err)
	}

	// Log agent start
	if cfg.Logger != nil {
		cfg.Logger.AgentStart(cfg.AgentID, cfg.AgentName,
			"docker", cfg.Manifest.Name)
	}

	fmt.Printf("🐳 Starting sandbox: %s\n", cfg.AgentName)
	fmt.Printf("   Container args: docker %s\n",
		strings.Join(args[:6], " ")+"...")

	// Start the container
	cmd := exec.Command("docker", args...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	if err := cmd.Start(); err != nil {
		s.status = StatusFailed
		return fmt.Errorf("cannot start container: %w", err)
	}

	s.status = StatusRunning

	// Wait for container in background goroutine
	go func() {
		err := cmd.Wait()
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

// buildDockerArgs constructs the docker run arguments from the manifest.
// This is where the manifest policy becomes real container restrictions.
func (s *DockerSandbox) buildDockerArgs(cfg RunConfig) ([]string, error) {
	m := cfg.Manifest
	args := []string{"run", "--rm"} // --rm removes container after exit

	// ── Identity ───────────────────────────────────────
	args = append(args, "--name", sanitizeContainerName(cfg.AgentID))

	// ── Resource limits ────────────────────────────────
	if m.Limits.MaxMemoryMB > 0 {
		args = append(args,
			"--memory", fmt.Sprintf("%dm", m.Limits.MaxMemoryMB),
			"--memory-swap", fmt.Sprintf("%dm", m.Limits.MaxMemoryMB))
	}

	// CPU limit — default to 1 CPU
	args = append(args, "--cpus", "1.0")

	if isWSL2() {
		args = append(args, "--network", "host")
	} else {
		// ── Network isolation ──────────────────────────────
		if len(m.Permissions.Network.Allow) == 0 {
			// No network access at all
			args = append(args, "--network", "none")
		} else {
			// Use default bridge network but we'll enforce
			// allowed hosts via our proxy (future step)
			// For now, use host networking with DNS restriction
			args = append(args, "--network", "bridge")
		}
	}
	// ── Filesystem mounts ──────────────────────────────
	// Mount only allowed read paths (read-only)
	for _, readPath := range m.Permissions.Filesystem.Read {
		expanded := expandHomePath(readPath)
		if pathExists(expanded) {
			args = append(args,
				"--volume",
				fmt.Sprintf("%s:%s:ro", expanded, expanded))
		}
	}

	// Mount allowed write paths (read-write)
	for _, writePath := range m.Permissions.Filesystem.Write {
		expanded := expandHomePath(writePath)
		// Create dir if it doesn't exist
		os.MkdirAll(expanded, 0755)
		args = append(args,
			"--volume",
			fmt.Sprintf("%s:%s:rw", expanded, expanded))
	}

	// ── Security options ───────────────────────────────
	// Drop ALL Linux capabilities, add back only what's needed
	args = append(args,
		"--cap-drop", "ALL",
		"--security-opt", "no-new-privileges",
		"--read-only",          // container filesystem is read-only
		"--tmpfs", "/tmp:size=64m", // except /tmp
	)

	// Apply seccomp profile if available
	seccompPath := generateSeccompProfile(m)
	if seccompPath != "" {
		args = append(args,
			"--security-opt",
			fmt.Sprintf("seccomp=%s", seccompPath))
	}

	// ── Environment variables (injected credentials) ───
	for key, value := range cfg.Env {
		args = append(args, "--env",
			fmt.Sprintf("%s=%s", key, value))
	}

	// ── Working directory ──────────────────────────────
	if cfg.WorkDir != "" {
		args = append(args, "--workdir", cfg.WorkDir)
	}

	// ── Image + command ────────────────────────────────
	// Use a minimal Python image as default
	image := "python:3.12-slim"
	args = append(args, image)
	args = append(args, cfg.Command...)

	return args, nil
}

// Wait blocks until the sandbox finishes.
func (s *DockerSandbox) Wait() RunResult {
	return <-s.resultCh
}

// Kill terminates the container immediately.
func (s *DockerSandbox) Kill(reason string) error {
	s.mu.Lock()
	containerName := sanitizeContainerName(s.id)
	s.status = StatusKilled
	s.mu.Unlock()

	if s.cfg.Logger != nil {
		s.cfg.Logger.AgentKilled(s.id, s.cfg.AgentName, reason)
	}

	cmd := exec.Command("docker", "kill", containerName)
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("cannot kill container %s: %w", containerName, err)
	}

	fmt.Printf("🛑 Killed sandbox: %s (%s)\n", s.cfg.AgentName, reason)
	return nil
}

// Status returns the current state.
func (s *DockerSandbox) Status() Status {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.status
}

// ID returns the agent ID.
func (s *DockerSandbox) ID() string {
	return s.id
}

// ── Seccomp profile generation ────────────────────────────

// generateSeccompProfile writes a seccomp JSON profile based
// on the manifest and returns its path.
// Returns "" if seccomp is not available.
func generateSeccompProfile(m *policy.Manifest) string {
	// Minimal allowed syscalls for a Python agent
	// This blocks dangerous syscalls like ptrace, mount, etc.
	profile := `{
  "defaultAction": "SCMP_ACT_ERRNO",
  "architectures": ["SCMP_ARCH_X86_64"],
  "syscalls": [
    {
      "names": [
        "read", "write", "open", "openat", "close", "stat", "fstat",
        "lstat", "poll", "lseek", "mmap", "mprotect", "munmap", "brk",
        "rt_sigaction", "rt_sigprocmask", "rt_sigreturn", "ioctl",
        "pread64", "pwrite64", "readv", "writev", "access", "pipe",
        "select", "sched_yield", "mremap", "msync", "mincore", "madvise",
        "dup", "dup2", "nanosleep", "getitimer", "alarm", "setitimer",
        "getpid", "sendfile", "socket", "connect", "accept", "sendto",
        "recvfrom", "sendmsg", "recvmsg", "shutdown", "bind", "listen",
        "getsockname", "getpeername", "socketpair", "setsockopt",
        "getsockopt", "clone", "fork", "vfork", "execve", "exit",
        "wait4", "kill", "uname", "fcntl", "flock", "fsync", "fdatasync",
        "truncate", "ftruncate", "getdents", "getcwd", "chdir", "fchdir",
        "rename", "mkdir", "rmdir", "link", "unlink", "symlink",
        "readlink", "chmod", "fchmod", "chown", "fchown", "umask",
        "gettimeofday", "getrlimit", "getrusage", "sysinfo", "times",
        "getuid", "syslog", "getgid", "setuid", "setgid", "geteuid",
        "getegid", "getppid", "getpgrp", "setsid", "setpgid", "getpgid",
        "getgroups", "setresuid", "getresuid", "setresgid", "getresgid",
        "prctl", "arch_prctl", "setrlimit", "sync", "gettid", "futex",
        "sched_getaffinity", "set_thread_area", "get_thread_area",
        "set_tid_address", "clock_gettime", "clock_getres",
        "clock_nanosleep", "exit_group", "epoll_create", "epoll_ctl",
        "epoll_wait", "set_robust_list", "get_robust_list", "splice",
        "tee", "sync_file_range", "readlinkat", "fstatat", "openat",
        "newfstatat", "unlinkat", "renameat", "linkat", "symlinkat",
        "readlinkat", "fchmodat", "faccessat", "pselect6", "ppoll",
        "splice", "tee", "vmsplice", "move_pages", "accept4",
        "epoll_pwait", "signalfd", "eventfd", "timerfd_create",
        "timerfd_settime", "timerfd_gettime", "signalfd4", "eventfd2",
        "epoll_create1", "dup3", "pipe2", "inotify_init1", "preadv",
        "pwritev", "recvmmsg", "prlimit64", "sendmmsg", "getcpu",
        "getrandom", "memfd_create", "statx"
      ],
      "action": "SCMP_ACT_ALLOW"
    }
  ]
}`

	tmpFile := fmt.Sprintf("/tmp/agentbox-seccomp-%s.json", m.Name)
	if err := os.WriteFile(tmpFile, []byte(profile), 0644); err != nil {
		return "" // seccomp optional — return empty if can't write
	}
	return tmpFile
}

// ── Path helpers ──────────────────────────────────────────

func expandHomePath(path string) string {
	if strings.HasPrefix(path, "~/") {
		home, err := os.UserHomeDir()
		if err == nil {
			return filepath.Join(home, path[2:])
		}
	}
	return path
}

func pathExists(path string) bool {
	_, err := os.Stat(path)
	return !os.IsNotExist(err)
}

func sanitizeContainerName(id string) string {
	// Docker container names must be [a-zA-Z0-9_.-]
	name := strings.Map(func(r rune) rune {
		switch {
		case r >= 'a' && r <= 'z': return r
		case r >= 'A' && r <= 'Z': return r
		case r >= '0' && r <= '9': return r
		case r == '-' || r == '_' || r == '.': return r
		default: return '-'
		}
	}, "agentbox-"+id)
	return name
}

// contextWithTimeout wraps context creation — used by tests.
func contextWithTimeout(seconds int) (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.Background(),
		time.Duration(seconds)*time.Second)
}