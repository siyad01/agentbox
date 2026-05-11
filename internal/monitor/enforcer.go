package monitor

import (
	"fmt"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/siyad01/agentbox/internal/audit"
)

type Limits struct {
	MaxDuration time.Duration
	MaxMemoryMB int
	MaxRequests int
}

type Enforcer struct {
	mu sync.Mutex
	agentID string
	agentName string
	containerName string
	limits Limits
	logger *audit.Logger
	startTime time.Time
	requestCount int
	killed bool
	killCh chan string
}

func NewEnforcer(agentID, agentName, containerName string, limits Limits, logger *audit.Logger) *Enforcer {
	return &Enforcer{
		agentID: agentID,
		agentName: agentName,
		containerName: containerName,
		limits: limits,
		logger: logger,
		startTime: time.Now(),
		killCh: make(chan string, 1),
	}
}

func (e *Enforcer) Start() <-chan string {
	go e.monitorLoop()
	return e.killCh
}

func (e *Enforcer) IncrementRequest() {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.requestCount++
}

func (e *Enforcer) Kill(reason string) error {
	e.mu.Lock()
	if e.killed {
		e.mu.Unlock()
		return nil
	}
	e.killed = true
	e.mu.Unlock()

	return e.killContainer(reason)
}

func (e *Enforcer) Stats() map[string]interface{} {
	e.mu.Lock()
	defer e.mu.Unlock()

	elapsed := time.Since(e.startTime)
	memMB := e.getMemoryMB()

	return map[string]interface{}{
		"elapsed": elapsed.Round(time.Second).String(),
		"memory_mb": memMB,
		"request_count": e.requestCount,
		"limit_duration": e.limits.MaxDuration.String(),
		"limit_memory": e.limits.MaxMemoryMB,
		"limit_requests": e.limits.MaxRequests,
	}
}

func (e *Enforcer) monitorLoop() {
	
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()

	for range ticker.C {
		e.mu.Lock()
		killed := e.killed
		e.mu.Unlock()

		if killed {
			return
		}

		if e.limits.MaxDuration > 0 {
			if time.Since(e.startTime) >= e.limits.MaxDuration {
				e.triggerKill(fmt.Sprintf("duration limit exceeded: %s", e.limits.MaxDuration))
				return
			}
		}

		if e.limits.MaxMemoryMB > 0 {
			memMB := e.getMemoryMB()
			if memMB > 0 && memMB >= e.limits.MaxMemoryMB {
				e.triggerKill(fmt.Sprintf("memory limit exceeded: %dMB used, limit %dMB", memMB, e.limits.MaxMemoryMB))
				return
			}

			if memMB > 0 &&
				memMB >= int(float64(e.limits.MaxMemoryMB)*0.8) {
				fmt.Printf("⚠️  Agent %s memory at %dMB / %dMB (80%%)\n",
					e.agentName, memMB, e.limits.MaxMemoryMB)

				if e.logger != nil {
					e.logger.Log(audit.Entry{
						AgentID: e.agentID,
						AgentName: e.agentName,
						EventType: audit.EventPolicyAlert,
						Allowed: true,
						Reason: fmt.Sprintf("memory at 80%%: %dMB", memMB),
					})
				}
			}
		}

		e.mu.Lock()
		reqCount := e.requestCount
		e.mu.Unlock()

		if e.limits.MaxRequests > 0 && reqCount >= e.limits.MaxRequests {
			e.triggerKill(fmt.Sprintf("request limit exceeded: %d requests, limit %d", reqCount, e.limits.MaxRequests))
			return
		}
	}
}

func (e *Enforcer) triggerKill(reason string) {
	e.mu.Lock()
	if e.killed {
		e.mu.Unlock()
		return
	}

	e.killed = true
	e.mu.Unlock()

	fmt.Printf("⛔ Killing agent %s: %s\n", e.agentName, reason)

	if e.logger != nil {
		e.logger.LimitBreached(e.agentID, e.agentName, "limit", reason)
		e.logger.AgentKilled(e.agentID, e.agentName, reason)
	}

	e.killContainer(reason)
	e.killCh <- reason
}

func (e *Enforcer) killContainer(reason string) error {

	cmd := exec.Command("docker", "kill", e.containerName)
	if err := cmd.Run(); err != nil {
		return nil
	}
	fmt.Printf("🛑 Agent %s killed: %s\n", e.agentName, reason)
	return nil
}

func (e *Enforcer) getMemoryMB() int {

	cmd := exec.Command("docker", "stats", e.containerName, "--no-stream", "--format", "{{.MemUsage}}")

	out, err := cmd.Output()
	if err != nil {
		return 0
	}

	parts := strings.Split(strings.TrimSpace(string(out)), " / ")
	if len(parts) == 0 {
		return 0
	}

	usage := strings.TrimSpace(parts[0])
	return parseMiB(usage)
}

func parseMiB(s string) int {
	s = strings.TrimSpace(s)

	if strings.HasSuffix(s, "GiB") {
		val, err := strconv.ParseFloat(
			strings.TrimSuffix(s, "GiB"), 64)
		if err != nil {
			return 0
		}
		return int(val * 1024)
	}

	if strings.HasSuffix(s, "MiB") {
		val, err := strconv.ParseFloat(
			strings.TrimSuffix(s, "MiB"), 64)
		if err != nil {
			return 0
		}
		return int(val)
	}

	if strings.HasSuffix(s, "KiB") {
		val, err := strconv.ParseFloat(
			strings.TrimSuffix(s, "KiB"), 64)
		if err != nil {
			return 0
		}
		return int(val / 1024)
	}

	return 0
}