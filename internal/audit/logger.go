package audit

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
	"sync"
	"time"
)

type EventType string

const (
	EventAgentStart      EventType = "agent_start"
	EventAgentStop       EventType = "agent_stop"
	EventAgentKilled     EventType = "agent_killed"
	EventFilesystemAllow EventType = "filesystem_allow"
	EventFilesystemDeny  EventType = "filesystem_deny"
	EventNetworkAllow    EventType = "network_allow"
	EventNetworkDeny     EventType = "network_deny"
	EventToolAllow       EventType = "tool_allow"
	EventToolDeny        EventType = "tool_deny"
	EventCredentialAllow EventType = "credential_allow"
	EventCredentialDeny  EventType = "credential_deny"
	EventLimitBreached   EventType = "limit_breached"
	EventPolicyAlert     EventType = "policy_alert"
)

type Entry struct {
	ID uint64 `json:"id"`
	Hash string `json:"hash"`
	PrevHash string `json:"prev_hash"`

	Timestamp string `json:"timestamp"`
	AgentID string `json:"agent_id"`
	AgentName string `json:"agent_name"`
	EventType EventType `json:"event_type"`
	Allowed bool `json:"allowed"`

	Resource string `json:"resource,omitempty"`
	Rule string `json:"rule,omitempty"`
	Reason string `json:"reason,omitempty"`
	Extra string `json:"extra,omitempty"`
}

type Logger struct {
	mu sync.Mutex
	file *os.File
	lastHash string
	counter uint64
	path string
}

func NewLogger(path string) (*Logger, error) {
	
	if err := os.MkdirAll(dirOf(path), 0755); err != nil {
		return nil, fmt.Errorf("cannot create log directory: %w", err)
	}

	f, err := os.OpenFile(path, os.O_APPEND | os.O_CREATE | os.O_WRONLY, 0644)
	if err != nil {
		return nil, fmt.Errorf("cannot open audit log %q: %w", path, err)
	}

	l := &Logger{
		file: f,
		lastHash: "genesis",
		path: path,
	}

	return l, nil
}

func (l *Logger) Log(entry Entry) error {
	l.mu.Lock()
	defer l.mu.Unlock()

	l.counter++
	entry.ID = l.counter
	entry.PrevHash = l.lastHash
	entry.Timestamp = time.Now().UTC().Format(time.RFC3339Nano)

	entry.Hash = l.computeHash(entry)

	data, err := json.Marshal(entry)
	if err != nil {
		return fmt.Errorf("cannot serialize audit entry: %w", err)
	}

	if _, err := fmt.Fprintf(l.file, "%s\n", data); err != nil {
		return fmt.Errorf("cannor write audit entry: %w", err)
	}

	l.lastHash = entry.Hash
	return nil
}

func (l *Logger) computeHash(e Entry) string {
	content := fmt.Sprintf("%d|%s|%s|%s|%s|%t|%s|%s|%s|%s", e.ID, e.PrevHash, e.Timestamp, e.AgentID, e.AgentName, e.Allowed, e.EventType, e.Resource, e.Rule, e.Reason,)
	sum := sha256.Sum256([]byte(content))
	return fmt.Sprintf("%x", sum)
}

func (l *Logger) Close() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.file.Close()
}

func (l *Logger) Path() string {
	return l.path
}

func (l *Logger) AgentStart(agentID, agentName, runtime, manifest string) error {
	return l.Log(Entry{
		AgentID: agentID,
		AgentName: agentName,
		EventType: EventAgentStart,
		Allowed: true,
		Resource: manifest,
		Extra: runtime,
	})
}

func (l *Logger) AgentStop(agentID, agentName string, exitCode int) error {
	return l.Log(Entry{
		AgentID: agentID,
		AgentName: agentName,
		EventType: EventAgentStop,
		Allowed: true,
		Extra: fmt.Sprintf("exit_code=%d", exitCode),
	})
}

func (l *Logger) AgentKilled(agentID, agentName, reason string) error {
	return l.Log(Entry{
		AgentID:   agentID,
		AgentName: agentName,
		EventType: EventAgentKilled,
		Allowed:   false,
		Reason:    reason,
	})
}

func (l *Logger) FilesystemEvent(agentID, agentName, op, path, rule, reason string, allowed bool) error {
	eventType := EventFilesystemAllow
	if !allowed {
		eventType = EventFilesystemDeny
	}

	return l.Log(Entry{
		AgentID:   agentID,
		AgentName: agentName,
		EventType: eventType,
		Allowed:   allowed,
		Resource:  fmt.Sprintf("%s:%s", op, path),
		Rule:      rule,
		Reason:    reason,
	})
}

func (l *Logger) NetworkEvent(agentID, agentName, host, rule, reason string, allowed bool) error {
	eventType := EventNetworkAllow
	if !allowed {
		eventType = EventNetworkDeny
	}

	return l.Log(Entry{
		AgentID:   agentID,
		AgentName: agentName,
		EventType: eventType,
		Allowed:   allowed,
		Resource:  host,
		Rule:      rule,
		Reason:    reason,
	})
}

func (l *Logger) ToolEvent(agentID, agentName, tool, rule, reason string, allowed bool) error {
	eventType := EventToolAllow
	if !allowed {
		eventType = EventToolDeny
	}
	return l.Log(Entry{
		AgentID:   agentID,
		AgentName: agentName,
		EventType: eventType,
		Allowed:   allowed,
		Resource:  tool,
		Rule:      rule,
		Reason:    reason,
	})
}

func (l *Logger) LimitBreached(agentID, agentName, limitType string, value interface{}) error {
	return l.Log(Entry{
		AgentID:   agentID,
		AgentName: agentName,
		EventType: EventLimitBreached,
		Allowed:   false,
		Reason:    fmt.Sprintf("%s limit breached: %v", limitType, value),
	})
}

// dirOf returns the directory part of a file path.
func dirOf(path string) string {
	for i := len(path) - 1; i >= 0; i-- {
		if path[i] == '/' {
			return path[:i]
		}
	}
	return "."
}