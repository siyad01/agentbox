package policy

import (
	"fmt"
	"path/filepath"
	"strings"
)

type Decision struct {
	Allowed bool
	Reason string
	Rule string
}

type EventType string

const (
	EventFilesystemRead  EventType = "filesystem_read"
	EventFilesystemWrite EventType = "filesystem_write"
	EventNetworkConnect  EventType = "network_connect"
	EventToolCall        EventType = "tool_call"
	EventCredentialRead  EventType = "credential_read"
)

type Engine struct {
	manifest *Manifest
}

func NewEngine(m *Manifest) *Engine {
	return &Engine{manifest: m}
}

func (e *Engine) CheckFilesystem(op string, path string) Decision {

	path = expandPath(path)

	for _, denyPath := range e.manifest.Permissions.Filesystem.Deny {
		denyPath = expandPath(denyPath)
		if pathMatches(path, denyPath) {
			return Decision{
				Allowed: false,
				Reason: fmt.Sprintf("path %q is explicitly denied", path),
				Rule: fmt.Sprintf("filesystem.deny: %s", denyPath),
			}
		}
	}

	var allowList []string
	switch op {
	case "read":
		allowList = e.manifest.Permissions.Filesystem.Read
	case "write":
		allowList = e.manifest.Permissions.Filesystem.Write
	default:
		return Decision{
			Allowed: false,
			Reason: fmt.Sprintf("unknown filesystem operation %s", op),
			Rule: "policy: unknown_op",
		}
	}

	for _, allowPath := range allowList {
		allowPath = expandPath(allowPath)
		if pathMatches(path, allowPath) {
			return Decision{
				Allowed: true,
				Reason: fmt.Sprintf("path %q matches allow rule", path),
				Rule: fmt.Sprintf("filesystem.%s: %s", op, allowPath),
			}
		}
	}

	return Decision{
		Allowed: false,
		Reason: fmt.Sprintf("path %q not in %s allow list", path, op),
		Rule: "policy: default_deny",
	}
}

func (e *Engine) CheckNetwork(host string) Decision {

	if idx := strings.LastIndex(host, ":"); idx != -1 {
		host = host[:idx]
	}

	for _, denyHost := range e.manifest.Permissions.Network.Deny {
		if hostMatches(host, denyHost) {
			return Decision{
				Allowed: false,
				Reason: fmt.Sprintf("host %q is denied", host),
				Rule: fmt.Sprintf("network.deny: %s", denyHost),
			}
		}
	}

	if len(e.manifest.Permissions.Network.Allow) == 0 {
		return Decision{
			Allowed: false,
			Reason: fmt.Sprintf("host %q: no network allow rules defined", host),
			Rule: "policy: default_deny",
		}
	}

	// Check allow list
	for _, allowHost := range e.manifest.Permissions.Network.Allow {
		if hostMatches(host, allowHost) {
			return Decision{
				Allowed: true,
				Reason:  fmt.Sprintf("host %q matches allow rule", host),
				Rule:    fmt.Sprintf("network.allow: %s", allowHost),
			}
		}
	}

	return Decision{
		Allowed: false,
		Reason:  fmt.Sprintf("host %q not in network allow list", host),
		Rule:    "policy: default_deny",
	}
}

func (e *Engine) CheckTool(tool string) Decision {

	for _, denyPattern := range e.manifest.Permissions.Tools.Deny {
		if toolMatches(tool, denyPattern) {
			return Decision{
				Allowed: false,
				Reason: fmt.Sprintf("tool %q matches deny pattern", tool),
				Rule: fmt.Sprintf("tool.deny: %s", denyPattern),
			}
		}
	}

	for _, allowPattern := range e.manifest.Permissions.Tools.Allow {
		if toolMatches(tool, allowPattern) {
			return Decision{
				Allowed: true,
				Reason: fmt.Sprintf("tool %q matches allow pattern", tool),
				Rule: fmt.Sprintf("tool.allow: %s", allowPattern),
			}
		}
	}

	return Decision{
		Allowed: false,
		Reason: fmt.Sprintf("tool %q not in allow list", tool),
		Rule: "policy: default_deny",
	}
}

func (e *Engine) CheckCredential(name string) Decision {
	for _, cred := range e.manifest.Permissions.Credentials {
		if cred == name {
			return Decision{
				Allowed: true,
				Reason: fmt.Sprintf("credential %q is in manifest", name),
				Rule: fmt.Sprintf("credential: %s", name),
			}
		}
	}
	return Decision{
		Allowed: false,
		Reason: fmt.Sprintf("credential %q is not declared in manifest", name),
		Rule: "policy: default_deny",
	}
}

func (e *Engine) ShouldAlert(eventType string) bool {
	for _, alertEvent := range e.manifest.Audit.AlertOn {
		if alertEvent == eventType {
			return true
		}
	}
	return false
}

func pathMatches(target, rule string) bool {

	if target == rule {
		return true
	}
	if strings.HasPrefix(target, rule+"/") {
		return true
	}

	matched, err := filepath.Match(rule, target)
	if err == nil && matched {
		return true
	}
	return false
}

func hostMatches(host, rule string) bool {
	if rule == "*" {
		return true
	}
	if rule == host {
		return true
	}

	if strings.HasPrefix(rule, "*.") {
		suffix := rule[1:]
		return strings.HasSuffix(host, suffix)
	}
	return false
}

func toolMatches(tool, pattern string) bool {
	if pattern == "*" {
		return true
	}
	if pattern == tool {
		return true
	}

	if strings.HasSuffix(pattern, "*") {
		prefix := strings.TrimSuffix(pattern, "*")
		return strings.HasPrefix(tool, prefix)
	}

	if strings.HasPrefix(pattern, "*") {
		suffix := strings.TrimPrefix(pattern, "*")
		return strings.HasSuffix(tool, suffix)
	}

	return false
}

func expandPath(path string) string {
	if strings.HasPrefix(path, "~/") {
		home, err := homeDir()
		if err == nil {
			return filepath.Join(home, path[2:])
		}
	}
	return path
}

func homeDir() (string, error) {
	home, err := filepath.Abs("~")
	if err != nil {
		return "/root", nil
	}
	return home, nil
}