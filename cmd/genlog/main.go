package main

import (
    "fmt"
    "github.com/siyad01/agentbox/internal/audit"
)

func main() {
    l, _ := audit.NewLogger("sample-audit.log")
    l.AgentStart("agent-abc123", "email-sorter", "docker", "manifests/email-sorter.yaml")
    l.FilesystemEvent("agent-abc123", "email-sorter", "read", "/home/user/documents/inbox/mail.txt", "filesystem.read: ~/Documents/inbox", "path matches allow rule", true)
    l.FilesystemEvent("agent-abc123", "email-sorter", "read", "/home/user/.ssh/id_rsa", "filesystem.deny: ~/.ssh", "path is explicitly denied", false)
    l.NetworkEvent("agent-abc123", "email-sorter", "api.anthropic.com", "network.allow: api.anthropic.com", "host matches allow rule", true)
    l.NetworkEvent("agent-abc123", "email-sorter", "evil.hacker.com", "policy: default_deny", "host not in allow list", false)
    l.ToolEvent("agent-abc123", "email-sorter", "execute_shell", "tools.deny: execute_shell", "tool matches deny pattern", false)
    l.AgentStop("agent-abc123", "email-sorter", 0)
    l.Close()
    fmt.Println("Sample audit log written to sample-audit.log")
}
