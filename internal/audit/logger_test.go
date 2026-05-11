package audit

import (
	"os"
	"testing"
)

func TestLogger_WriteAndVerify(t *testing.T) {
	// Use a temp file for testing
	tmpFile := "/tmp/agentbox-test-audit.log"
	defer os.Remove(tmpFile)

	logger, err := NewLogger(tmpFile)
	if err != nil {
		t.Fatalf("cannot create logger: %v", err)
	}

	// Write a sequence of entries
	logger.AgentStart("agent-001", "email-sorter", "docker",
		"manifests/email-sorter.yaml")

	logger.FilesystemEvent("agent-001", "email-sorter",
		"read", "/home/user/documents/inbox",
		"filesystem.read: ~/Documents/inbox",
		"path matches allow rule", true)

	logger.FilesystemEvent("agent-001", "email-sorter",
		"read", "/home/user/.ssh/id_rsa",
		"filesystem.deny: ~/.ssh",
		"path is explicitly denied", false)

	logger.NetworkEvent("agent-001", "email-sorter",
		"api.anthropic.com",
		"network.allow: api.anthropic.com",
		"host matches allow rule", true)

	logger.NetworkEvent("agent-001", "email-sorter",
		"evil.hacker.com",
		"policy: default_deny",
		"host not in allow list", false)

	logger.ToolEvent("agent-001", "email-sorter",
		"execute_shell",
		"tools.deny: execute_shell",
		"tool matches deny pattern", false)

	logger.AgentStop("agent-001", "email-sorter", 0)

	logger.Close()

	// Verify the chain is intact
	result := VerifyChain(tmpFile)
	if !result.Valid {
		t.Errorf("chain should be valid: %s", result.Error)
	}
	if result.TotalEntries != 7 {
		t.Errorf("expected 7 entries, got %d", result.TotalEntries)
	}

	t.Logf("✅ Chain verified: %d entries, IDs %d–%d",
		result.TotalEntries, result.FirstID, result.LastID)
}

func TestLogger_TamperDetection(t *testing.T) {
	tmpFile := "/tmp/agentbox-tamper-test.log"
	defer os.Remove(tmpFile)

	logger, _ := NewLogger(tmpFile)
	logger.AgentStart("agent-002", "test-agent", "docker", "test.yaml")
	logger.FilesystemEvent("agent-002", "test-agent",
		"read", "/tmp/data", "filesystem.read: /tmp", "allowed", true)
	logger.AgentStop("agent-002", "test-agent", 0)
	logger.Close()

	// Tamper with the file — change "allowed" to "denied" in entry 2
	data, _ := os.ReadFile(tmpFile)
	tampered := string(data)

	// Crude tampering — flip one character
	tampered = tampered[:50] + "X" + tampered[51:]
	os.WriteFile(tmpFile, []byte(tampered), 0644)

	// Verify should now fail
	result := VerifyChain(tmpFile)
	if result.Valid {
		t.Error("tampered log should fail verification")
	}
	t.Logf("✅ Tampering correctly detected: %s", result.Error)
}