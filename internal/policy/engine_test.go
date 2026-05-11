package policy

import (
	"testing"
)

func buildTestManifest() *Manifest {
	return &Manifest{
		Name: "test-agent",
		Version: "1.0.0",
		Runtime: "docker",
		Permissions: Permissions{
			Filesystem: FilesystemPerms{
				Read:  []string{"/home/user/documents", "/tmp/agent"},
				Write: []string{"/home/user/output"},
				Deny:  []string{"/home/user/.ssh", "/etc"},
			},
			Network: NetworkPerms{
				Allow: []string{"api.anthropic.com", "*.googleapis.com"},
				Deny:  []string{"169.254.169.254"}, // block AWS metadata
			},
			Tools: ToolPerms{
				Allow: []string{"read_file", "write_file", "list_*"},
				Deny:  []string{"execute_shell", "*_delete"},
			},
			Credentials:  []string{"ANTHROPIC_API_KEY"},
		},
		Limits: Limits{
			MaxDuration: "30m",
			MaxMemoryMB: 256,
		},
		Audit: AuditConfig{
			LogLevel: "full",
			AlertOn: []string{"filesystem_deny", "network_deny"},
		},
	}
}

func TestFilesystem_AllowedRead(t *testing.T) {
	e := NewEngine(buildTestManifest())
	d := e.CheckFilesystem("read", "/home/user/documents/report.pdf")
	if !d.Allowed {
		t.Errorf("expected ALLOW, got DENY: %s", d.Reason)
	}
}

func TestFilesystem_DeniedSsh(t *testing.T) {
	e := NewEngine(buildTestManifest())
	d := e.CheckFilesystem("read", "/home/user/.ssh/id_rsa")
	if d.Allowed {
		t.Errorf("expected DENY for .ssh, got ALLOW: %s", d.Reason)
	}
}

func TestFilesystem_denyOverridesREad(t *testing.T) {
	m := buildTestManifest()
	m.Permissions.Filesystem.Read = append(m.Permissions.Filesystem.Read, "/home/user/.ssh")
	e := NewEngine(m)
	d := e.CheckFilesystem("read", "/home/user/.ssh/id_rsa")
	if d.Allowed {
		t.Errorf("deny should override read allow: %s", d.Reason)
	}
}

func TestFilesystem_NotInAllowList(t *testing.T) {
	e := NewEngine(buildTestManifest())
	d := e.CheckFilesystem("read", "/home/user/secret-notes.txt")
	if d.Allowed {
		t.Errorf("expected DENY for path not in allow list: %s", d.Reason)
	}
}

func TestFilesystem_WriteAllowed(t *testing.T) {
	e := NewEngine(buildTestManifest())
	d := e.CheckFilesystem("write", "/home/user/output/result.json")
	if !d.Allowed {
		t.Errorf("expected ALLOW for write: %s", d.Reason)
	}
}

func TestFilesystem_WriteNotAllowed(t *testing.T) {
	e := NewEngine(buildTestManifest())
	d := e.CheckFilesystem("write", "/home/user/documents/system.cfg")
	if d.Allowed {
		t.Errorf("expected DENY: documents is read-only: %s", d.Reason)
	}
}

// ── Network tests ─────────────────────────────────────────

func TestNetwork_AllowedHost(t *testing.T) {
	e := NewEngine(buildTestManifest())
	d := e.CheckNetwork("api.anthropic.com")
	if !d.Allowed {
		t.Errorf("expected ALLOW: %s", d.Reason)
	}
}

func TestNetwork_WildcardSubdomain(t *testing.T) {
	e := NewEngine(buildTestManifest())
	d := e.CheckNetwork("gmail.googleapis.com")
	if !d.Allowed {
		t.Errorf("expected ALLOW for wildcard subdomain: %s", d.Reason)
	}
}

func TestNetwork_BlockedMetadata(t *testing.T) {
	e := NewEngine(buildTestManifest())
	// 169.254.169.254 is the AWS metadata endpoint — common attack target
	d := e.CheckNetwork("169.254.169.254")
	if d.Allowed {
		t.Errorf("expected DENY for metadata endpoint: %s", d.Reason)
	}
}

func TestNetwork_UnknownHost(t *testing.T) {
	e := NewEngine(buildTestManifest())
	d := e.CheckNetwork("evil.attacker.com")
	if d.Allowed {
		t.Errorf("expected DENY for unknown host: %s", d.Reason)
	}
}

func TestNetwork_PortStripped(t *testing.T) {
	e := NewEngine(buildTestManifest())
	// Port should be stripped before matching
	d := e.CheckNetwork("api.anthropic.com:443")
	if !d.Allowed {
		t.Errorf("expected ALLOW with port number: %s", d.Reason)
	}
}

// ── Tool tests ────────────────────────────────────────────

func TestTool_AllowedExact(t *testing.T) {
	e := NewEngine(buildTestManifest())
	d := e.CheckTool("read_file")
	if !d.Allowed {
		t.Errorf("expected ALLOW: %s", d.Reason)
	}
}

func TestTool_AllowedWildcard(t *testing.T) {
	e := NewEngine(buildTestManifest())
	// list_* should match list_files, list_directories
	d := e.CheckTool("list_files")
	if !d.Allowed {
		t.Errorf("expected ALLOW for list_* wildcard: %s", d.Reason)
	}
}

func TestTool_DeniedShell(t *testing.T) {
	e := NewEngine(buildTestManifest())
	d := e.CheckTool("execute_shell")
	if d.Allowed {
		t.Errorf("expected DENY for execute_shell: %s", d.Reason)
	}
}

func TestTool_DeniedDeleteWildcard(t *testing.T) {
	e := NewEngine(buildTestManifest())
	// *_delete should block file_delete, dir_delete, everything_delete
	d := e.CheckTool("file_delete")
	if d.Allowed {
		t.Errorf("expected DENY for *_delete wildcard: %s", d.Reason)
	}
}

func TestTool_DeniedUnknown(t *testing.T) {
	e := NewEngine(buildTestManifest())
	d := e.CheckTool("unknown_tool")
	if d.Allowed {
		t.Errorf("expected DENY for unknown tool: %s", d.Reason)
	}
}

// ── Credential tests ──────────────────────────────────────

func TestCredential_Allowed(t *testing.T) {
	e := NewEngine(buildTestManifest())
	d := e.CheckCredential("ANTHROPIC_API_KEY")
	if !d.Allowed {
		t.Errorf("expected ALLOW: %s", d.Reason)
	}
}

func TestCredential_NotDeclared(t *testing.T) {
	e := NewEngine(buildTestManifest())
	d := e.CheckCredential("AWS_SECRET_KEY")
	if d.Allowed {
		t.Errorf("expected DENY for undeclared credential: %s", d.Reason)
	}
}

// ── Alert tests ───────────────────────────────────────────

func TestShouldAlert_Matching(t *testing.T) {
	e := NewEngine(buildTestManifest())
	if !e.ShouldAlert("filesystem_deny") {
		t.Error("expected filesystem_deny to trigger alert")
	}
}

func TestShouldAlert_NotMatching(t *testing.T) {
	e := NewEngine(buildTestManifest())
	if e.ShouldAlert("token_budget_80pct") {
		t.Error("token_budget_80pct not in alert_on list")
	}
}