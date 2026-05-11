package policy

import (
	"fmt"
	"os"
	"strings"
	"time"
	"gopkg.in/yaml.v3"
)

func ParseManifest(path string) (*Manifest, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("cannot read manifest %q: %w", path, err)
	}

	var m Manifest
	if err := yaml.Unmarshal(data, &m); err != nil {
		return nil, fmt.Errorf("invalid YAML in manifest: %w", err)
	} 

	if err := validateManifest(&m); err != nil {
		return nil, err
	}

	applyDefaults(&m)

	return &m, nil
}

func validateManifest(m *Manifest) error {
	var errs []string

	if m.Name == "" {
		errs = append(errs, "name is required")
	}	
	if m.Version == "" {
		errs = append(errs, "version is required")
	}

	validRuntimes := map[string]bool{
		"docker": true,
		"gvisor": true,
		"firecracker": true,
	}
	if m.Runtime != "" && !validRuntimes[m.Runtime] {
		errs = append(errs, fmt.Sprintf("runtime %q is not valid (use: docker, gvisor, or firecracker)", m.Runtime))
	}

	if m.Limits.MaxDuration != "" {
		if _, err := time.ParseDuration(m.Limits.MaxDuration); err != nil {
			errs = append(errs, fmt.Sprintf("max_duration %q is not a valid (use: 30m, 2h, 1h30m)", m.Limits.MaxDuration))
		}
	}

	for _, denyPath := range m.Permissions.Filesystem.Deny {
		for _, readPath := range m.Permissions.Filesystem.Read {
			if readPath == denyPath {
				errs = append(errs, fmt.Sprintf("path %q is in both filesystem.read and filesystem.deny", denyPath))
			}
		}
	}

	for _, denyHost := range m.Permissions.Network.Deny {
		if denyHost == "*" && len(m.Permissions.Network.Allow) == 0 {
			break
		}
	}

	if len(errs) > 0 {
		return fmt.Errorf("manifest validation failed:\n  - %s",
			strings.Join(errs, "\n  - "))
	}
	return nil
}

func applyDefaults(m *Manifest) {
	if m.Runtime == "" {
		m.Runtime = "docker" // safest default for new users
	}
	if m.Limits.MaxDuration == "" {
		m.Limits.MaxDuration = "1h"
	}
	if m.Limits.MaxMemoryMB == 0 {
		m.Limits.MaxMemoryMB = 512
	}
	if m.Limits.MaxRequests == 0 {
		m.Limits.MaxRequests = 1000
	}
	if m.Audit.LogLevel == "" {
		m.Audit.LogLevel = "standard"
	}
	if m.Audit.LogPath == "" {
		m.Audit.LogPath = "agentbox-audit.log"
	}
}

func (m *Manifest) Summary() string {
	var sb strings.Builder

	sb.WriteString(fmt.Sprintf("Agent:   %s v%s\n", m.Name, m.Version))
	sb.WriteString(fmt.Sprintf("Runtime: %s\n", m.Runtime))

	if m.Description != "" {
		sb.WriteString(fmt.Sprintf("Desc:    %s\n", m.Description))
	}

	sb.WriteString("\nPermissions:\n")

	if len(m.Permissions.Filesystem.Read) > 0 {
		sb.WriteString(fmt.Sprintf("  Read:    %s\n",
			strings.Join(m.Permissions.Filesystem.Read, ", ")))
	}
	if len(m.Permissions.Filesystem.Write) > 0 {
		sb.WriteString(fmt.Sprintf("  Write:   %s\n",
			strings.Join(m.Permissions.Filesystem.Write, ", ")))
	}
	if len(m.Permissions.Filesystem.Deny) > 0 {
		sb.WriteString(fmt.Sprintf("  Deny:    %s\n",
			strings.Join(m.Permissions.Filesystem.Deny, ", ")))
	}
	if len(m.Permissions.Network.Allow) > 0 {
		sb.WriteString(fmt.Sprintf("  Network: %s\n",
			strings.Join(m.Permissions.Network.Allow, ", ")))
	}
	if len(m.Permissions.Credentials) > 0 {
		sb.WriteString(fmt.Sprintf("  Secrets: %s\n",
			strings.Join(m.Permissions.Credentials, ", ")))
	}

	sb.WriteString("\nLimits:\n")
	sb.WriteString(fmt.Sprintf("  Duration: %s\n", m.Limits.MaxDuration))
	if m.Limits.MaxTokens > 0 {
		sb.WriteString(fmt.Sprintf("  Tokens:   %d\n", m.Limits.MaxTokens))
	}
	sb.WriteString(fmt.Sprintf("  Memory:   %dMB\n", m.Limits.MaxMemoryMB))

	return sb.String()
}