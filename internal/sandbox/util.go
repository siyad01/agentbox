package sandbox

import (
	"os"
	"strings"
)

// isWSL2 detects if running inside WSL2.
// WSL2 kernel version string always contains "microsoft".
func isWSL2() bool {
	data, err := os.ReadFile("/proc/version")
	if err != nil {
		return false
	}
	return strings.Contains(strings.ToLower(string(data)), "microsoft")
}