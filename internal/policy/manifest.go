package policy

type Manifest struct {
	Name string `yaml:"name"`
	Version string `yaml:"version"`
	Description string `yaml:"description"`
	Runtime string `yaml:"runtime"`
	Permissions Permissions `yaml:"permissions"`
	Limits Limits `yaml:"limits"`
	Audit AuditConfig `yaml:"audit"`
}

type Permissions struct {
	Filesystem FilesystemPerms `yaml:"filesystem"`
	Network NetworkPerms `yaml:"network"`
	Tools ToolPerms `yaml:"tools"`
	Credentials []string `yaml:"credentials"`
}

type FilesystemPerms struct {
	Read []string `yaml:"read"`
	Write []string `yaml:"write"`
	Deny []string `yaml:"deny"`
}

type NetworkPerms struct {
	Allow []string `yaml:"allow"`
	Deny []string `yaml:"deny"`
}

type ToolPerms struct {
	Allow []string `yaml:"allow"`
	Deny []string `yaml:"deny"`
}

type Limits struct {
	MaxTokens int `yaml:"max_tokens"`
	MaxDuration string `yaml:"max_duration"`
	MaxFiles int `yaml:"max_files"`
	MaxRequests int `yaml:"max_requests"`
	MaxMemoryMB int `yaml:"max_memory_mb"`
}

type AuditConfig struct {
	LogLevel string `yaml:"log_level"`
	AlertOn []string `yaml:"alert_on"`
	LogPath string `yaml:"log_path"`
}