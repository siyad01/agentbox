package api

import (
	"encoding/json"
	"fmt"
	"net/http"
	"time"
	"os"
	"strings"

	"github.com/siyad01/agentbox/internal/audit"
	"github.com/siyad01/agentbox/internal/policy"
	"github.com/siyad01/agentbox/internal/sandbox"
	"github.com/siyad01/agentbox/internal/vault"
)

type Server struct {
	manager *sandbox.Manager
	logger  *audit.Logger
	mux     *http.ServeMux
}

func NewServer(mgr *sandbox.Manager, logger *audit.Logger) *Server {
	s := &Server{
		manager: mgr,
		logger:  logger,
		mux:     http.NewServeMux(),
	}
	s.routes()
	return s
}

func (s *Server) routes() {
	s.mux.HandleFunc("/health",           s.handleHealth)
	s.mux.HandleFunc("/dashboard", s.handleDashboard)
	s.mux.HandleFunc("/api/agents",       s.handleAgents)
	s.mux.HandleFunc("/api/agents/",      s.handleAgent)
	s.mux.HandleFunc("/api/audit",        s.handleAudit)
}

func (s *Server) Start(addr string) error {
	fmt.Printf("🌐 API server listening on http://%s\n", addr)
	return http.ListenAndServe(addr, s.withCORS(s.mux))
}

func (s *Server) withCORS(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods",
			"GET, POST, DELETE, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers",
			"Content-Type, Authorization")
		if r.Method == "OPTIONS" {
			w.WriteHeader(http.StatusOK)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func (s *Server) json(w http.ResponseWriter, code int, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(v)
}

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	s.json(w, http.StatusOK, map[string]interface{}{
		"status":  "ok",
		"service": "agentbox",
		"time":    time.Now().UTC().Format(time.RFC3339),
	})
}

func (s *Server) handleDashboard(w http.ResponseWriter, r *http.Request) {
	// Read dashboard HTML from embedded file
	// In production this would use go:embed
	// For now read from disk relative to binary location
	htmlPath := "dashboard/index.html"
	data, err := os.ReadFile(htmlPath)
	if err != nil {
		http.Error(w, "Dashboard not found", http.StatusNotFound)
		return
	}
	w.Header().Set("Content-Type", "text/html")
	w.Write(data)
}

func (s *Server) handleAgents(w http.ResponseWriter, r *http.Request) {
	
	switch r.Method {

	case http.MethodGet:
		// List all agents
		agents := s.manager.List()
		result := make([]map[string]interface{}, len(agents))
		for i, a := range agents {
			result[i] = map[string]interface{}{
				"id":         a.ID,
				"name":       a.Name,
				"runtime":    a.Runtime,
				"status":     a.Status,
				"started_at": a.StartedAt.Format(time.RFC3339),
				"uptime":     time.Since(a.StartedAt).Round(time.Second).String(),
			}
		}
		s.json(w, http.StatusOK, map[string]interface{}{
			"agents": result,
			"count":  len(result),
		})

	case http.MethodPost:
		// Start a new agent
		var req struct {
			Manifest string   `json:"manifest"` // path to manifest file
			Command  []string `json:"command"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			s.json(w, http.StatusBadRequest, map[string]string{
				"error": "invalid request body",
			})
			return
		}

		m, err := policy.ParseManifest(req.Manifest)
		if err != nil {
			s.json(w, http.StatusBadRequest, map[string]string{
				"error": fmt.Sprintf("invalid manifest: %v", err),
			})
			return
		}

		// Set up vault for credential injection
		var store *vault.Store
		if len(m.Permissions.Credentials) > 0 {
			store, err = vault.NewStore(
				os.Getenv("HOME")+"/.agentbox/vault.json",
				getVaultPassword())
			if err != nil {
				s.json(w, http.StatusInternalServerError, map[string]string{
					"error": "cannot open vault",
				})
				return
			}
		}

		mgr := sandbox.NewManager(s.logger, store)
		agentID, err := mgr.Run(m, req.Command)
		if err != nil {
			s.json(w, http.StatusInternalServerError, map[string]string{
				"error": err.Error(),
			})
			return
		}

		s.json(w, http.StatusCreated, map[string]string{
			"agent_id": agentID,
			"status":   "running",
		})

	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}

func (s *Server) handleAgent(w http.ResponseWriter, r *http.Request) {

	// Extract agent ID from path: /api/agents/{id}
	path  := r.URL.Path
	parts := splitPath(path)
	if len(parts) < 3 {
		s.json(w, http.StatusBadRequest, map[string]string{
			"error": "missing agent ID",
		})
		return
	}
	agentID := parts[2]

	switch r.Method {
	case http.MethodDelete:
		// Kill agent
		if err := s.manager.Kill(agentID, "killed via API"); err != nil {
			s.json(w, http.StatusNotFound, map[string]string{
				"error": err.Error(),
			})
			return
		}
		s.json(w, http.StatusOK, map[string]string{
			"status":   "killed",
			"agent_id": agentID,
		})

	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}

func (s *Server) handleAudit(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}

	logPath   := r.URL.Query().Get("log")
	agentName := r.URL.Query().Get("agent")
	onlyDeny  := r.URL.Query().Get("deny") == "true"
	limitStr  := r.URL.Query().Get("limit")

	if logPath == "" {
		logPath = "agentbox-audit.log"
	}

	limit := 100
	if limitStr != "" {
		fmt.Sscanf(limitStr, "%d", &limit)
	}

	entries, err := audit.Query(logPath, audit.Filter{
		AgentName: agentName,
		OnlyDeny:  onlyDeny,
		Limit:     limit,
	})
	if err != nil {
		// Return empty instead of error if log doesn't exist yet
		s.json(w, http.StatusOK, map[string]interface{}{
			"entries": []audit.Entry{},
			"count":   0,
		})
		return
	}

	s.json(w, http.StatusOK, map[string]interface{}{
		"entries": entries,
		"count":   len(entries),
	})
}

func splitPath(path string) []string {
	var parts []string
	for _, p := range strings.Split(path, "/") {
		if p != "" {
			parts = append(parts, p)
		}
	}
	return parts
}

func getVaultPassword() string {
	if p := os.Getenv("AGENTBOX_VAULT_PASSWORD"); p != "" {
		return p
	}
	return "agentbox-dev-password"
}