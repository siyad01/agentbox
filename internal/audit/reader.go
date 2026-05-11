package audit

import (
	"bufio"
	"encoding/json"
	"os"
	"strings"
	"time"
)

type Filter struct {
	AgentID string
	AgentName string
	EventType EventType
	OnlyDeny bool
	Since time.Time
	Limit int
}

func Query(logPath string, f Filter) ([]Entry, error) {
	file, err := os.Open(logPath)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var results []Entry
	scanner := bufio.NewScanner(file)
	scanner.Buffer(make([]byte, 1024*1024), 1024*1024)

	for scanner.Scan() {
		line := scanner.Text()
		if line == "" {
			continue
		}

		var entry Entry 
		if err := json.Unmarshal([]byte(line), &entry); err != nil {
			continue
		}

		if f.AgentID != "" && entry.AgentID != f.AgentID {
			continue
		}

		if f.AgentName != "" &&
			!strings.Contains(entry.AgentName, f.AgentName) {
			continue
		}
		if f.EventType != "" && entry.EventType != f.EventType {
			continue
		}
		if f.OnlyDeny && entry.Allowed {
			continue
		}
		if !f.Since.IsZero() {
			entryTime, err := time.Parse(time.RFC3339Nano, entry.Timestamp)
			if err != nil || entryTime.Before(f.Since) {
				continue
			}
		}

		results = append(results, entry)

		if f.Limit > 0 && len(results) >= f.Limit {
			break
		}
	}
	return results, scanner.Err()
}