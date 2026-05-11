package audit

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
)

type VerifyResult struct {
	Valid        bool
	TotalEntries int
	FirstID      uint64
	LastID       uint64
	Error        string // set if Valid is false
	TamperedAt   uint64
}

func VerifyChain(logPath string) VerifyResult {

	f, err := os.Open(logPath)
	if err != nil {
		return VerifyResult{
			Error: fmt.Sprintf("cannot open log: %v", err),
		}
	}

	defer f.Close()
	var (
		prevHash = "genesis"
		count = 0
		firstID uint64
		lastID uint64

	)

	tmpLogger := &Logger{}

	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 1024*1024), 1024*1024)

	for scanner.Scan() {
		line := scanner.Text()
		if line == "" {
			continue
		}

		var entry Entry
		if err := json.Unmarshal([]byte(line), &entry); err != nil {
			return VerifyResult{
				Error: fmt.Sprintf("cannot parse entry: %v", err),
				TamperedAt: lastID + 1,
			}
		}

		if entry.PrevHash != prevHash {
			return VerifyResult{
				Valid:        false,
				TotalEntries: count,
				FirstID:      firstID,
				LastID:       lastID,
				TamperedAt:   entry.ID,
				Error: fmt.Sprintf(
					"chain broken at entry %d: expected prev_hash %q, got %q",
					entry.ID, prevHash, entry.PrevHash),
			}
		}

		storedHash := entry.Hash
		computed := tmpLogger.computeHash(entry)

		if storedHash != computed {
			return VerifyResult{
				Valid:        false,
				TotalEntries: count,
				TamperedAt:   entry.ID,
				Error: fmt.Sprintf(
					"entry %d hash mismatch: stored=%q computed=%q",
					entry.ID, storedHash, computed),
			}
		}

		prevHash = entry.Hash
		count++
		lastID = entry.ID
		if count == 1 {
			firstID = entry.ID
		}
	}

	if err := scanner.Err(); err != nil {
		return VerifyResult{Error: fmt.Sprintf("scan error: %v", err)}
	}

	return VerifyResult{
		Valid:        true,
		TotalEntries: count,
		FirstID:      firstID,
		LastID:       lastID,
	}
}