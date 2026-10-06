package collect

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os/exec"
	"strconv"
	"strings"
	"time"
)

type JournalEntry struct {
	Timestamp string `json:"__REALTIME_TIMESTAMP"`
	Priority  string `json:"PRIORITY"`
	Unit      string `json:"_SYSTEMD_UNIT"`
	Message   string `json:"MESSAGE"`
}

func (entry JournalEntry) FormattedTimestamp() string {
	microseconds, err := strconv.ParseInt(entry.Timestamp, 10, 64)
	if err != nil || microseconds <= 0 {
		return ""
	}
	return time.UnixMicro(microseconds).Local().Format("2006-01-02 15:04:05")
}

type LogFilter struct {
	ShowInfo    bool
	ShowWarning bool
	ShowError   bool
	Search      string
	Limit       int
}

func RecentLogs(limit string) ([]JournalEntry, error) {
	return RecentLogsFiltered(LogFilter{Limit: parseLimit(limit)})
}

func RecentLogsFiltered(filter LogFilter) ([]JournalEntry, error) {
	limit := filter.Limit
	if limit <= 0 || limit > 500 {
		limit = 200
	}
	cmd := exec.Command("journalctl", "--no-pager", "--output=json", "--lines="+strconv.Itoa(limit))
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("journalctl: %w: %s", err, stderr.String())
	}

	var entries []JournalEntry
	for _, line := range bytes.Split(stdout.Bytes(), []byte{'\n'}) {
		if len(bytes.TrimSpace(line)) == 0 {
			continue
		}
		var entry JournalEntry
		if err := json.Unmarshal(line, &entry); err != nil {
			return nil, fmt.Errorf("parsing journalctl output: %w", err)
		}
		entries = append(entries, entry)
	}
	search := strings.ToLower(strings.TrimSpace(filter.Search))
	filtered := make([]JournalEntry, 0, len(entries))
	for _, entry := range entries {
		if !priorityVisible(entry.Priority, filter) {
			continue
		}
		if search != "" && !strings.Contains(strings.ToLower(entry.Unit), search) && !strings.Contains(strings.ToLower(entry.Message), search) {
			continue
		}
		filtered = append(filtered, entry)
	}
	return filtered, nil
}

func RecentUnitLogs(unit string, limit int) ([]JournalEntry, error) {
	if limit <= 0 || limit > 500 {
		limit = 80
	}
	cmd := exec.Command("journalctl", "--no-pager", "--output=json", "--lines="+strconv.Itoa(limit), "-u", unit)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("journalctl %s: %w: %s", unit, err, stderr.String())
	}
	var entries []JournalEntry
	for _, line := range bytes.Split(stdout.Bytes(), []byte{'\n'}) {
		if len(bytes.TrimSpace(line)) == 0 {
			continue
		}
		var entry JournalEntry
		if err := json.Unmarshal(line, &entry); err != nil {
			return nil, fmt.Errorf("parsing journalctl output: %w", err)
		}
		entries = append(entries, entry)
	}
	return entries, nil
}

func priorityVisible(priority string, filter LogFilter) bool {
	switch priority {
	case "0", "1", "2", "3":
		return filter.ShowError
	case "4":
		return filter.ShowWarning
	case "5", "6", "7":
		return filter.ShowInfo
	default:
		return false
	}
}

func parseLimit(value string) int {
	var limit int
	if _, err := fmt.Sscanf(value, "%d", &limit); err != nil {
		return 200
	}
	return limit
}
