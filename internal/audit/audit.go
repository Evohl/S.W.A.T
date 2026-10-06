// Package audit appends one JSON line per privileged action to the SWAT state directory.
package audit

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sync"
	"time"
)

type Entry struct {
	Time   time.Time `json:"time"`
	User   string    `json:"user"`
	Action string    `json:"action"`
	Target string    `json:"target"`
	Result string    `json:"result"`
	Detail string    `json:"detail,omitempty"`
}

var mu sync.Mutex

// Log appends an entry to <dir>/audit.log; failures are returned so callers can refuse the action.
func Log(dir string, entry Entry) error {
	entry.Time = time.Now().UTC()
	data, err := json.Marshal(entry)
	if err != nil {
		return err
	}
	mu.Lock()
	defer mu.Unlock()
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	file, err := os.OpenFile(filepath.Join(dir, "audit.log"), os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	defer file.Close()
	_, err = file.Write(append(data, '\n'))
	return err
}
