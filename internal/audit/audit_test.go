package audit

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLogCreatesGroupWritableInternalAuditFile(t *testing.T) {
	dir := t.TempDir()
	if err := Log(dir, Entry{User: "admin", Action: "test", Target: "setting", Result: "ok"}); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(filepath.Join(dir, "audit.log"))
	if err != nil {
		t.Fatal(err)
	}
	if got := info.Mode().Perm(); got != 0o660 {
		t.Fatalf("audit log mode = %04o, want 0660", got)
	}
}
