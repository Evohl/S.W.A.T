package configwrite

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestApplyOwnedFilesWritesAndUpdatesAtomically(t *testing.T) {
	directory := t.TempDir()
	files := []File{{Name: "10-swat-one.conf", OwnerID: "test/one", Content: []byte(managedMarker + "# SWAT-Config-ID: test/one\nfirst\n")}}
	if err := ApplyOwnedFiles(directory, files, nil); err != nil {
		t.Fatal(err)
	}
	files[0].Content = []byte(managedMarker + "# SWAT-Config-ID: test/one\nsecond\n")
	if err := ApplyOwnedFiles(directory, files, nil); err != nil {
		t.Fatal(err)
	}
	content, err := os.ReadFile(filepath.Join(directory, files[0].Name))
	if err != nil {
		t.Fatal(err)
	}
	if string(content) != string(files[0].Content) {
		t.Fatalf("file content = %q, want %q", content, files[0].Content)
	}
}

func TestApplyOwnedFilesRefusesForeignFileAndDoesNotPartiallyWrite(t *testing.T) {
	directory := t.TempDir()
	foreign := filepath.Join(directory, "20-local.conf")
	if err := os.WriteFile(foreign, []byte("# user-owned\nkeep\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	err := ApplyOwnedFiles(directory, []File{
		{Name: "10-swat.conf", OwnerID: "test/first", Content: []byte(managedMarker + "# SWAT-Config-ID: test/first\ngenerated\n")},
		{Name: "20-local.conf", OwnerID: "test/local", Content: []byte(managedMarker + "# SWAT-Config-ID: test/local\nmust-not-write\n")},
	}, nil)
	if err == nil || !strings.Contains(err.Error(), "fremde oder anders verwaltete Datei") {
		t.Fatalf("ApplyOwnedFiles error = %v, want foreign-file refusal", err)
	}
	if _, err := os.Stat(filepath.Join(directory, "10-swat.conf")); !os.IsNotExist(err) {
		t.Fatalf("write started before all targets were checked: stat error %v", err)
	}
	content, err := os.ReadFile(foreign)
	if err != nil || string(content) != "# user-owned\nkeep\n" {
		t.Fatalf("foreign file changed: content=%q error=%v", content, err)
	}
}

func TestApplyOwnedFilesRemovesOnlyOwnedFiles(t *testing.T) {
	directory := t.TempDir()
	name := "10-swat-old.conf"
	path := filepath.Join(directory, name)
	if err := os.WriteFile(path, []byte(managedMarker+"# SWAT-Config-ID: test/old\nold\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := ApplyOwnedFiles(directory, nil, []Removal{{Name: name, OwnerID: "test/old"}}); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("owned stale file still exists: %v", err)
	}
}

func TestApplyOwnedFilesRejectsUnsafeNames(t *testing.T) {
	for _, name := range []string{"../outside.conf", "/etc/owned.conf", "subdir/file.conf", ".."} {
		t.Run(name, func(t *testing.T) {
			err := ApplyOwnedFiles(t.TempDir(), []File{{Name: name, OwnerID: "test/file", Content: []byte(managedMarker + "# SWAT-Config-ID: test/file\n")}}, nil)
			if err == nil {
				t.Fatal("unsafe filename accepted")
			}
		})
	}
}

func TestApplyOwnedFilesRefusesMismatchedOwnerID(t *testing.T) {
	directory := t.TempDir()
	path := filepath.Join(directory, "10-swat.conf")
	if err := os.WriteFile(path, []byte(managedMarker+"# SWAT-Config-ID: service/one\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	err := ApplyOwnedFiles(directory, []File{{Name: "10-swat.conf", OwnerID: "service/two", Content: []byte(managedMarker + "# SWAT-Config-ID: service/two\n")}}, nil)
	if err == nil || !strings.Contains(err.Error(), "anders verwaltete Datei") {
		t.Fatalf("ApplyOwnedFiles error = %v, want mismatched-owner refusal", err)
	}
}
