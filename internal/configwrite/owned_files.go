package configwrite
// Package configwrite provides ownership-checked atomic writes for generated
// configuration files. Callers must use a fixed service-owned directory and
// must never derive it from request data.

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

const managedMarker = "# Managed-By: SWAT\n"

type File struct {
	Name    string
	OwnerID string
	Content []byte
	Mode    fs.FileMode
}

type Removal struct {
	Name    string
	OwnerID string
}

type snapshot struct {
	content []byte
	mode    fs.FileMode
	exists  bool
}

// ApplyOwnedFiles writes generated files and removes stale files only when SWAT owns them.
func ApplyOwnedFiles(directory string, files []File, remove []Removal) error {
	info, err := os.Lstat(directory)
	if err != nil {
		return fmt.Errorf("Konfigurationsverzeichnis %s: %w", directory, err)
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("Konfigurationsziel %s ist kein normales Verzeichnis", directory)
	}

	writes := make(map[string]File, len(files))
	for _, file := range files {
		if !validName(file.Name) {
			return fmt.Errorf("ungültiger Konfigurationsdateiname %q", file.Name)
		}
		if !validOwnerID(file.OwnerID) {
			return fmt.Errorf("ungültige SWAT-Config-ID für %s", file.Name)
		}
		if !hasOwnership(file.Content, file.OwnerID) {
			return fmt.Errorf("Datei %s hat keinen passenden SWAT-Eigentumsnachweis", file.Name)
		}
		if file.Mode == 0 {
			file.Mode = 0o644
		}
		if file.Mode.Perm() != file.Mode {
			return fmt.Errorf("ungültige Dateirechte für %s", file.Name)
		}
		if _, exists := writes[file.Name]; exists {
			return fmt.Errorf("Datei %s ist mehrfach angegeben", file.Name)
		}
		writes[file.Name] = file
	}

	removals := make(map[string]Removal, len(remove))
	for _, removal := range remove {
		if !validName(removal.Name) {
			return fmt.Errorf("ungültiger Konfigurationsdateiname %q", removal.Name)
		}
		if !validOwnerID(removal.OwnerID) {
			return fmt.Errorf("ungültige SWAT-Config-ID für %s", removal.Name)
		}
		if _, exists := writes[removal.Name]; exists {
			return fmt.Errorf("Datei %s kann nicht gleichzeitig geschrieben und entfernt werden", removal.Name)
		}
		if _, exists := removals[removal.Name]; exists {
			return fmt.Errorf("Datei %s ist mehrfach zum Entfernen angegeben", removal.Name)
		}
		removals[removal.Name] = removal
	}

	allNames := make([]string, 0, len(writes)+len(removals))
	for name := range writes {
		allNames = append(allNames, name)
	}
	for name := range removals {
		allNames = append(allNames, name)
	}
	sort.Strings(allNames)
	previous := make(map[string]snapshot, len(allNames))
	for _, name := range allNames {
		ownerID := ""
		if file, exists := writes[name]; exists {
			ownerID = file.OwnerID
		} else {
			ownerID = removals[name].OwnerID
		}
		state, err := inspectOwnedFile(filepath.Join(directory, name), ownerID)
		if err != nil {
			return fmt.Errorf("Datei %s: %w", name, err)
		}
		if _, removing := removals[name]; removing && !state.exists {
			return fmt.Errorf("SWAT-Datei %s zum Entfernen nicht gefunden", name)
		}
		previous[name] = state
	}

	changed := make([]string, 0, len(allNames))
	for _, name := range allNames {
		if file, exists := writes[name]; exists {
			err = writeAtomic(directory, name, file.Content, file.Mode)
		} else {
			err = os.Remove(filepath.Join(directory, name))
		}
		if err != nil {
			rollbackErr := rollbackFiles(directory, changed, previous)
			if rollbackErr != nil {
				return fmt.Errorf("Änderung von %s fehlgeschlagen: %w; Rollback fehlgeschlagen: %v", name, err, rollbackErr)
			}
			return fmt.Errorf("Änderung von %s fehlgeschlagen: %w", name, err)
		}
		changed = append(changed, name)
	}
	return nil
}

func validOwnerID(ownerID string) bool {
	if ownerID == "" || len(ownerID) > 128 || strings.Contains(ownerID, "..") {
		return false
	}
	for _, character := range ownerID {
		if character != '/' && character != '-' && character != '_' && (character < 'a' || character > 'z') && (character < 'A' || character > 'Z') && (character < '0' || character > '9') {
			return false
		}
	}
	return true
}

func hasOwnership(content []byte, ownerID string) bool {
	if !strings.HasPrefix(string(content), managedMarker) {
		return false
	}
	wanted := "# SWAT-Config-ID: " + ownerID
	for _, line := range strings.Split(string(content), "\n") {
		if line == wanted {
			return true
		}
	}
	return false
}

func validName(name string) bool {
	return name != "" && name != "." && name != ".." && !filepath.IsAbs(name) && filepath.Base(name) == name && !strings.ContainsAny(name, `/\`)
}

func inspectOwnedFile(path, ownerID string) (snapshot, error) {
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return snapshot{}, nil
	}
	if err != nil {
		return snapshot{}, err
	}
	if !info.Mode().IsRegular() {
		return snapshot{}, fmt.Errorf("ist keine reguläre Datei; SWAT überschreibt keine fremden Ziele")
	}
	content, err := os.ReadFile(path)
	if err != nil {
		return snapshot{}, err
	}
	if !hasOwnership(content, ownerID) {
		return snapshot{}, fmt.Errorf("fremde oder anders verwaltete Datei; SWAT überschreibt sie nicht")
	}
	return snapshot{content: content, mode: info.Mode().Perm(), exists: true}, nil
}

func writeAtomic(directory, name string, content []byte, mode fs.FileMode) error {
	temporary, err := os.CreateTemp(directory, ".swat-config-*")
	if err != nil {
		return err
	}
	temporaryPath := temporary.Name()
	defer os.Remove(temporaryPath)
	if err := temporary.Chmod(mode); err != nil {
		temporary.Close()
		return err
	}
	if _, err := temporary.Write(content); err != nil {
		temporary.Close()
		return err
	}
	if err := temporary.Sync(); err != nil {
		temporary.Close()
		return err
	}
	if err := temporary.Close(); err != nil {
		return err
	}
	return os.Rename(temporaryPath, filepath.Join(directory, name))
}

func rollbackFiles(directory string, changed []string, previous map[string]snapshot) error {
	var failures []error
	for i := len(changed) - 1; i >= 0; i-- {
		name := changed[i]
		state := previous[name]
		var err error
		if state.exists {
			err = writeAtomic(directory, name, state.content, state.mode)
		} else {
			err = os.Remove(filepath.Join(directory, name))
			if errors.Is(err, os.ErrNotExist) {
				err = nil
			}
		}
		if err != nil {
			failures = append(failures, fmt.Errorf("%s: %w", name, err))
		}
	}
	return errors.Join(failures...)
}
