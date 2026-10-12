package modules

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

func StatePath(directory string) string {
	return filepath.Join(directory, "modules.json")
}

func loadSelection(path string) (Selection, error) {
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return Selection{Version: CurrentVersion}, nil
	}
	if err != nil {
		return Selection{}, err
	}
	var selection Selection
	if err := json.Unmarshal(data, &selection); err != nil {
		return Selection{}, fmt.Errorf("Modulauswahl ist ungültig: %w", err)
	}
	if selection.Version != CurrentVersion {
		return Selection{}, fmt.Errorf("nicht unterstützte Modulzustandsversion %d", selection.Version)
	}
	normalized, err := NormalizeSelection(selection.Selected)
	if err != nil {
		return Selection{}, err
	}
	selection.Selected = normalized
	return selection, nil
}

func saveSelection(path string, selection Selection) error {
	data, err := json.MarshalIndent(selection, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	temporary, err := os.CreateTemp(filepath.Dir(path), ".modules-*.tmp")
	if err != nil {
		return err
	}
	defer os.Remove(temporary.Name())
	if err := temporary.Chmod(0o600); err != nil {
		temporary.Close()
		return err
	}
	if _, err := temporary.Write(data); err != nil {
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
	return os.Rename(temporary.Name(), path)
}
