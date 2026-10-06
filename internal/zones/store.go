package zones

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
)

const configFile = "zones.json"

// StateDir is where SWAT keeps its desired state, applied scripts, and audit log.
func StateDir() string {
	if dir := os.Getenv("SWAT_STATE_DIR"); dir != "" {
		return dir
	}
	if home, err := os.UserHomeDir(); err == nil {
		return filepath.Join(home, ".local", "state", "swat")
	}
	return filepath.Join(os.TempDir(), "swat")
}

// Load returns the saved config; a missing file yields an empty config.
func Load(dir string) (Config, error) {
	data, err := os.ReadFile(filepath.Join(dir, configFile))
	if errors.Is(err, os.ErrNotExist) {
		return Config{}, nil
	}
	if err != nil {
		return Config{}, err
	}
	var cfg Config
	if err := json.Unmarshal(data, &cfg); err != nil {
		return Config{}, err
	}
	for i := range cfg.Zones {
		if cfg.Zones[i].Ping && !cfg.Zones[i].HasService(PingService) {
			cfg.Zones[i].Services = append(cfg.Zones[i].Services, PingService)
		}
		cfg.Zones[i].Ping = false
	}
	return cfg, nil
}

// Save validates and atomically writes the config.
func Save(dir string, cfg Config) error {
	if err := cfg.Validate(); err != nil {
		return err
	}
	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return err
	}
	return WriteFileAtomic(filepath.Join(dir, configFile), data)
}

// WriteFileAtomic writes via a temp file and rename, creating the directory with mode 0700.
func WriteFileAtomic(path string, data []byte) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".tmp-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), path)
}
