package netcfg

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"swat/internal/configwrite"
)

type InterfaceNameBinding struct {
	PermanentMAC string `json:"permanent_mac"`
	Name         string `json:"name"`
}

type InterfaceNameConfig struct {
	Version    int                    `json:"version"`
	Interfaces []InterfaceNameBinding `json:"interfaces"`
}

var stableInterfaceNamePattern = regexp.MustCompile(`^[A-Za-z0-9_-]{1,15}$`)
var legacyKernelInterfaceNamePattern = regexp.MustCompile(`^(eth|wlan)[0-9]+$`)

// GenerateInterfaceLinks creates one early-boot systemd.link file per permanent MAC.
func GenerateInterfaceLinks(bindings []InterfaceNameBinding) (map[string][]byte, error) {
	files := make(map[string][]byte, len(bindings))
	macOwners := make(map[string]string, len(bindings))
	nameOwners := make(map[string]string, len(bindings))
	for _, binding := range bindings {
		mac, err := net.ParseMAC(strings.TrimSpace(binding.PermanentMAC))
		if err != nil || len(mac) != 6 || mac[0]&1 != 0 || bytes.Equal(mac, make([]byte, 6)) {
			return nil, fmt.Errorf("ungültige permanente Ethernet-MAC-Adresse %q", binding.PermanentMAC)
		}
		canonicalMAC := strings.ToLower(mac.String())
		if !stableInterfaceNamePattern.MatchString(binding.Name) || isNumericInterfaceName(binding.Name) || binding.Name == "all" || binding.Name == "default" {
			return nil, fmt.Errorf("ungültiger Interface-Name %q (1 bis 15 ASCII-Zeichen; keine rein numerischen Namen)", binding.Name)
		}
		if legacyKernelInterfaceNamePattern.MatchString(binding.Name) {
			return nil, fmt.Errorf("Interface-Name %q kann mit Kernel-Namen kollidieren; verwenden Sie zum Beispiel lan0 oder wan0", binding.Name)
		}
		if owner, exists := macOwners[canonicalMAC]; exists {
			return nil, fmt.Errorf("MAC-Adresse %s ist bereits Interface %s zugewiesen", canonicalMAC, owner)
		}
		if owner, exists := nameOwners[binding.Name]; exists {
			return nil, fmt.Errorf("Interface-Name %s ist bereits MAC-Adresse %s zugewiesen", binding.Name, owner)
		}
		macOwners[canonicalMAC] = binding.Name
		nameOwners[binding.Name] = canonicalMAC
	}

	macs := make([]string, 0, len(macOwners))
	for mac := range macOwners {
		macs = append(macs, mac)
	}
	sort.Strings(macs)
	for _, mac := range macs {
		name := macOwners[mac]
		fileName := "10-swat-nic-" + strings.ReplaceAll(mac, ":", "-") + ".link"
		content := fmt.Sprintf("# Managed-By: SWAT\n# SWAT-Config-ID: %s\n[Match]\nPermanentMACAddress=%s\n[Link]\nNamePolicy=\nName=%s\n", interfaceLinkOwnerID(mac), mac, name)
		files[fileName] = []byte(content)
	}
	return files, nil
}

func LoadInterfaceNameBindings(path string) ([]InterfaceNameBinding, error) {
	data, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var config InterfaceNameConfig
	if err := json.Unmarshal(data, &config); err != nil {
		return nil, fmt.Errorf("Netzwerknamens-Konfiguration ist ungültig: %w", err)
	}
	if config.Version != 1 {
		return nil, fmt.Errorf("nicht unterstützte Version der Netzwerknamens-Konfiguration")
	}
	if _, err := GenerateInterfaceLinks(config.Interfaces); err != nil {
		return nil, err
	}
	return config.Interfaces, nil
}

func SaveInterfaceNameBindings(path string, bindings []InterfaceNameBinding) error {
	if _, err := GenerateInterfaceLinks(bindings); err != nil {
		return err
	}
	data, err := json.MarshalIndent(InterfaceNameConfig{Version: 1, Interfaces: bindings}, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	temporary, err := os.CreateTemp(filepath.Dir(path), ".network-names-*.tmp")
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

// WriteInterfaceLinks applies SWAT-owned .link files without activating a live rename.
func WriteInterfaceLinks(directory string, bindings []InterfaceNameBinding) error {
	generated, err := GenerateInterfaceLinks(bindings)
	if err != nil {
		return err
	}
	files := make([]configwrite.File, 0, len(generated))
	for name, content := range generated {
		ownerID := strings.TrimSuffix(strings.TrimPrefix(name, "10-swat-nic-"), ".link")
		files = append(files, configwrite.File{Name: name, OwnerID: interfaceLinkOwnerID(strings.ReplaceAll(ownerID, "-", ":")), Content: content, Mode: 0o644})
	}

	entries, err := os.ReadDir(directory)
	if err != nil {
		return fmt.Errorf("systemd-Link-Verzeichnis konnte nicht gelesen werden: %w", err)
	}
	keep := make(map[string]bool, len(generated))
	for name := range generated {
		keep[name] = true
	}
	var stale []configwrite.Removal
	for _, entry := range entries {
		name := entry.Name()
		if entry.IsDir() || !strings.HasPrefix(name, "10-swat-nic-") || !strings.HasSuffix(name, ".link") || keep[name] {
			continue
		}
		ownerID := strings.TrimSuffix(strings.TrimPrefix(name, "10-swat-nic-"), ".link")
		mac, parseErr := net.ParseMAC(strings.ReplaceAll(ownerID, "-", ":"))
		if parseErr != nil || len(mac) != 6 || strings.ToLower(mac.String()) != strings.ReplaceAll(strings.ToLower(ownerID), "-", ":") {
			return fmt.Errorf("unerwarteter SWAT-NIC-Dateiname %q; Datei wird nicht entfernt", name)
		}
		stale = append(stale, configwrite.Removal{Name: name, OwnerID: interfaceLinkOwnerID(mac.String())})
	}
	if err := configwrite.ApplyOwnedFiles(filepath.Clean(directory), files, stale); err != nil {
		return fmt.Errorf("systemd-Link-Dateien konnten nicht geschrieben werden: %w", err)
	}
	return nil
}

func interfaceLinkOwnerID(mac string) string {
	return "network/interface/" + strings.ReplaceAll(strings.ToLower(mac), ":", "-")
}

func isNumericInterfaceName(name string) bool {
	for _, character := range name {
		if character < '0' || character > '9' {
			return false
		}
	}
	return name != ""
}
