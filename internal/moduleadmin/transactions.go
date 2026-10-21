package moduleadmin

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"swat/internal/audit"
	"swat/internal/netcfg"
	"swat/internal/zones"
)

const (
	networkdDirectory = "/etc/systemd/network"
	nftablesPath      = "/etc/swat/swat.nft"
	transactionWindow = 60 * time.Second
)

type fileSnapshot struct {
	content []byte
	exists  bool
}

type pendingNetwork struct {
	files    map[string]fileSnapshot
	links    []string
	config   []byte
	deadline time.Time
	timer    *time.Timer
	user     string
}

type pendingFirewall struct {
	previous string
	current  string
	deadline time.Time
	timer    *time.Timer
	user     string
}

func (installer *Installer) ApplyBridgeConfig(ctx context.Context, configJSON, previousJSON, username string) (Response, error) {
	installer.mu.Lock()
	defer installer.mu.Unlock()
	if installer.Run == nil {
		installer.Run = SystemRunner
	}
	if installer.networkPending != nil {
		return Response{}, errors.New("Eine Netzwerkänderung wartet bereits auf Bestätigung oder Rücknahme.")
	}
	var config netcfg.Config
	if err := json.Unmarshal([]byte(configJSON), &config); err != nil {
		return Response{}, fmt.Errorf("Ungültige Bridge-Konfiguration: %w", err)
	}
	var previousConfig netcfg.Config
	if previousJSON != "" {
		if err := json.Unmarshal([]byte(previousJSON), &previousConfig); err != nil {
			return Response{}, fmt.Errorf("Ungültige vorherige Bridge-Konfiguration: %w", err)
		}
		if err := previousConfig.Validate(); err != nil {
			return Response{}, err
		}
	}
	generated, err := netcfg.Generate(config)
	if err != nil {
		return Response{}, err
	}
	if _, err := installer.Run(ctx, "systemctl", "is-active", "--quiet", "systemd-networkd.service"); err != nil {
		return Response{}, errors.New("systemd-networkd.service ist nicht aktiv.")
	}
	routes, err := installer.Run(ctx, "ip", "-j", "route", "show", "default")
	if err != nil {
		return Response{}, fmt.Errorf("Default-Routen konnten nicht geprüft werden: %s", summarize(routes, err))
	}
	var defaultRoutes []struct {
		Device string `json:"dev"`
	}
	if err := json.Unmarshal(routes, &defaultRoutes); err != nil {
		return Response{}, fmt.Errorf("Default-Routen konnten nicht gelesen werden: %w", err)
	}
	for _, bridge := range config.Bridges {
		for _, port := range bridge.Ports {
			for _, route := range defaultRoutes {
				if port == route.Device {
					return Response{}, fmt.Errorf("Interface %s trägt eine Default-Route und kann nicht als Bridge-Port verwendet werden", port)
				}
			}
		}
	}
	previous, names, err := snapshotSWATNetworkFiles(networkdDirectory)
	if err != nil {
		return Response{}, err
	}
	allNames := make(map[string]bool, len(names)+len(generated))
	for _, name := range names {
		allNames[name] = true
	}
	for name := range generated {
		allNames[name] = true
		if _, exists := previous[name]; !exists {
			previous[name] = fileSnapshot{}
		}
	}
	if err := verifyNetworkdOwner(ctx, installer.Run, config, previous); err != nil {
		return Response{}, err
	}
	for name := range generated {
		if filepath.Base(name) != name || (!strings.HasPrefix(name, "90-swat-bridge-") && !strings.HasPrefix(name, "91-swat-port-")) {
			return Response{}, fmt.Errorf("unerwarteter Netzwerk-Dateiname %q", name)
		}
	}
	stage, err := os.MkdirTemp("/var/lib/swat", "network-stage-")
	if err != nil {
		return Response{}, err
	}
	defer os.RemoveAll(stage)
	verifyPaths := make([]string, 0, len(generated))
	for name, content := range generated {
		path := filepath.Join(stage, name)
		if err := os.WriteFile(path, content, 0o600); err != nil {
			return Response{}, err
		}
		verifyPaths = append(verifyPaths, path)
	}
	if len(verifyPaths) > 0 {
		sort.Strings(verifyPaths)
		if _, err := installer.Run(ctx, "networkd-analyze", append([]string{"verify"}, verifyPaths...)...); err != nil {
			return Response{}, fmt.Errorf("networkd-analyze verify: %w", err)
		}
	}
	if err := applyNetworkFiles(networkdDirectory, allNames, generated, previous); err != nil {
		return Response{}, err
	}
	links := bridgeConfigLinks(previousConfig, config)
	if err := reloadNetworkd(ctx, installer.Run, links); err != nil {
		rollbackErr := restoreNetworkFiles(networkdDirectory, previous)
		_ = reloadNetworkd(context.Background(), installer.Run, links)
		if rollbackErr != nil {
			return Response{}, fmt.Errorf("%w; Rollback fehlgeschlagen: %v", err, rollbackErr)
		}
		return Response{}, err
	}
	pending := &pendingNetwork{files: previous, links: links, config: []byte(configJSON), deadline: time.Now().Add(transactionWindow), user: username}
	pending.timer = time.AfterFunc(transactionWindow, func() {
		installer.mu.Lock()
		defer installer.mu.Unlock()
		if installer.networkPending == pending {
			_ = installer.rollbackNetworkLocked("automatisch")
		}
	})
	installer.networkPending = pending
	return Response{OK: true, Message: "Bridge-Konfiguration geladen; Bestätigung innerhalb von 60 Sekunden erforderlich."}, nil
}

func verifyNetworkdOwner(ctx context.Context, runner CommandRunner, config netcfg.Config, previous map[string]fileSnapshot) error {
	for _, bridge := range config.Bridges {
		links := append([]string{bridge.Name}, bridge.Ports...)
		for _, link := range links {
			output, err := runner(ctx, "networkctl", "status", "--no-pager", link)
			if err != nil {
				return fmt.Errorf("networkctl status %s: %s", link, summarize(output, err))
			}
			for _, line := range strings.Split(string(output), "\n") {
				key, value, ok := strings.Cut(strings.TrimSpace(line), ":")
				if !ok || strings.TrimSpace(key) != "Network File" {
					continue
				}
				path := strings.TrimSpace(value)
				base := filepath.Base(path)
				if path == "n/a" || path == "-" || previous[base].exists || strings.HasPrefix(base, "90-swat-bridge-") || strings.HasPrefix(base, "91-swat-port-") {
					break
				}
				return fmt.Errorf("Interface %s wird bereits von %s verwaltet; fremde .network-Dateien werden nicht überschrieben", link, path)
			}
		}
	}
	return nil
}

func (installer *Installer) NetworkAction(ctx context.Context, action, configJSON, previousJSON, username string) (Response, error) {
	if action == "network-bridge-apply" {
		return installer.ApplyBridgeConfig(ctx, configJSON, previousJSON, username)
	}
	installer.mu.Lock()
	defer installer.mu.Unlock()
	if installer.Run == nil {
		installer.Run = SystemRunner
	}
	pending := installer.networkPending
	if pending == nil {
		return Response{}, errors.New("Keine Netzwerkänderung wartet auf Bestätigung oder Rücknahme.")
	}
	switch action {
	case "network-bridge-confirm":
		if err := writeAtomicSystemFile("/var/lib/swat", "network-bridges-applied.json", pending.config, 0o644); err != nil {
			return Response{}, fmt.Errorf("angewendete Bridge-Konfiguration konnte nicht gespeichert werden: %w", err)
		}
		pending.timer.Stop()
		installer.networkPending = nil
		return Response{OK: true, Message: "Bridge-Konfiguration bestätigt."}, nil
	case "network-bridge-rollback":
		if err := installer.rollbackNetworkLocked("manuell"); err != nil {
			return Response{}, err
		}
		return Response{OK: true, Message: "Bridge-Konfiguration zurückgenommen."}, nil
	default:
		return Response{}, errors.New("Unbekannte Netzwerkaktion.")
	}
}

func snapshotSWATNetworkFiles(directory string) (map[string]fileSnapshot, []string, error) {
	entries, err := os.ReadDir(directory)
	if err != nil {
		return nil, nil, err
	}
	previous := make(map[string]fileSnapshot)
	var names []string
	for _, entry := range entries {
		name := entry.Name()
		if !strings.HasPrefix(name, "90-swat-bridge-") && !strings.HasPrefix(name, "91-swat-port-") {
			continue
		}
		info, err := entry.Info()
		if err != nil || !info.Mode().IsRegular() {
			return nil, nil, fmt.Errorf("Netzwerkdatei %s ist nicht regulär", name)
		}
		content, err := os.ReadFile(filepath.Join(directory, name))
		if err != nil {
			return nil, nil, err
		}
		if !strings.HasPrefix(string(content), "# Managed-By: SWAT\n# SWAT-Config-ID: network/bridge/") {
			return nil, nil, fmt.Errorf("fremde Datei %s wird nicht überschrieben", filepath.Join(directory, name))
		}
		previous[name] = fileSnapshot{content: content, exists: true}
		names = append(names, name)
	}
	return previous, names, nil
}

func applyNetworkFiles(directory string, names map[string]bool, generated map[string][]byte, previous map[string]fileSnapshot) error {
	for name := range names {
		path := filepath.Join(directory, name)
		content, exists := generated[name]
		if !exists {
			if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
				_ = restoreNetworkFiles(directory, previous)
				return err
			}
			continue
		}
		if err := writeAtomicSystemFile(directory, name, content, 0o644); err != nil {
			_ = restoreNetworkFiles(directory, previous)
			return err
		}
	}
	return nil
}

func writeAtomicSystemFile(directory, name string, content []byte, mode os.FileMode) error {
	if filepath.Base(name) != name {
		return errors.New("ungültiger Systemdateiname")
	}
	temporary, err := os.CreateTemp(directory, ".swat-*.tmp")
	if err != nil {
		return err
	}
	defer os.Remove(temporary.Name())
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
	return os.Rename(temporary.Name(), filepath.Join(directory, name))
}

func restoreNetworkFiles(directory string, snapshots map[string]fileSnapshot) error {
	for name, snapshot := range snapshots {
		path := filepath.Join(directory, name)
		if !snapshot.exists {
			if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
				return err
			}
			continue
		}
		if err := writeAtomicSystemFile(directory, name, snapshot.content, 0o644); err != nil {
			return err
		}
	}
	return nil
}

func bridgeConfigLinks(configs ...netcfg.Config) []string {
	set := make(map[string]bool)
	for _, config := range configs {
		for _, bridge := range config.Bridges {
			set[bridge.Name] = true
			for _, port := range bridge.Ports {
				set[port] = true
			}
		}
	}
	links := make([]string, 0, len(set))
	for link := range set {
		links = append(links, link)
	}
	sort.Strings(links)
	return links
}

func reloadNetworkd(ctx context.Context, runner CommandRunner, links []string) error {
	if output, err := runner(ctx, "networkctl", "reload"); err != nil {
		return fmt.Errorf("networkctl reload: %s", summarize(output, err))
	}
	for _, link := range links {
		if output, err := runner(ctx, "networkctl", "reconfigure", link); err != nil {
			return fmt.Errorf("networkctl reconfigure %s: %s", link, summarize(output, err))
		}
	}
	return nil
}

func (installer *Installer) rollbackNetworkLocked(reason string) error {
	pending := installer.networkPending
	installer.networkPending = nil
	if pending.timer != nil {
		pending.timer.Stop()
	}
	err := restoreNetworkFiles(networkdDirectory, pending.files)
	if err == nil {
		err = reloadNetworkd(context.Background(), installer.Run, pending.links)
	}
	result, detail := "ok", ""
	if err != nil {
		result, detail = "fehler", err.Error()
	}
	if installer.Audit != nil {
		_ = installer.Audit(auditEntry(pending.user, "network/bridge/rollback", reason, result, detail))
	}
	return err
}

func auditEntry(user, action, target, result, detail string) audit.Entry {
	return audit.Entry{User: user, Action: action, Target: target, Result: result, Detail: detail}
}

func (installer *Installer) ApplyFirewall(ctx context.Context, action, configJSON, username string) (Response, error) {
	installer.mu.Lock()
	defer installer.mu.Unlock()
	if installer.Run == nil {
		installer.Run = SystemRunner
	}
	switch action {
	case "firewall-apply":
		if installer.firewallPending != nil {
			return Response{}, errors.New("Eine Firewalländerung wartet bereits auf Bestätigung oder Rücknahme.")
		}
		var config zones.Config
		if err := json.Unmarshal([]byte(configJSON), &config); err != nil {
			return Response{}, fmt.Errorf("Ungültige Firewall-Konfiguration: %w", err)
		}
		script, err := zones.Generate(config)
		if err != nil {
			return Response{}, err
		}
		for _, unit := range []string{"firewalld.service", "ufw.service"} {
			if _, ownerErr := installer.Run(ctx, "systemctl", "is-active", "--quiet", unit); ownerErr == nil {
				return Response{}, fmt.Errorf("Firewall-Anwendung gesperrt: %s ist aktiv; parallele Firewall-Owner werden nicht verändert", unit)
			}
		}
		previousBytes, err := installer.Run(ctx, "nft", "list", "table", "inet", "swat")
		previous := zones.RemoveScript
		if err == nil {
			previous = string(previousBytes)
			if strings.HasPrefix(strings.TrimSpace(previous), "table inet swat {") {
				previous = "delete table inet swat\n" + previous
			}
		}
		if err := runNftScript(ctx, installer.Run, script, true); err != nil {
			return Response{}, fmt.Errorf("nftables hat die Regeln abgelehnt: %w", err)
		}
		if err := runNftScript(ctx, installer.Run, script, false); err != nil {
			return Response{}, fmt.Errorf("Firewall-Regeln konnten nicht geladen werden: %w", err)
		}
		pending := &pendingFirewall{previous: previous, current: script, deadline: time.Now().Add(transactionWindow), user: username}
		pending.timer = time.AfterFunc(transactionWindow, func() {
			installer.mu.Lock()
			defer installer.mu.Unlock()
			if installer.firewallPending == pending {
				_ = installer.rollbackFirewallLocked("automatisch")
			}
		})
		installer.firewallPending = pending
		return Response{OK: true, Message: "Firewall-Regeln geladen; Bestätigung innerhalb von 60 Sekunden erforderlich."}, nil
	case "firewall-confirm":
		pending := installer.firewallPending
		if pending == nil {
			return Response{}, errors.New("Keine Firewalländerung wartet auf Bestätigung.")
		}
		content := pending.current
		if !strings.HasPrefix(content, "# Managed-By: SWAT\n") {
			content = "# Managed-By: SWAT\n" + content
		}
		if err := writeOwnedSystemFile(nftablesPath, "# Managed-By: SWAT\n", []byte(content), 0o644); err != nil {
			return Response{}, err
		}
		pending.timer.Stop()
		installer.firewallPending = nil
		return Response{OK: true, Message: "Firewalländerung bestätigt und gespeichert."}, nil
	case "firewall-rollback":
		if installer.firewallPending == nil {
			return Response{}, errors.New("Keine Firewalländerung wartet auf Rücknahme.")
		}
		if err := installer.rollbackFirewallLocked("manuell"); err != nil {
			return Response{}, err
		}
		return Response{OK: true, Message: "Firewalländerung zurückgenommen."}, nil
	default:
		return Response{}, errors.New("Unbekannte Firewallaktion.")
	}
}

func runNftScript(ctx context.Context, runner CommandRunner, script string, check bool) error {
	file, err := os.CreateTemp("/var/lib/swat", "nft-transaction-*.conf")
	if err != nil {
		return err
	}
	path := file.Name()
	defer os.Remove(path)
	if err := file.Chmod(0o600); err != nil {
		file.Close()
		return err
	}
	if _, err := file.WriteString(script); err != nil {
		file.Close()
		return err
	}
	if err := file.Sync(); err != nil {
		file.Close()
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	args := []string{"-f", path}
	if check {
		args = []string{"-c", "-f", path}
	}
	output, err := runner(ctx, "nft", args...)
	if err != nil {
		return fmt.Errorf("%s", summarize(output, err))
	}
	return nil
}

func (installer *Installer) rollbackFirewallLocked(reason string) error {
	pending := installer.firewallPending
	installer.firewallPending = nil
	if pending.timer != nil {
		pending.timer.Stop()
	}
	err := runNftScript(context.Background(), installer.Run, pending.previous, false)
	result, detail := "ok", ""
	if err != nil {
		result, detail = "fehler", err.Error()
	}
	if installer.Audit != nil {
		_ = installer.Audit(auditEntry(pending.user, "firewall/rollback", reason, result, detail))
	}
	return err
}
