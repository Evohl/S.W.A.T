package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"swat/internal/audit"
	"swat/internal/collect"
	"swat/internal/netcfg"
	"swat/internal/zones"
)

const networkConfirmWindow = 60 * time.Second

var networkApplyState = struct {
	sync.Mutex
	pending *pendingNetworkApply
}{}

type pendingNetworkApply struct {
	Deadline time.Time
	Previous map[string][]byte
	Absent   map[string]bool
	Links    []string
	Password string
	User     string
	Timer    *time.Timer
}

type bridgeView struct {
	netcfg.Bridge
	PortsText     string
	AddressesText string
	DNSText       string
}

type bridgeInterfaceOption struct {
	Name        string
	Unavailable string
	Selected    bool
}

func bridgeStatePath() string { return filepath.Join(zones.StateDir(), "network-bridges.json") }
func appliedBridgePath() string { return filepath.Join(zones.StateDir(), "network-bridges-applied.json") }

func bridgeManagerStatus() (bool, string) {
	runtime := collect.NetworkRuntimeStatus()
	if runtime.Networkd != "active" {
		return false, "systemd-networkd.service ist nicht aktiv. SWAT wendet keine Bridge-Konfiguration an, solange ein anderer Netzwerkdienst oder kein Network-Manager aktiv ist."
	}
	if reason := collect.ServiceRestriction("Netzwerk", "systemd-networkd.service", "systemd-networkd.service"); reason != "" {
		return false, reason
	}
	if _, err := exec.LookPath("networkd-analyze"); err != nil {
		return false, "networkd-analyze fehlt; die native Konfiguration kann vor dem Anwenden nicht geprüft werden."
	}
	if _, err := exec.LookPath("networkctl"); err != nil {
		return false, "networkctl fehlt; Bridges können nicht sicher neu konfiguriert werden."
	}
	return true, ""
}

func defaultRouteInterfaces() (map[string]bool, error) {
	output, err := exec.Command("ip", "-j", "route", "show", "default").Output()
	if err != nil {
		return nil, fmt.Errorf("Default-Routen konnten nicht geprüft werden: %w", err)
	}
	var routes []struct {
		Device string `json:"dev"`
	}
	if err := json.Unmarshal(output, &routes); err != nil {
		return nil, fmt.Errorf("Default-Routen konnten nicht gelesen werden: %w", err)
	}
	result := make(map[string]bool)
	for _, route := range routes {
		if route.Device != "" {
			result[route.Device] = true
		}
	}
	return result, nil
}

func bridgeInterfaceOptions(config netcfg.Config, selected []string) ([]bridgeInterfaceOption, error) {
	interfaces, err := collect.Interfaces()
	if err != nil {
		return nil, err
	}
	defaultRoutes, err := defaultRouteInterfaces()
	if err != nil {
		return nil, err
	}
	selectedPorts := make(map[string]bool, len(selected))
	for _, name := range selected {
		selectedPorts[name] = true
	}
	assigned := make(map[string]string)
	for _, bridge := range config.Bridges {
		for _, port := range bridge.Ports {
			assigned[port] = bridge.Name
		}
	}
	options := make([]bridgeInterfaceOption, 0, len(interfaces))
	for _, iface := range interfaces {
		if iface.Name == "lo" || iface.IsBridge || strings.HasPrefix(iface.Name, "wg") || strings.HasPrefix(iface.Name, "tun") {
			continue
		}
		option := bridgeInterfaceOption{Name: iface.Name, Selected: selectedPorts[iface.Name]}
		if defaultRoutes[iface.Name] {
			option.Unavailable = "Default-Route: aus Sicherheitsgründen gesperrt"
		} else if owner := assigned[iface.Name]; owner != "" && !selectedPorts[iface.Name] {
			option.Unavailable = "bereits Bridge " + owner + " zugewiesen"
		} else if _, err := os.Stat(filepath.Join("/sys/class/net", iface.Name, "wireless")); err == nil {
			option.Unavailable = "WLAN-Client kann nicht als Ethernet-Bridge-Port verwendet werden"
		}
		options = append(options, option)
	}
	return options, nil
}

func validateBridgePorts(bridge netcfg.Bridge) error {
	interfaces, err := collect.Interfaces()
	if err != nil {
		return err
	}
	known := make(map[string]collect.Interface, len(interfaces))
	for _, iface := range interfaces {
		known[iface.Name] = iface
	}
	defaultRoutes, err := defaultRouteInterfaces()
	if err != nil {
		return err
	}
	for _, name := range bridge.Ports {
		iface, exists := known[name]
		if !exists || name == "lo" || iface.IsBridge || strings.HasPrefix(name, "wg") || strings.HasPrefix(name, "tun") {
			return fmt.Errorf("Interface %q ist kein verfügbares physisches oder virtuelles Port-Interface", name)
		}
		if defaultRoutes[name] {
			return fmt.Errorf("Interface %s trägt eine Default-Route und ist für Bridge-Änderungen gesperrt", name)
		}
		if _, err := os.Stat(filepath.Join("/sys/class/net", name, "wireless")); err == nil {
			return fmt.Errorf("WLAN-Client %s kann ohne Access-Point-/4addr-Modus nicht als Bridge-Port verwendet werden", name)
		}
	}
	return nil
}

func verifyNetworkdMatches(configs []netcfg.Config, generated map[string][]byte) error {
	ports := make(map[string]bool)
	for _, config := range configs {
		for _, bridge := range config.Bridges {
			for _, port := range bridge.Ports {
				ports[port] = true
			}
		}
	}
	for port := range ports {
		networkFile, err := currentNetworkFile(port)
		if err != nil {
			return err
		}
		if networkFile == "n/a" || networkFile == "-" {
			continue
		}
		if _, ok := generated[filepath.Base(networkFile)]; ok {
			continue
		}
		content, readErr := os.ReadFile(networkFile)
		if readErr == nil && strings.HasPrefix(string(content), "# Managed-By: SWAT\n") && strings.HasPrefix(filepath.Base(networkFile), "91-swat-port-") {
			continue
		}
		return fmt.Errorf("Interface %s wird bereits von %s verwaltet; SWAT überschreibt keine fremden .network-Dateien", port, networkFile)
	}
	return nil
}

func currentNetworkFile(link string) (string, error) {
	output, err := exec.Command("networkctl", "status", "--no-pager", link).CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("networkctl status %s: %w: %s", link, err, strings.TrimSpace(string(output)))
	}
	path, ok := ParseNetworkFile(string(output))
	if !ok {
		return "", fmt.Errorf("networkctl konnte den aktiven .network-Besitzer von %s nicht bestimmen", link)
	}
	return path, nil
}

func ParseNetworkFile(output string) (string, bool) {
	for _, line := range strings.Split(string(output), "\n") {
		if key, value, ok := strings.Cut(strings.TrimSpace(line), ":"); ok && strings.TrimSpace(key) == "Network File" {
			return strings.TrimSpace(value), true
		}
	}
	return "", false
}

func verifyAppliedNetworkdFiles(config netcfg.Config) error {
	for _, bridge := range config.Bridges {
		expected := netcfg.BridgeFileName(bridge.Name, "network")
		links := append([]string{bridge.Name}, bridge.Ports...)
		for i, link := range links {
			want := expected
			if i > 0 {
				want = netcfg.PortFileName(bridge.Name, link)
			}
			actual, err := currentNetworkFile(link)
			if err != nil {
				return err
			}
			if filepath.Base(actual) != want {
				return fmt.Errorf("systemd-networkd hat für %s %q statt %q ausgewählt", link, actual, want)
			}
		}
	}
	return nil
}

func bridgeManagerData(r *http.Request) map[string]any {
	config, err := netcfg.Load(bridgeStatePath())
	if err != nil {
		config = netcfg.Config{}
	}
	rows := make([]bridgeView, 0, len(config.Bridges))
	for _, bridge := range config.Bridges {
		rows = append(rows, bridgeView{Bridge: bridge, PortsText: strings.Join(bridge.Ports, ", "), AddressesText: strings.Join(bridge.Addresses, ", "), DNSText: strings.Join(bridge.DNS, ", ")})
	}
	edit := bridgeView{Bridge: netcfg.Bridge{STP: true}}
	if name := r.URL.Query().Get("bridge"); name != "" {
		for _, bridge := range config.Bridges {
			if bridge.Name == name {
				edit = bridgeView{Bridge: bridge, PortsText: strings.Join(bridge.Ports, ", "), AddressesText: strings.Join(bridge.Addresses, ", "), DNSText: strings.Join(bridge.DNS, ", ")}
			}
		}
	}
	ready, reason := bridgeManagerStatus()
	options, optionErr := bridgeInterfaceOptions(config, edit.Ports)
	if optionErr != nil {
		ready = false
		reason = optionErr.Error()
	}
	networkApplyState.Lock()
	var pending *pendingNetworkApply
	if networkApplyState.pending != nil {
		snapshot := *networkApplyState.pending
		pending = &snapshot
	}
	networkApplyState.Unlock()
	return map[string]any{
		"BridgeManager": map[string]any{
			"Bridges": rows, "Interfaces": options, "Ready": ready, "Reason": reason,
			"Edit": edit, "Pending": pending, "ConfirmSeconds": int(networkConfirmWindow.Seconds()),
		},
	}
}

func handleNetworkBridgeAction(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Methode nicht erlaubt", http.StatusMethodNotAllowed)
		return
	}
	session, err := accountActionSession(r)
	if err != nil {
		renderNetwork(w, r, err.Error(), "")
		return
	}
	action := r.FormValue("action")
	var success string
	switch action {
	case "save":
		success, err = saveBridge(r)
	case "delete":
		success, err = deleteBridge(r.FormValue("name"))
	case "apply":
		success, err = applyBridgeConfig(session)
	case "confirm":
		success, err = confirmBridgeConfig(session)
	case "rollback":
		success, err = rollbackBridgeConfig("manuell")
	default:
		err = fmt.Errorf("Ungültige Bridge-Aktion.")
	}
	result, detail := "ok", ""
	if err != nil {
		result, detail = "fehler", err.Error()
	}
	_ = audit.Log(zones.StateDir(), audit.Entry{User: session.Username, Action: "network/bridge/" + action, Target: r.FormValue("name"), Result: result, Detail: detail})
	if err != nil {
		renderNetwork(w, r, err.Error(), "")
		return
	}
	renderNetwork(w, r, "", success)
}

func saveBridge(r *http.Request) (string, error) {
	ports := cleanFields(r.Form["ports"])
	bridge := netcfg.Bridge{
		Name: strings.TrimSpace(r.FormValue("name")), Ports: ports,
		Addresses: splitFields(r.FormValue("addresses")), Gateway: strings.TrimSpace(r.FormValue("gateway")),
		DNS: splitFields(r.FormValue("dns")), DHCP: r.FormValue("dhcp") == "1", STP: r.FormValue("stp") == "1",
	}
	if err := bridge.Validate(); err != nil {
		return "", err
	}
	if err := validateBridgePorts(bridge); err != nil {
		return "", err
	}
	config, err := netcfg.Load(bridgeStatePath())
	if err != nil {
		return "", err
	}
	selected := make(map[string]bool)
	for _, port := range bridge.Ports {
		selected[port] = true
	}
	for _, existing := range config.Bridges {
		if existing.Name == bridge.Name {
			continue
		}
		for _, port := range existing.Ports {
			if selected[port] {
				return "", fmt.Errorf("Interface %s ist bereits Bridge %s zugewiesen", port, existing.Name)
			}
		}
	}
	updated := false
	for i := range config.Bridges {
		if config.Bridges[i].Name == bridge.Name {
			config.Bridges[i], updated = bridge, true
		}
	}
	if !updated {
		config.Bridges = append(config.Bridges, bridge)
	}
	if err := config.Validate(); err != nil {
		return "", err
	}
	if err := netcfg.Save(bridgeStatePath(), config); err != nil {
		return "", err
	}
	return "Bridge-Konfiguration gespeichert. Sie wird erst nach „Anwenden“ aktiv.", nil
}

func deleteBridge(name string) (string, error) {
	config, err := netcfg.Load(bridgeStatePath())
	if err != nil {
		return "", err
	}
	bridges := config.Bridges[:0]
	found := false
	for _, bridge := range config.Bridges {
		if bridge.Name == name {
			found = true
			continue
		}
		bridges = append(bridges, bridge)
	}
	if !found {
		return "", fmt.Errorf("Bridge %q nicht gefunden", name)
	}
	config.Bridges = bridges
	if err := netcfg.Save(bridgeStatePath(), config); err != nil {
		return "", err
	}
	return "Bridge aus dem gewünschten Zustand entfernt. Mit „Anwenden“ wird sie auch systemd-networkd-seitig entfernt.", nil
}

func bridgeFiles(config netcfg.Config) (map[string][]byte, error) {
	files, err := netcfg.Generate(config)
	if err != nil {
		return nil, err
	}
	for name := range files {
		if filepath.Base(name) != name || !strings.HasPrefix(name, "90-swat-") && !strings.HasPrefix(name, "91-swat-") {
			return nil, fmt.Errorf("unerwarteter Netzwerk-Dateiname %q", name)
		}
	}
	return files, nil
}

func applyBridgeConfig(session authSession) (string, error) {
	ready, reason := bridgeManagerStatus()
	if !ready {
		return "", fmt.Errorf("Bridge-Anwendung gesperrt: %s", reason)
	}
	config, err := netcfg.Load(bridgeStatePath())
	if err != nil {
		return "", err
	}
	files, err := bridgeFiles(config)
	if err != nil {
		return "", err
	}
	defaultRoutes, err := defaultRouteInterfaces()
	if err != nil {
		return "", err
	}
	for _, bridge := range config.Bridges {
		for _, port := range bridge.Ports {
			if defaultRoutes[port] {
				return "", fmt.Errorf("Interface %s trägt eine Default-Route und kann nicht als Bridge-Port verwendet werden", port)
			}
		}
	}

	networkApplyState.Lock()
	defer networkApplyState.Unlock()
	if networkApplyState.pending != nil {
		return "", fmt.Errorf("Eine Netzwerkänderung wartet noch auf Bestätigung oder Rollback")
	}

	oldConfig, err := netcfg.Load(appliedBridgePath())
	if err != nil {
		return "", fmt.Errorf("zuletzt angewendete Bridge-Konfiguration kann nicht gelesen werden: %w", err)
	}
	oldFiles, err := bridgeFiles(oldConfig)
	if err != nil {
		return "", err
	}
	if err := verifyNetworkdMatches([]netcfg.Config{oldConfig, config}, files); err != nil {
		return "", err
	}
	targetDir := "/etc/systemd/network"
	previous := make(map[string][]byte)
	absent := make(map[string]bool)
	allNames := make(map[string]bool)
	for name := range files {
		allNames[name] = true
	}
	for name := range oldFiles {
		allNames[name] = true
	}
	for name := range allNames {
		path := filepath.Join(targetDir, name)
		content, readErr := os.ReadFile(path)
		if os.IsNotExist(readErr) {
			absent[path] = true
			continue
		}
		if readErr != nil {
			return "", readErr
		}
		if !strings.HasPrefix(string(content), "# Managed-By: SWAT\n") {
			return "", fmt.Errorf("fremde Datei %s wird nicht überschrieben", path)
		}
		previous[path] = content
	}

	stageDir, err := os.MkdirTemp(zones.StateDir(), "networkd-stage-")
	if err != nil {
		return "", err
	}
	defer os.RemoveAll(stageDir)
	verifyPaths := make([]string, 0, len(files))
	for name, content := range files {
		path := filepath.Join(stageDir, name)
		if err := os.WriteFile(path, content, 0o600); err != nil {
			return "", err
		}
		verifyPaths = append(verifyPaths, path)
	}
	sort.Strings(verifyPaths)
	if len(verifyPaths) > 0 {
		command := exec.Command("networkd-analyze", append([]string{"verify"}, verifyPaths...)...)
		if output, err := command.CombinedOutput(); err != nil {
			return "", fmt.Errorf("networkd-analyze verify: %w: %s", err, strings.TrimSpace(string(output)))
		}
	}
	if err := audit.Log(zones.StateDir(), audit.Entry{User: session.Username, Action: "network/bridge/apply-start", Target: "systemd-networkd", Result: "ok"}); err != nil {
		return "", fmt.Errorf("Audit-Log nicht schreibbar; Änderung abgebrochen: %w", err)
	}

	for name := range oldFiles {
		if _, remains := files[name]; remains {
			continue
		}
		if err := runAsRoot(session.SudoPassword, "rm", "--", filepath.Join(targetDir, name)); err != nil {
			return "", rollbackBridgeFiles(session.SudoPassword, previous, absent, nil, err)
		}
	}
	for name := range files {
		if err := runAsRoot(session.SudoPassword, "install", "-m", "0644", filepath.Join(stageDir, name), filepath.Join(targetDir, name)); err != nil {
			return "", rollbackBridgeFiles(session.SudoPassword, previous, absent, nil, err)
		}
	}
	links := bridgeLinks(oldConfig, config)
	if err := reloadBridgeLinks(session.SudoPassword, links); err != nil {
		return "", rollbackBridgeFiles(session.SudoPassword, previous, absent, links, err)
	}
	if err := verifyAppliedNetworkdFiles(config); err != nil {
		return "", rollbackBridgeFiles(session.SudoPassword, previous, absent, links, err)
	}

	pending := &pendingNetworkApply{Deadline: time.Now().Add(networkConfirmWindow), Previous: previous, Absent: absent, Links: links, Password: session.SudoPassword, User: session.Username}
	pending.Timer = time.AfterFunc(networkConfirmWindow, func() {
		networkApplyState.Lock()
		defer networkApplyState.Unlock()
		if networkApplyState.pending == pending {
			_ = rollbackNetworkLocked(pending, "automatisch")
		}
	})
	networkApplyState.pending = pending
	return fmt.Sprintf("Bridge-Konfiguration geladen. Bitte innerhalb von %d Sekunden bestätigen; sonst wird sie zurückgenommen.", int(networkConfirmWindow.Seconds())), nil
}

func bridgeLinks(configs ...netcfg.Config) []string {
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

func reloadBridgeLinks(password string, links []string) error {
	if err := runAsRoot(password, "networkctl", "reload"); err != nil {
		return err
	}
	for _, link := range links {
		if err := runAsRoot(password, "networkctl", "reconfigure", link); err != nil {
			return fmt.Errorf("networkctl reconfigure %s: %w", link, err)
		}
	}
	return nil
}

func rollbackBridgeFiles(password string, previous map[string][]byte, absent map[string]bool, links []string, cause error) error {
	pending := &pendingNetworkApply{Previous: previous, Absent: absent, Links: links, Password: password}
	if err := rollbackNetworkLocked(pending, "fehler"); err != nil {
		return fmt.Errorf("%w; Rollback fehlgeschlagen: %v", cause, err)
	}
	return cause
}

func confirmBridgeConfig(session authSession) (string, error) {
	networkApplyState.Lock()
	defer networkApplyState.Unlock()
	pending := networkApplyState.pending
	if pending == nil {
		return "", fmt.Errorf("Keine Netzwerkänderung wartet auf Bestätigung")
	}
	pending.Timer.Stop()
	config, err := netcfg.Load(bridgeStatePath())
	if err != nil {		return "", err
	}
	if err := netcfg.Save(appliedBridgePath(), config); err != nil {
		return "", err
	}
	networkApplyState.pending = nil
	pending.Password = ""
	_ = audit.Log(zones.StateDir(), audit.Entry{User: session.Username, Action: "network/bridge/confirm", Target: "systemd-networkd", Result: "ok"})
	return "Bridge-Konfiguration bestätigt.", nil
}

func rollbackBridgeConfig(reason string) (string, error) {
	networkApplyState.Lock()
	defer networkApplyState.Unlock()
	pending := networkApplyState.pending
	if pending == nil {
		return "", fmt.Errorf("Keine Netzwerkänderung wartet auf Rollback")
	}
	pending.Timer.Stop()
	if err := rollbackNetworkLocked(pending, reason); err != nil {
		return "", err
	}
	return "Bridge-Konfiguration zurückgenommen.", nil
}

func rollbackNetworkLocked(pending *pendingNetworkApply, reason string) error {
	networkApplyState.pending = nil
	for path := range pending.Absent {
		if err := runAsRoot(pending.Password, "rm", "-f", "--", path); err != nil {
			return err
		}
	}
	tempDir, err := os.MkdirTemp(zones.StateDir(), "networkd-rollback-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(tempDir)
	for path, content := range pending.Previous {
		staged := filepath.Join(tempDir, filepath.Base(path))
		if err := os.WriteFile(staged, content, 0o600); err != nil {
			return err
		}
		if err := runAsRoot(pending.Password, "install", "-m", "0644", staged, path); err != nil {
			return err
		}
	}
	if err := reloadBridgeLinks(pending.Password, pending.Links); err != nil {
		return err
	}
	_ = audit.Log(zones.StateDir(), audit.Entry{User: pending.User, Action: "network/bridge/rollback", Target: reason, Result: "ok"})
	pending.Password = ""
	return nil
}

func splitFields(value string) []string {
	return cleanFields(strings.FieldsFunc(value, func(r rune) bool { return r == ',' || r == ' ' || r == '\n' || r == '\t' }))
}

func cleanFields(fields []string) []string {
	result := make([]string, 0, len(fields))
	for _, field := range fields {
		if value := strings.TrimSpace(field); value != "" {
			result = append(result, value)
		}
	}
	return result
}
