package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"swat/internal/audit"
	"swat/internal/collect"
	"swat/internal/moduleadmin"
	"swat/internal/netcfg"
	"swat/internal/zones"
)

const networkConfirmWindow = 60 * time.Second

type pendingNetworkApply struct {
	Deadline time.Time
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
func appliedBridgePath() string {
	return filepath.Join(zones.StateDir(), "network-bridges-applied.json")
}

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
	var pending *pendingNetworkApply
	if transactionStatus, statusErr := moduleadmin.TransactionStatus(context.Background()); statusErr == nil && transactionStatus.NetworkPending {
		pending = &pendingNetworkApply{Deadline: transactionStatus.NetworkDeadline}
	}
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
	if !modulePageReady("network") {
		http.Redirect(w, r, "/modules?required=network", http.StatusSeeOther)
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
		success, err = rollbackBridgeConfig(session)
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

	oldConfig, err := netcfg.Load(appliedBridgePath())
	if err != nil {
		return "", fmt.Errorf("zuletzt angewendete Bridge-Konfiguration kann nicht gelesen werden: %w", err)
	}
	if err := verifyNetworkdMatches([]netcfg.Config{oldConfig, config}, files); err != nil {
		return "", err
	}
	if err := audit.Log(zones.StateDir(), audit.Entry{User: session.Username, Action: "network/bridge/apply-start", Target: "systemd-networkd", Result: "ok"}); err != nil {
		return "", fmt.Errorf("Audit-Log nicht schreibbar; Änderung abgebrochen: %w", err)
	}

	configJSON, err := json.Marshal(config)
	if err != nil {
		return "", err
	}
	previousJSON, err := json.Marshal(oldConfig)
	if err != nil {
		return "", err
	}
	response, err := moduleadmin.PerformNetworkAction(context.Background(), "network-bridge-apply", string(configJSON), string(previousJSON), session.Username, session.AdminPassword)
	if err != nil {
		return "", err
	}
	return response.Message, nil
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

func confirmBridgeConfig(session authSession) (string, error) {
	response, err := moduleadmin.PerformNetworkAction(context.Background(), "network-bridge-confirm", "", "", session.Username, session.AdminPassword)
	if err != nil {
		return "", err
	}
	_ = audit.Log(zones.StateDir(), audit.Entry{User: session.Username, Action: "network/bridge/confirm", Target: "systemd-networkd", Result: "ok"})
	return response.Message, nil
}

func rollbackBridgeConfig(session authSession) (string, error) {
	response, err := moduleadmin.PerformNetworkAction(context.Background(), "network-bridge-rollback", "", "", session.Username, session.AdminPassword)
	if err != nil {
		return "", err
	}
	return response.Message, nil
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
