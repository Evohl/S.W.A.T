package main

import (
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"swat/internal/audit"
	"swat/internal/collect"
	"swat/internal/netcfg"
	"swat/internal/zones"
)

const forwardingSysctlFile = "/etc/sysctl.d/90-swat-forwarding.conf"

type forwardingFamily struct {
	Family  string
	Label   string
	Key     string
	Proc    string
	Enabled bool
}

type interfaceNameRow struct {
	CurrentName  string
	CurrentMAC   string
	PermanentMAC string
	Hardware     string
	DesiredName  string
	Connected    bool
}

type interfaceNamesView struct {
	Rows            []interfaceNameRow
	Preview         string
	ConfigError     string
	PreviewError    string
	HasDesiredState bool
}

func interfaceNamesPath() string {
	return filepath.Join(zones.StateDir(), "network-interface-names.json")
}

var forwardingFamilies = []forwardingFamily{
	{Family: "ipv4", Label: "IPv4", Key: "net.ipv4.ip_forward", Proc: "/proc/sys/net/ipv4/ip_forward"},
	{Family: "ipv6", Label: "IPv6", Key: "net.ipv6.conf.all.forwarding", Proc: "/proc/sys/net/ipv6/conf/all/forwarding"},
}

func readForwarding() []forwardingFamily {
	state := make([]forwardingFamily, len(forwardingFamilies))
	for i, family := range forwardingFamilies {
		value, err := os.ReadFile(family.Proc)
		family.Enabled = err == nil && strings.TrimSpace(string(value)) == "1"
		state[i] = family
	}
	return state
}

func handleNetwork(w http.ResponseWriter, r *http.Request) {
	if !modulePageReady("network") {
		http.Redirect(w, r, "/modules?required=network", http.StatusSeeOther)
		return
	}
	renderNetwork(w, r, "", "")
}

func renderNetwork(w http.ResponseWriter, r *http.Request, actionError, actionSuccess string) {
	ifaces, err := collect.Interfaces()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	page := collect.NetworkConfig(ifaces, collect.NetworkRuntimeStatus())
	page.ReadOnly = page.ReadOnly || page.Status == "warn"
	if authData(r).RootAccess && page.Status != "warn" {
		page.ReadOnly = false
	}
	data := map[string]any{
		"ConfigPage":     page,
		"Forwarding":     readForwarding(),
		"InterfaceNames": interfaceNamesData(ifaces),
		"ActionError":    actionError,
		"ActionSuccess":  actionSuccess,
	}
	for key, value := range bridgeManagerData(r) {
		data[key] = value
	}
	render(w, r, "network", "config.html", data)
}

func handleNetworkForwarding(w http.ResponseWriter, r *http.Request) {
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
	message, err := setForwarding(session, r.FormValue("family"), r.FormValue("enable") == "1")
	result, detail := "ok", ""
	if err != nil {
		result, detail = "fehler", err.Error()
	}
	_ = audit.Log(zones.StateDir(), audit.Entry{User: session.Username, Action: "network/forwarding", Target: r.FormValue("family") + "=" + r.FormValue("enable"), Result: result, Detail: detail})
	if err != nil {
		renderNetwork(w, r, err.Error(), "")
		return
	}
	renderNetwork(w, r, "", message)
}

func interfaceNamesData(ifaces []collect.Interface) interfaceNamesView {
	bindings, err := netcfg.LoadInterfaceNameBindings(interfaceNamesPath())
	view := interfaceNamesView{HasDesiredState: err == nil && len(bindings) > 0}
	if err != nil {
		view.ConfigError = err.Error()
		return view
	}
	byMAC := make(map[string]string, len(bindings))
	for _, binding := range bindings {
		mac := canonicalPermanentMAC(binding.PermanentMAC)
		if mac != "" {
			byMAC[mac] = binding.Name
		}
	}
	seen := make(map[string]bool)
	allBindings := make([]netcfg.InterfaceNameBinding, 0, len(bindings)+len(ifaces))
	for _, iface := range ifaces {
		mac := canonicalPermanentMAC(iface.PermanentAddress)
		if mac == "" {
			continue
		}
		name := byMAC[mac]
		if name == "" {
			name = iface.Name
		}
		hardware := iface.Hardware
		if hardware == "" {
			hardware = "-"
		}
		view.Rows = append(view.Rows, interfaceNameRow{
			CurrentName: iface.Name, CurrentMAC: iface.Address, PermanentMAC: mac,
			Hardware: hardware, DesiredName: name, Connected: true,
		})
		allBindings = append(allBindings, netcfg.InterfaceNameBinding{PermanentMAC: mac, Name: name})
		seen[mac] = true
	}
	for _, binding := range bindings {
		mac := canonicalPermanentMAC(binding.PermanentMAC)
		if seen[mac] {
			continue
		}
		view.Rows = append(view.Rows, interfaceNameRow{PermanentMAC: mac, Hardware: "nicht verbunden", DesiredName: binding.Name})
		allBindings = append(allBindings, binding)
	}
	files, err := netcfg.GenerateInterfaceLinks(allBindings)
	if err != nil {
		view.PreviewError = err.Error()
		return view
	}
	fileNames := make([]string, 0, len(files))
	for name := range files {
		fileNames = append(fileNames, name)
	}
	sort.Strings(fileNames)
	var preview strings.Builder
	for _, name := range fileNames {
		fmt.Fprintf(&preview, "# %s\n%s\n", name, files[name])
	}
	view.Preview = preview.String()
	return view
}

func canonicalPermanentMAC(value string) string {
	address, err := net.ParseMAC(strings.TrimSpace(value))
	if err != nil || len(address) != 6 || address[0]&1 != 0 {
		return ""
	}
	return strings.ToLower(address.String())
}

func updateInterfaceNameBindings(ifaces []collect.Interface, submittedMACs, submittedNames []string, previous []netcfg.InterfaceNameBinding) ([]netcfg.InterfaceNameBinding, error) {
	if len(submittedMACs) != len(submittedNames) || len(submittedMACs) > 128 {
		return nil, fmt.Errorf("Ungültige Anzahl von Netzwerkadaptern.")
	}
	known := make(map[string]bool, len(ifaces)+len(previous))
	connected := make(map[string]bool, len(ifaces))
	for _, iface := range ifaces {
		if mac := canonicalPermanentMAC(iface.PermanentAddress); mac != "" {
			known[mac] = true
			connected[mac] = true
		}
	}
	for _, binding := range previous {
		if mac := canonicalPermanentMAC(binding.PermanentMAC); mac != "" {
			known[mac] = true
		}
	}
	updated := make(map[string]string, len(submittedMACs))
	for index, rawMAC := range submittedMACs {
		mac := canonicalPermanentMAC(rawMAC)
		name := strings.TrimSpace(submittedNames[index])
		if mac == "" || !known[mac] {
			return nil, fmt.Errorf("Permanente MAC-Adresse %q ist unbekannt.", rawMAC)
		}
		if _, exists := updated[mac]; exists {
			return nil, fmt.Errorf("Adapter %s wurde mehrfach übermittelt.", mac)
		}
		updated[mac] = name
	}
	for mac := range connected {
		if _, exists := updated[mac]; !exists {
			return nil, fmt.Errorf("Der erkannte Adapter %s fehlt in der Anfrage.", mac)
		}
	}
	for _, binding := range previous {
		mac := canonicalPermanentMAC(binding.PermanentMAC)
		if _, exists := updated[mac]; !exists {
			updated[mac] = binding.Name
		}
	}
	for _, iface := range ifaces {
		mac := canonicalPermanentMAC(iface.PermanentAddress)
		if mac == "" {
			continue
		}
		desiredName := updated[mac]
		for _, other := range ifaces {
			if other.Name == desiredName && canonicalPermanentMAC(other.PermanentAddress) != mac {
				return nil, fmt.Errorf("Name %q ist bereits dem aktuellen Interface %s zugewiesen.", desiredName, other.Name)
			}
		}
	}
	result := make([]netcfg.InterfaceNameBinding, 0, len(updated))
	for mac, name := range updated {
		result = append(result, netcfg.InterfaceNameBinding{PermanentMAC: mac, Name: name})
	}
	if _, err := netcfg.GenerateInterfaceLinks(result); err != nil {
		return nil, err
	}
	sort.Slice(result, func(i, j int) bool { return result[i].PermanentMAC < result[j].PermanentMAC })
	return result, nil
}

func handleNetworkInterfaceNames(w http.ResponseWriter, r *http.Request) {
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
	if err := r.ParseForm(); err != nil {
		renderNetwork(w, r, "Ungültige Anfrage.", "")
		return
	}
	ifaces, err := collect.Interfaces()
	if err != nil {
		renderNetwork(w, r, "Netzwerkadapter konnten nicht gelesen werden: "+err.Error(), "")
		return
	}
	previous, err := netcfg.LoadInterfaceNameBindings(interfaceNamesPath())
	if err != nil {
		renderNetwork(w, r, "Gespeicherte Netzwerknamen sind ungültig: "+err.Error(), "")
		return
	}
	updated, err := updateInterfaceNameBindings(ifaces, r.Form["permanent_mac"], r.Form["desired_name"], previous)
	if err != nil {
		renderNetwork(w, r, err.Error(), "")
		return
	}
	if err := audit.Log(zones.StateDir(), audit.Entry{User: session.Username, Action: "network/interface-names/save-start", Target: fmt.Sprintf("adapters=%d", len(updated)), Result: "started"}); err != nil {
		renderNetwork(w, r, "Audit-Log nicht schreibbar; Änderung wurde nicht gespeichert.", "")
		return
	}
	if err := netcfg.SaveInterfaceNameBindings(interfaceNamesPath(), updated); err != nil {
		_ = audit.Log(zones.StateDir(), audit.Entry{User: session.Username, Action: "network/interface-names/save", Target: fmt.Sprintf("adapters=%d", len(updated)), Result: "fehler", Detail: err.Error()})
		renderNetwork(w, r, "Netzwerknamen konnten nicht gespeichert werden: "+err.Error(), "")
		return
	}
	_ = audit.Log(zones.StateDir(), audit.Entry{User: session.Username, Action: "network/interface-names/save", Target: fmt.Sprintf("adapters=%d", len(updated)), Result: "ok"})
	renderNetwork(w, r, "", "Netzwerk-Namenszuordnung gespeichert. Die Systemdateien wurden noch nicht angewendet.")
}

func setForwarding(session authSession, family string, enable bool) (string, error) {
	var target *forwardingFamily
	for i := range forwardingFamilies {
		if forwardingFamilies[i].Family == family {
			target = &forwardingFamilies[i]
		}
	}
	if target == nil {
		return "", fmt.Errorf("Ungültiges Protokoll.")
	}
	value := "0"
	if enable {
		value = "1"
	}
	if err := runAsRoot(session.SudoPassword, "sysctl", "-w", target.Key+"="+value); err != nil {
		return "", fmt.Errorf("Forwarding konnte nicht gesetzt werden: %w", err)
	}

	var content strings.Builder
	content.WriteString("# Managed-By: SWAT\n")
	for _, current := range readForwarding() {
		state := "0"
		if current.Enabled {
			state = "1"
		}
		fmt.Fprintf(&content, "%s = %s\n", current.Key, state)
	}
	staging := filepath.Join(zones.StateDir(), "forwarding.conf")
	if err := zones.WriteFileAtomic(staging, []byte(content.String())); err != nil {
		return "", err
	}
	if err := runAsRoot(session.SudoPassword, "install", "-m", "0644", staging, forwardingSysctlFile); err != nil {
		return "", fmt.Errorf("%s-Forwarding ist gesetzt, konnte aber nicht dauerhaft gespeichert werden: %w", target.Label, err)
	}
	state := "deaktiviert"
	if enable {
		state = "aktiviert"
	}
	return target.Label + "-Forwarding " + state + ".", nil
}
