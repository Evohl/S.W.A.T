package main

import (
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"swat/internal/audit"
	"swat/internal/collect"
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
		"ConfigPage":    page,
		"Forwarding":    readForwarding(),
		"ActionError":   actionError,
		"ActionSuccess": actionSuccess,
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
