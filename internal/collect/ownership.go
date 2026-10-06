package collect

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

type ServiceOwnership struct {
	Domain         string
	Purpose        string
	Owner          string
	Competitors    string
	ManagedBy      string
	State          string
	StateLabel     string
	Services       string
	Recommendation string
}

type ownershipDefinition struct {
	Domain      string
	Purpose     string
	Units       []string
	Recommended string
}

var ownershipDefinitions = []ownershipDefinition{
	{Domain: "Netzwerk", Purpose: "Interfaces, Adressen, Routen und Verbindungen", Recommended: "systemd.network", Units: []string{"systemd-networkd.service", "NetworkManager.service", "dhcpcd.service", "connman.service"}},
	{Domain: "DNS-Resolver", Purpose: "Lokale Namensauflösung und Upstream-DNS", Recommended: "systemd-resolved", Units: []string{"systemd-resolved.service", "NetworkManager.service", "dnsmasq.service", "unbound.service"}},
	{Domain: "Firewall", Purpose: "Firewall-Regeln und Sicherheitsrichtlinien", Recommended: "nftables/firewalld", Units: []string{"firewalld.service", "ufw.service"}},
	{Domain: "Virtualisierung", Purpose: "Libvirt- und QEMU-Gäste", Recommended: "libvirtd.service", Units: []string{"libvirtd.service", "virtqemud.service"}},
	{Domain: "Zeit", Purpose: "Synchronisierung der Systemzeit", Recommended: "systemd-timesyncd.service", Units: []string{"systemd-timesyncd.service", "chronyd.service", "ntpd.service"}},
	{Domain: "mDNS", Purpose: "Dienstsuche und .local-Namensauflösung", Recommended: "avahi-daemon.service", Units: []string{"avahi-daemon.service"}},
}

func ServiceOwnerships() []ServiceOwnership {
	result := make([]ServiceOwnership, 0, len(ownershipDefinitions))
	for _, definition := range ownershipDefinitions {
		statuses := make([]unitStatus, 0, len(definition.Units))
		for _, unit := range definition.Units {
			statuses = append(statuses, inspectUnit(unit))
		}

		active := filterStatuses(statuses, func(status unitStatus) bool { return status.Active == "active" })
		enabled := filterStatuses(statuses, func(status unitStatus) bool { return status.Enabled == "enabled" })
		available := filterStatuses(statuses, func(status unitStatus) bool { return status.Enabled != "not-found" })

		state, label := "missing", "fehlt"
		if len(active) == 1 {
			state, label = "ok", "OK"
		} else if len(active) > 1 || len(enabled) > 1 {
			state, label = "warn", "Konflikt"
		} else if len(available) > 0 {
			state, label = "muted", "inaktiv"
		}

		owner := "-"
		if len(active) > 0 {
			owner = active[0].Unit
		} else if len(enabled) > 0 {
			owner = enabled[0].Unit
		}
		competitors := make([]string, 0)
		for _, status := range statuses {
			if status.Unit == owner || (status.Active != "active" && status.Enabled != "enabled") {
				continue
			}
			competitors = append(competitors, status.Unit)
		}
		managedBy := "System"
		if swatManagesDomain(definition.Domain) {
			managedBy = "SWAT"
		}
		result = append(result, ServiceOwnership{
			Domain: definition.Domain, Purpose: definition.Purpose, Owner: owner,
			Competitors: strings.Join(competitors, ", "),
			ManagedBy:   managedBy,
			State:       state, StateLabel: label, Services: strings.Join(definition.Units, ", "),
			Recommendation: definition.Recommended,
		})
	}
	return result
}

func ServiceRestriction(domain, expected string, allowed ...string) string {
	for _, ownership := range ServiceOwnerships() {
		if ownership.Domain != domain {
			continue
		}
		if ownership.State == "warn" {
			return "Konfiguration kann nicht sicher angewendet werden, solange konkurrierende Dienste erkannt werden."
		}
		if ownership.Owner != "-" && !containsService(allowed, ownership.Owner) {
			return "Für die Verwaltung ist " + expected + " vorgesehen. Aktuell wird " + ownership.Owner + " verwendet. Verwenden Sie den vorgesehenen Dienst, um die Verwaltung hier zu aktivieren."
		}
	}
	return ""
}

func containsService(services []string, service string) bool {
	for _, candidate := range services {
		if candidate == service {
			return true
		}
	}
	return false
}

func swatManagesDomain(domain string) bool {
	paths := map[string][]string{
		"Netzwerk":     {"/etc/swat/network/desired.yaml", "/etc/systemd/network/90-swat-*"},
		"DNS-Resolver": {"/etc/swat/dns/desired.yaml", "/etc/systemd/resolved.conf.d/90-swat.conf"},
		"Firewall":     {"/etc/swat/firewall/desired.yaml", "/etc/nftables.d/90-swat.nft"},
	}
	for _, pattern := range paths[domain] {
		if matches, _ := filepath.Glob(pattern); len(matches) > 0 {
			return true
		}
		if info, err := os.Stat(pattern); err == nil && !info.IsDir() {
			return true
		}
	}
	return false
}

type unitStatus struct {
	Unit    string
	Active  string
	Enabled string
}

func inspectUnit(unit string) unitStatus {
	return unitStatus{Unit: unit, Active: systemctlState("is-active", unit), Enabled: systemctlState("is-enabled", unit)}
}

func systemctlState(action, unit string) string {
	cmd := exec.Command("systemctl", action, unit, "--no-pager")
	var stdout bytes.Buffer
	cmd.Stdout = &stdout
	if err := cmd.Run(); err != nil && stdout.Len() == 0 {
		return "not-found"
	}
	state := strings.TrimSpace(stdout.String())
	if state == "" {
		return "not-found"
	}
	return state
}

func filterStatuses(statuses []unitStatus, predicate func(unitStatus) bool) []unitStatus {
	filtered := make([]unitStatus, 0, len(statuses))
	for _, status := range statuses {
		if predicate(status) {
			filtered = append(filtered, status)
		}
	}
	return filtered
}
