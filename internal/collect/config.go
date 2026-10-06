package collect

import (
	"os/exec"
	"strconv"
	"strings"
)

// ConfigPage is the common read-only representation used by configuration views.

type ConfigPage struct {
	ID             string
	Title          string
	Description    string
	Owner          string
	Status         string
	StatusLabel    string
	ReadOnly       bool
	ReadOnlyReason string
	Sections       []ConfigSection
}

// ConfigSection is one consistent, tabular section on a configuration page.
type ConfigSection struct {
	Title       string
	Description string
	Columns     []string
	Rows        [][]string
	RawText     string
	EmptyText   string
}

// NetworkConfig adapts native network state to the common config view.
func NetworkConfig(ifaces []Interface, runtime NetworkRuntime) ConfigPage {
	rows := make([][]string, 0, len(ifaces))
	for _, iface := range ifaces {
		addresses := make([]string, 0, len(iface.Addrs))
		for _, addr := range iface.Addrs {
			addresses = append(addresses, addr.Local+"/"+strconv.Itoa(addr.PrefixLen)+" ("+addr.Family+")")
		}
		rows = append(rows, []string{iface.Name, interfaceState(iface), strings.Join(addresses, "\n")})
	}

	page := ConfigPage{
		ID:          "network",
		Title:       "Netzwerk",
		Description: "Interfaces, systemd-networkd, Resolver, Forwarding und native Netzwerkdateien.",
		Owner:       "systemd-networkd.service / systemd-resolved.service",
		Status:      configStatus(len(rows) > 0),
		StatusLabel: configStatusLabel(len(rows) > 0),
		ReadOnly:    true,
		Sections: []ConfigSection{{
			Title:     "Interfaces",
			Columns:   []string{"Interface", "Status", "Adressen"},
			Rows:      rows,
			EmptyText: "Keine Netzwerk-Interfaces gefunden.",
		}},
	}
	ownership := ServiceOwnerships()
	networkOwner := "-"
	resolverOwner := "-"
	conflictRows := make([][]string, 0)
	for _, item := range ownership {
		if item.Domain == "Netzwerk" || item.Domain == "DNS-Resolver" || item.Domain == "Firewall" {
			conflictRows = append(conflictRows, []string{item.Domain, item.Owner, item.StateLabel, item.Recommendation})
			if item.Domain == "Netzwerk" && item.Owner != "-" {
				networkOwner = item.Owner
			}
			if item.Domain == "DNS-Resolver" && item.Owner != "-" {
				resolverOwner = item.Owner
			}
			if item.State == "warn" {
				page.Status = "warn"
				page.StatusLabel = "Änderungen gesperrt"
				page.ReadOnlyReason = "Konfiguration kann nicht sicher angewendet werden, solange konkurrierende Dienste erkannt werden."
			}
		}
	}
	page.Owner = networkOwner + " / " + resolverOwner
	if reason := ServiceRestriction("Netzwerk", "systemd-networkd.service", "systemd-networkd.service"); reason != "" {
		page.Status = "warn"
		page.StatusLabel = "Änderungen gesperrt"
		page.ReadOnlyReason = reason
	}
	page.Sections = append(page.Sections, ConfigSection{
		Title:       "Konfigurationsbesitz und Konflikte",
		Description: "Apply bleibt gesperrt, solange mehrere konkurrierende Netzwerk-, DNS- oder Firewall-Dienste aktiv oder für den Start aktiviert sind.",
		Columns:     []string{"Bereich", "Aktiver Besitzer", "Status", "Empfehlung"},
		Rows:        conflictRows,
		EmptyText:   "Keine Besitzinformationen verfügbar.",
	})
	page.Sections = append(page.Sections,
		ConfigSection{
			Title:   "Systemstatus",
			Columns: []string{"Bereich", "Status"},
			Rows: [][]string{
				{"systemd-networkd", runtime.Networkd},
				{"systemd-resolved", runtime.Resolved},
				{"IPv4 Forwarding", runtime.IPv4Forwarding},
				{"IPv6 Forwarding", runtime.IPv6Forwarding},
			},
			EmptyText: "Kein Netzwerkstatus verfügbar.",
		},
		ConfigSection{
			Title:       "DNS-Resolver",
			Description: "Aktueller Status von systemd-resolved. Konfigurationsänderungen bleiben bis zur Einführung eines autorisierten Writers schreibgeschützt.",
			RawText:     runtime.DNS,
			EmptyText:   "Kein Resolverstatus verfügbar.",
		},
	)
	fileRows := make([][]string, 0, len(runtime.Files))
	for _, file := range runtime.Files {
		fileRows = append(fileRows, []string{file.Name, file.Path, file.Size})
	}
	page.Sections = append(page.Sections, ConfigSection{
		Title:       "systemd-networkd-Konfiguration",
		Description: "Erkannte native Dateien. SWAT schreibt aktuell keine bestehenden Dateien um.",
		Columns:     []string{"Datei", "Pfad", "Größe"},
		Rows:        fileRows,
		EmptyText:   "Keine .network-, .netdev- oder .link-Dateien gefunden.",
	})
	return page
}

func interfaceState(iface Interface) string {
	if iface.Name == "lo" {
		return "lokal"
	}
	if strings.EqualFold(iface.OperState, "unknown") && (strings.HasPrefix(iface.Name, "tun") || strings.HasPrefix(iface.Name, "tap") || strings.HasPrefix(iface.Name, "veth")) {
		return "virtuell"
	}
	return iface.OperState
}

// FirewallConfig adapts the native nftables inventory to the common config view.
func FirewallConfig(ruleset *Ruleset) ConfigPage {
	available := firewallBackendAvailable(ruleset)
	page := ConfigPage{
		ID:          "firewall",
		Title:       "Firewall",
		Description: "Aktuelle nftables-Konfiguration und erkannte Chains.",
		Owner:       "nftables.service / firewalld.service",
		Status:      configStatus(available),
		StatusLabel: configStatusLabel(available),
		ReadOnly:    true,
	}
	if reason := ServiceRestriction("Firewall", "firewalld.service oder nftables", "firewalld.service"); reason != "" {
		page.Status = "warn"
		page.StatusLabel = "Änderungen gesperrt"
		page.ReadOnlyReason = reason
	}
	if ruleset == nil {
		ruleset = &Ruleset{}
	}

	tableRows := make([][]string, 0, len(ruleset.Tables))
	for _, table := range ruleset.Tables {
		tableRows = append(tableRows, []string{table.Family, table.Name, strconv.Itoa(table.Handle)})
	}
	page.Sections = append(page.Sections, ConfigSection{
		Title:     "Tabellen",
		Columns:   []string{"Family", "Name", "Handle"},
		Rows:      tableRows,
		EmptyText: "Keine nftables-Tabellen gefunden.",
	})

	chainRows := make([][]string, 0, len(ruleset.Chains))
	for _, chain := range ruleset.Chains {
		chainRows = append(chainRows, []string{chain.Table, chain.Name, chain.Hook, chain.Policy})
	}
	page.Sections = append(page.Sections, ConfigSection{
		Title:     "Chains",
		Columns:   []string{"Tabelle", "Name", "Hook", "Policy"},
		Rows:      chainRows,
		EmptyText: "Keine nftables-Chains gefunden.",
	})
	page.Sections = append(page.Sections, ConfigSection{
		Title:     "Rohes Regelwerk",
		RawText:   ruleset.RawText,
		EmptyText: "Kein Regelwerk sichtbar; Backend vorhanden, aber Regeln fehlen oder Leserechte sind nicht ausreichend.",
	})

	return page
}

func LibvirtConfig(runtime LibvirtRuntime) ConfigPage {
	available := runtime.Available == "verfügbar"
	page := ConfigPage{
		ID:          "libvirt",
		Title:       "Libvirt",
		Description: "Systemverbindung, Virtualisierungshost, Netzwerke und Speicherpools.",
		Owner:       "libvirtd.service / virtqemud.service",
		Status:      configStatus(available),
		StatusLabel: runtime.Available,
		ReadOnly:    true,
	}
	if reason := ServiceRestriction("Virtualisierung", "libvirtd.service oder virtqemud.service", "libvirtd.service", "virtqemud.service"); reason != "" {
		page.Status = "warn"
		page.StatusLabel = "Änderungen gesperrt"
		page.ReadOnlyReason = reason
	}
	if page.StatusLabel == "" {
		page.StatusLabel = configStatusLabel(available)
	}
	page.Sections = append(page.Sections, ConfigSection{
		Title:     "Globale Einstellungen",
		Columns:   []string{"Bereich", "Wert"},
		Rows:      [][]string{{"URI", runtime.URI}, {"Version", runtime.Version}, {"Zustand", runtime.Available}},
		EmptyText: "Keine Libvirt-Laufzeitdaten verfügbar.",
	})
	page.Sections = append(page.Sections, ConfigSection{
		Title:       "Virtualisierungshost",
		Description: runtime.Hint,
		RawText:     runtime.NodeInfo,
		EmptyText:   "Keine Hostinformationen verfügbar.",
	})
	page.Sections = append(page.Sections, ConfigSection{
		Title:     "Virtuelle Netzwerke",
		Columns:   []string{"Name", "Status", "Autostart", "Persistent"},
		Rows:      runtime.Networks,
		EmptyText: "Keine Libvirt-Netzwerke gefunden.",
	})
	page.Sections = append(page.Sections, ConfigSection{
		Title:     "Speicherpools",
		Columns:   []string{"Name", "Status", "Autostart", "Persistent"},
		Rows:      runtime.Pools,
		EmptyText: "Keine Libvirt-Speicherpools gefunden.",
	})
	return page
}

func firewallBackendAvailable(ruleset *Ruleset) bool {
	if ruleset != nil && (len(ruleset.Tables) > 0 || len(ruleset.Chains) > 0 || ruleset.RawText != "") {
		return true
	}
	if _, err := exec.LookPath("nft"); err == nil {
		return true
	}
	if _, err := exec.LookPath("firewall-cmd"); err == nil {
		return true
	}
	for _, item := range ServiceOwnerships() {
		if item.Domain == "Firewall" && item.State != "missing" {
			return true
		}
	}
	return false
}

func configStatus(available bool) string {
	if available {
		return "ok"
	}
	return "muted"
}

func configStatusLabel(available bool) string {
	if available {
		return "verfügbar"
	}
	return "nicht verfügbar"
}
