package modules

import (
	"fmt"
	"sort"
)

const CurrentVersion = 1

type Package struct {
	Name   string
	Role   string
	Needed bool
}

type Service struct {
	Unit                  string
	Role                  string
	ConfigurationRequired bool
}

type Definition struct {
	ID         string
	Title      string
	Summary    string
	Required   bool
	Packages   []Package
	Services   []Service
	SafetyNote string
	PagePath   string
}

type Selection struct {
	Version  int      `json:"version"`
	Selected []string `json:"selected"`
}

type PackageState struct {
	Name      string
	Installed bool
	Role      string
	Needed    bool
}

type ServiceState struct {
	Unit    string
	Active  string
	Enabled string
	Role    string
}

type Status struct {
	Definition
	Selected        bool
	Ready           bool
	MissingPackages []string
	PackageStates   []PackageState
	ServiceStates   []ServiceState
}

var catalog = []Definition{
	{
		ID: "network", Title: "Netzwerk-Grundlage", Required: true,
		Summary: "Erforderliches Basisprofil für Adapter, systemd-networkd und systemd-resolved.",
		Packages: []Package{
			{Name: "systemd", Role: "udev, systemd-networkd, systemd-resolved", Needed: true},
			{Name: "iproute2", Role: "Interface-, Routen- und Adressverwaltung", Needed: true},
		},
		Services: []Service{
			{Unit: "systemd-networkd.service", Role: "Netzwerkverwaltung", ConfigurationRequired: true},
			{Unit: "systemd-resolved.service", Role: "DNS-Resolver", ConfigurationRequired: true},
		},
		SafetyNote: "Basisprofil kann nicht abgewählt werden. Netzwerkdienste werden nicht automatisch aktiviert, da das die Verbindung unterbrechen kann.",
		PagePath:   "/network",
	},
	{
		ID: "firewall", Title: "nftables-Firewall",
		Summary:    "Firewall-Zonen, Paketfilter und NAT über die native nftables-Engine.",
		Packages:   []Package{{Name: "nftables", Role: "nftables-Regelwerk und nft CLI", Needed: true}},
		Services:   []Service{{Unit: "nftables.service", Role: "Firewall-Regelwerk", ConfigurationRequired: true}},
		SafetyNote: "Firewall-Unit erst aktivieren, wenn das Ruleset validiert und ein unabhängiger Zugriffspfad bestätigt ist.",
		PagePath:   "/firewall",
	},
	{
		ID: "hotspot", Title: "WLAN-Hotspot",
		Summary: "Eigenes WLAN mit Access Point, DHCP/DNS und isolierter Gastnetz-Option.",
		Packages: []Package{
			{Name: "hostapd", Role: "WLAN Access Point", Needed: true},
			{Name: "dnsmasq", Role: "DHCP/DNS für das dedizierte Hotspot-Netz", Needed: true},
			{Name: "iw", Role: "WLAN-Hardware und AP-Fähigkeit erkennen", Needed: true},
		},
		Services: []Service{
			{Unit: "hostapd.service", Role: "Access Point", ConfigurationRequired: true},
			{Unit: "dnsmasq.service", Role: "DHCP/DNS", ConfigurationRequired: true},
		},
		SafetyNote: "Start erst nach WLAN-Hardwareprüfung, eigener DHCP-Bindung und geprüfter Firewall-/NAT-Konfiguration.",
	},
	{
		ID: "nginx", Title: "Nginx Webserver",
		Summary:    "Reverse-Proxy und statische Websites mit TLS-Zertifikatsreferenzen.",
		Packages:   []Package{{Name: "nginx", Role: "HTTP-Server und Reverse-Proxy", Needed: true}},
		Services:   []Service{{Unit: "nginx.service", Role: "Webserver", ConfigurationRequired: true}},
		SafetyNote: "Start erst nach nginx -t und Prüfung der Listener. Firewallports werden nicht automatisch geöffnet.",
		PagePath:   "/nginx",
	},
	{
		ID: "mail", Title: "Mailserver",
		Summary: "Postfix (SMTP), Dovecot (IMAP/LMTP) und Rspamd (Spamfilter, SPF/DKIM/DMARC).",
		Packages: []Package{
			{Name: "postfix", Role: "SMTP-Mailtransport", Needed: true},
			{Name: "dovecot", Role: "IMAP/LMTP und Mailbox-Zugriff", Needed: true},
			{Name: "rspamd", Role: "Spamfilter sowie SPF/DKIM/DMARC", Needed: true},
			{Name: "redis", Role: "Rspamd Bayes-, Greylisting- und Rate-Limit-Daten", Needed: false},
		},
		Services: []Service{
			{Unit: "postfix.service", Role: "SMTP", ConfigurationRequired: true},
			{Unit: "dovecot.service", Role: "IMAP/LMTP", ConfigurationRequired: true},
			{Unit: "rspamd.service", Role: "Spamfilter", ConfigurationRequired: true},
			{Unit: "redis.service", Role: "Lern-/Rate-Limit-Speicher", ConfigurationRequired: true},
		},
		SafetyNote: "Dienste erst nach Anti-Open-Relay-, TLS-, DNS- und Zustellprüfung starten. Öffentliche Ports und DNS werden nie ungefragt verändert.",
	},
	{
		ID: "fail2ban", Title: "Fail2ban",
		Summary:    "Journald-basierter Schutz für SSH und ausgewählte Web-/Maildienste.",
		Packages:   []Package{{Name: "fail2ban", Role: "Log-basierte Sperren gegen wiederholte Fehlversuche", Needed: true}},
		Services:   []Service{{Unit: "fail2ban.service", Role: "Ban-Überwachung", ConfigurationRequired: true}},
		SafetyNote: "Start erst nach Jail- und nftables-Aktionsprüfung, damit gültige Admin-Zugriffe nicht ausgesperrt werden.",
	},
}

func Catalog() []Definition {
	definitions := make([]Definition, len(catalog))
	for index, definition := range catalog {
		definitions[index] = definition
		definitions[index].Packages = append([]Package(nil), definition.Packages...)
		definitions[index].Services = append([]Service(nil), definition.Services...)
	}
	return definitions
}

func DefinitionFor(id string) (Definition, bool) {
	for index, definition := range catalog {
		if definition.ID == id {
			return Catalog()[index], true
		}
	}
	return Definition{}, false
}

func NormalizeSelection(ids []string) ([]string, error) {
	selected := make(map[string]bool, len(ids))
	for _, id := range ids {
		if _, ok := DefinitionFor(id); !ok {
			return nil, fmt.Errorf("unbekanntes SWAT-Modul %q", id)
		}
		if selected[id] {
			return nil, fmt.Errorf("SWAT-Modul %q wurde mehrfach ausgewählt", id)
		}
		selected[id] = true
	}
	for _, definition := range catalog {
		if definition.Required {
			selected[definition.ID] = true
		}
	}
	normalized := make([]string, 0, len(selected))
	for id := range selected {
		normalized = append(normalized, id)
	}
	sort.Strings(normalized)
	return normalized, nil
}

func PackagePlan(ids []string) ([]string, error) {
	normalized, err := NormalizeSelection(ids)
	if err != nil {
		return nil, err
	}
	packages := make(map[string]bool)
	for _, id := range normalized {
		definition, _ := DefinitionFor(id)
		for _, dependency := range definition.Packages {
			if dependency.Needed {
				packages[dependency.Name] = true
			}
		}
	}
	result := make([]string, 0, len(packages))
	for name := range packages {
		result = append(result, name)
	}
	sort.Strings(result)
	return result, nil
}

func Load(path string) (Selection, error) {
	selection, err := loadSelection(path)
	if err != nil {
		return Selection{}, err
	}
	return selection, nil
}

func Save(path string, ids []string) (Selection, error) {
	normalized, err := NormalizeSelection(ids)
	if err != nil {
		return Selection{}, err
	}
	selection := Selection{Version: CurrentVersion, Selected: normalized}
	if err := saveSelection(path, selection); err != nil {
		return Selection{}, err
	}
	return selection, nil
}

func Statuses(selection Selection, installedPackages map[string]bool, serviceStates map[string]ServiceState) ([]Status, error) {
	if selection.Version != CurrentVersion {
		return nil, fmt.Errorf("nicht unterstützte Modulzustandsversion %d", selection.Version)
	}
	selected, err := NormalizeSelection(selection.Selected)
	if err != nil {
		return nil, err
	}
	selectedSet := make(map[string]bool, len(selected))
	for _, id := range selected {
		selectedSet[id] = true
	}
	statuses := make([]Status, 0, len(catalog))
	for _, definition := range Catalog() {
		status := Status{Definition: definition, Selected: selectedSet[definition.ID], Ready: true}
		for _, dependency := range definition.Packages {
			installed := installedPackages[dependency.Name]
			status.PackageStates = append(status.PackageStates, PackageState{Name: dependency.Name, Installed: installed, Role: dependency.Role, Needed: dependency.Needed})
			if dependency.Needed && !installed {
				status.Ready = false
				status.MissingPackages = append(status.MissingPackages, dependency.Name)
			}
		}
		if !status.Selected {
			status.Ready = false
		}
		for _, service := range definition.Services {
			state, found := serviceStates[service.Unit]
			if !found {
				state = ServiceState{Unit: service.Unit, Active: "unknown", Enabled: "unknown"}
			}
			state.Unit, state.Role = service.Unit, service.Role
			status.ServiceStates = append(status.ServiceStates, state)
		}
		statuses = append(statuses, status)
	}
	return statuses, nil
}
