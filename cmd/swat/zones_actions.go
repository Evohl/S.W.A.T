package main

import (
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"swat/internal/audit"
	"swat/internal/collect"
	"swat/internal/zones"
)

const zonesConfirmWindow = 60 * time.Second

// pendingApply is a firewall change that is rolled back unless confirmed in time.
type pendingApply struct {
	Deadline time.Time
	previous string
	password string
	user     string
	timer    *time.Timer
}

var zonesState = struct {
	sync.Mutex
	pending *pendingApply
}{}

type zoneRow struct {
	zones.Zone
	ServicesText string
	PortsText    string
}

type matrixCell struct {
	From    string
	To      string
	Self    bool
	Label   string
	Class   string
	Masq    bool
	PortNAT bool
}

type matrixRow struct {
	From  string
	Cells []matrixCell
}

type ifaceOption struct {
	Name string
	Zone string
}

type serviceRow struct {
	Name    string
	Detail  string
	Checked bool
	CanNAT  bool
	NAT     string
}

type customRow struct {
	Port    string
	To      string
	Comment string
}

type zoneForm struct {
	Name        string
	Input       string
	Isolated    bool
	Interfaces  map[string]bool
	ServiceRows []serviceRow
	Custom      []customRow
}

type policyForm struct {
	From, To    string
	Mode        string
	Masquerade  bool
	ServiceRows []serviceRow
	Custom      []customRow
}

// serviceRows lists every known service; withNAT adds the translation field where it is unambiguous.
func serviceRows(selected map[string]bool, nat map[string]string, withNAT bool) []serviceRow {
	names := zones.ServiceNames()
	rows := make([]serviceRow, len(names))
	for i, name := range names {
		rows[i] = serviceRow{Name: name, Detail: zones.ServiceDetail(name), Checked: selected[name], CanNAT: withNAT && zones.CanTranslate(name), NAT: nat[name]}
	}
	return rows
}

// customRows returns the existing custom ports plus one empty row for new ones.
func customRows(ports []zones.Port) []customRow {
	rows := make([]customRow, 0, len(ports)+1)
	for _, port := range ports {
		rows = append(rows, customRow{Port: port.String(), To: port.To, Comment: port.Comment})
	}
	return append(rows, customRow{})
}

func handleFirewall(w http.ResponseWriter, r *http.Request) {
	renderZones(w, r, "", "")
}

func renderZones(w http.ResponseWriter, r *http.Request, actionError, actionSuccess string) {
	dir := zones.StateDir()
	cfg, loadErr := zones.Load(dir)
	if loadErr != nil && actionError == "" {
		actionError = "Gespeicherte Zonen konnten nicht gelesen werden: " + loadErr.Error()
	}

	rows := make([]zoneRow, 0, len(cfg.Zones))
	for _, zone := range cfg.Zones {
		row := zoneRow{Zone: zone, ServicesText: strings.Join(zone.Services, ", ")}
		row.PortsText = portsText(zone.Ports)
		rows = append(rows, row)
	}

	matrix := make([]matrixRow, 0, len(cfg.Zones))
	for _, from := range cfg.Zones {
		row := matrixRow{From: from.Name}
		for _, to := range cfg.Zones {
			cell := matrixCell{From: from.Name, To: to.Name, Self: from.Name == to.Name}
			switch policy, ok := cfg.Policy(from.Name, to.Name); {
			case cell.Self:
				cell.Label, cell.Class = "intern", "muted"
				if from.Isolated {
					cell.Label = "isoliert"
				}
			case !ok:
				cell.Label, cell.Class = "gesperrt", "fail"
			case policy.Mode == zones.ModeAllow:
				cell.Label, cell.Class, cell.Masq, cell.PortNAT = "erlaubt", "ok", policy.Masquerade, policy.HasTranslation()
			default:
				cell.Label, cell.Class, cell.Masq, cell.PortNAT = "eingeschränkt", "warn", policy.Masquerade, policy.HasTranslation()
			}
			row.Cells = append(row.Cells, cell)
		}
		matrix = append(matrix, row)
	}

	assigned := make(map[string]string)
	for _, zone := range cfg.Zones {
		for _, iface := range zone.Interfaces {
			assigned[iface] = zone.Name
		}
	}
	var options []ifaceOption
	seen := make(map[string]bool)
	if ifaces, err := collect.Interfaces(); err == nil {
		for _, iface := range ifaces {
			if iface.Name != "lo" {
				options = append(options, ifaceOption{Name: iface.Name, Zone: assigned[iface.Name]})
				seen[iface.Name] = true
			}
		}
	}
	for name, zone := range assigned {
		if !seen[name] {
			options = append(options, ifaceOption{Name: name, Zone: zone})
		}
	}

	editZone := zoneForm{Input: zones.InputRestricted, ServiceRows: serviceRows(map[string]bool{zones.PingService: true}, nil, false), Custom: customRows(nil)}
	if zone, ok := cfg.Zone(r.URL.Query().Get("zone")); ok {
		editZone = zoneForm{Name: zone.Name, Input: zone.Input, Isolated: zone.Isolated,
			Interfaces: toSet(zone.Interfaces), ServiceRows: serviceRows(toSet(zone.Services), nil, false), Custom: customRows(zone.Ports)}
	}
	editPolicy := policyForm{Mode: zones.ModeAllow, ServiceRows: serviceRows(nil, nil, true), Custom: customRows(nil)}
	if policy, ok := cfg.Policy(r.URL.Query().Get("from"), r.URL.Query().Get("to")); ok {
		editPolicy = policyForm{From: policy.From, To: policy.To, Mode: policy.Mode, Masquerade: policy.Masquerade,
			ServiceRows: serviceRows(toSet(policy.Services), policy.ServiceNAT, true), Custom: customRows(policy.Ports)}
	} else if r.URL.Query().Get("from") != "" {
		editPolicy.From, editPolicy.To = r.URL.Query().Get("from"), r.URL.Query().Get("to")
	}

	script, scriptErr := zones.Generate(cfg)
	scriptNote := ""
	if scriptErr != nil {
		scriptNote = scriptErr.Error()
	}

	zonesState.Lock()
	var pending *pendingApply
	if zonesState.pending != nil {
		snapshot := *zonesState.pending
		pending = &snapshot
	}
	zonesState.Unlock()

	forwarding := true
	if value, err := os.ReadFile("/proc/sys/net/ipv4/ip_forward"); err == nil {
		forwarding = strings.TrimSpace(string(value)) == "1"
	}

	ruleset, err := collect.ListRuleset()
	if err != nil {
		ruleset = &collect.Ruleset{}
	}

	render(w, r, "firewall", "firewall-zones.html", map[string]any{
		"Active":             collect.FirewallConfig(ruleset),
		"Zones":              rows,
		"Policies":           cfg.Policies,
		"ZoneNames":          zoneNames(cfg),
		"Matrix":             matrix,
		"IfaceOptions":       options,
		"ServiceOptions":     zones.ServiceNames(),
		"EditZone":           editZone,
		"EditPolicy":         editPolicy,
		"Script":             script,
		"ScriptNote":         scriptNote,
		"Pending":            pending,
		"PendingSeconds":     int(zonesConfirmWindow.Seconds()),
		"ForwardingDisabled": !forwarding,
		"ZoneActionError":    actionError,
		"ZoneActionSuccess":  actionSuccess,
	})
}

func handleZonesAction(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Methode nicht erlaubt", http.StatusMethodNotAllowed)
		return
	}
	session, err := accountActionSession(r)
	if err != nil {
		renderZones(w, r, err.Error(), "")
		return
	}
	dir := zones.StateDir()
	action := r.FormValue("action")
	var message string
	switch action {
	case "save-zone", "delete-zone", "save-policy", "delete-policy":
		message, err = editZonesConfig(dir, action, r)
	case "apply":
		message, err = applyZones(dir, session)
	case "confirm":
		message, err = confirmZones(dir, session)
	case "rollback":
		message, err = rollbackZones(dir, session.Username, "manuell")
	default:
		err = fmt.Errorf("Ungültige Aktion.")
	}
	result := "ok"
	if err != nil {
		result = "fehler"
	}
	detail := ""
	if err != nil {
		detail = err.Error()
	}
	_ = audit.Log(dir, audit.Entry{User: session.Username, Action: "zones/" + action, Target: r.FormValue("name") + r.FormValue("from") + ">" + r.FormValue("to"), Result: result, Detail: detail})
	if err != nil {
		renderZones(w, r, err.Error(), "")
		return
	}
	renderZones(w, r, "", message)
}

func editZonesConfig(dir, action string, r *http.Request) (string, error) {
	cfg, err := zones.Load(dir)
	if err != nil {
		return "", err
	}
	switch action {
	case "save-zone":
		ports, err := customPolicyPorts(r.Form["custom_port"], nil, r.Form["custom_comment"])
		if err != nil {
			return "", err
		}
		zone := zones.Zone{
			Name: strings.TrimSpace(r.FormValue("name")), Interfaces: r.Form["interfaces"],
			Input: r.FormValue("input"), Isolated: r.FormValue("isolated") != "",
			Access: zones.Access{Services: r.Form["services"], Ports: ports},
		}
		moved := toSet(zone.Interfaces)
		for i := range cfg.Zones {
			var kept []string
			for _, iface := range cfg.Zones[i].Interfaces {
				if !moved[iface] || cfg.Zones[i].Name == zone.Name {
					kept = append(kept, iface)
				}
			}
			cfg.Zones[i].Interfaces = kept
		}
		replaced := false
		for i := range cfg.Zones {
			if cfg.Zones[i].Name == zone.Name {
				cfg.Zones[i], replaced = zone, true
			}
		}
		if !replaced {
			cfg.Zones = append(cfg.Zones, zone)
		}
		if err := zones.Save(dir, cfg); err != nil {
			return "", err
		}
		return "Zone " + zone.Name + " gespeichert. Sie ist erst nach „Anwenden“ aktiv.", nil
	case "delete-zone":
		name := r.FormValue("name")
		kept := cfg.Zones[:0]
		for _, zone := range cfg.Zones {
			if zone.Name != name {
				kept = append(kept, zone)
			}
		}
		cfg.Zones = kept
		policies := cfg.Policies[:0]
		for _, policy := range cfg.Policies {
			if policy.From != name && policy.To != name {
				policies = append(policies, policy)
			}
		}
		cfg.Policies = policies
		if err := zones.Save(dir, cfg); err != nil {
			return "", err
		}
		return "Zone " + name + " und ihre Richtlinien wurden entfernt. Sie wird erst nach „Anwenden“ wirksam.", nil
	case "save-policy":
		ports, err := customPolicyPorts(r.Form["custom_port"], r.Form["custom_to"], r.Form["custom_comment"])
		if err != nil {
			return "", err
		}
		serviceNAT := make(map[string]string)
		for _, name := range r.Form["services"] {
			if target := strings.TrimSpace(r.FormValue("nat_" + name)); target != "" {
				serviceNAT[name] = target
			}
		}
		if len(serviceNAT) == 0 {
			serviceNAT = nil
		}
		policy := zones.Policy{
			From: r.FormValue("from"), To: r.FormValue("to"), Mode: r.FormValue("mode"), Masquerade: r.FormValue("masquerade") != "",
			Access: zones.Access{Services: r.Form["services"], Ports: ports, ServiceNAT: serviceNAT},
		}
		replaced := false
		for i := range cfg.Policies {
			if cfg.Policies[i].From == policy.From && cfg.Policies[i].To == policy.To {
				cfg.Policies[i], replaced = policy, true
			}
		}
		if !replaced {
			cfg.Policies = append(cfg.Policies, policy)
		}
		if err := zones.Save(dir, cfg); err != nil {
			return "", err
		}
		return "Richtlinie " + policy.From + " → " + policy.To + " gespeichert. Sie ist erst nach „Anwenden“ aktiv.", nil
	default:
		from, to := r.FormValue("from"), r.FormValue("to")
		kept := cfg.Policies[:0]
		for _, policy := range cfg.Policies {
			if policy.From != from || policy.To != to {
				kept = append(kept, policy)
			}
		}
		cfg.Policies = kept
		if err := zones.Save(dir, cfg); err != nil {
			return "", err
		}
		return "Richtlinie " + from + " → " + to + " entfernt: Verkehr ist nun gesperrt, sobald angewendet wird.", nil
	}
}

func applyZones(dir string, session authSession) (string, error) {
	cfg, err := zones.Load(dir)
	if err != nil {
		return "", err
	}
	script, err := zones.Generate(cfg)
	if err != nil {
		return "", err
	}
	zonesState.Lock()
	defer zonesState.Unlock()
	if zonesState.pending != nil {
		return "", fmt.Errorf("Eine Änderung wartet noch auf Bestätigung oder Rücknahme.")
	}
	previous := zones.RemoveScript
	if data, err := os.ReadFile(filepath.Join(dir, "applied.nft")); err == nil {
		previous = string(data)
	}
	pendingPath := filepath.Join(dir, "pending.nft")
	if err := zones.WriteFileAtomic(pendingPath, []byte(script)); err != nil {
		return "", err
	}
	if err := runAsRoot(session.SudoPassword, "nft", "-c", "-f", pendingPath); err != nil {
		return "", fmt.Errorf("nftables hat die Regeln abgelehnt: %w", err)
	}
	if err := audit.Log(dir, audit.Entry{User: session.Username, Action: "zones/apply-start", Target: "inet swat", Result: "ok"}); err != nil {
		return "", fmt.Errorf("Audit-Log nicht schreibbar, Änderung abgebrochen: %w", err)
	}
	if err := runAsRoot(session.SudoPassword, "nft", "-f", pendingPath); err != nil {
		return "", fmt.Errorf("Regeln konnten nicht geladen werden: %w", err)
	}
	pending := &pendingApply{Deadline: time.Now().Add(zonesConfirmWindow), previous: previous, password: session.SudoPassword, user: session.Username}
	pending.timer = time.AfterFunc(zonesConfirmWindow, func() {
		zonesState.Lock()
		defer zonesState.Unlock()
		if zonesState.pending == pending {
			rollbackLocked(dir, pending, "automatisch")
		}
	})
	zonesState.pending = pending
	return fmt.Sprintf("Regeln geladen. Ohne Bestätigung innerhalb von %d Sekunden werden sie automatisch zurückgenommen.", int(zonesConfirmWindow.Seconds())), nil
}

func confirmZones(dir string, session authSession) (string, error) {
	zonesState.Lock()
	defer zonesState.Unlock()
	pending := zonesState.pending
	if pending == nil {
		return "", fmt.Errorf("Keine Änderung wartet auf Bestätigung.")
	}
	pending.timer.Stop()
	zonesState.pending = nil
	applied := filepath.Join(dir, "applied.nft")
	if err := os.Rename(filepath.Join(dir, "pending.nft"), applied); err != nil {
		return "", err
	}
	if err := runAsRoot(session.SudoPassword, "install", "-D", "-m", "0644", applied, "/etc/swat/swat.nft"); err != nil {
		return "", fmt.Errorf("Regeln sind aktiv, konnten aber nicht nach /etc/swat/swat.nft gespeichert werden: %w", err)
	}
	return "Änderung bestätigt. Die Regeln liegen in /etc/swat/swat.nft; für den Start beim Booten muss diese Datei in /etc/nftables.conf eingebunden sein.", nil
}

func rollbackZones(dir, user, how string) (string, error) {
	zonesState.Lock()
	defer zonesState.Unlock()
	pending := zonesState.pending
	if pending == nil {
		return "", fmt.Errorf("Keine Änderung zum Zurücknehmen vorhanden.")
	}
	pending.timer.Stop()
	if err := rollbackLocked(dir, pending, how); err != nil {
		return "", err
	}
	return "Änderung zurückgenommen.", nil
}

func rollbackLocked(dir string, pending *pendingApply, how string) error {
	zonesState.pending = nil
	path := filepath.Join(dir, "rollback.nft")
	err := zones.WriteFileAtomic(path, []byte(pending.previous))
	if err == nil {
		err = runAsRoot(pending.password, "nft", "-f", path)
	}
	result, detail := "ok", ""
	if err != nil {
		result, detail = "fehler", err.Error()
	}
	_ = audit.Log(dir, audit.Entry{User: pending.user, Action: "zones/rollback", Target: how, Result: result, Detail: detail})
	pending.password = ""
	return err
}

// customPolicyPorts pairs each custom port row with its optional translate-to and comment fields.
func customPolicyPorts(ports, targets, comments []string) ([]zones.Port, error) {
	var result []zones.Port
	for i, text := range ports {
		text = strings.TrimSpace(text)
		if text == "" {
			continue
		}
		parsed, err := zones.ParsePorts(text)
		if err != nil {
			return nil, err
		}
		if len(parsed) != 1 {
			return nil, fmt.Errorf("Pro Zeile ist genau ein Port oder Bereich erlaubt: %q", text)
		}
		port := parsed[0]
		if i < len(targets) {
			port.To = strings.TrimSpace(targets[i])
		}
		if i < len(comments) {
			port.Comment = strings.TrimSpace(comments[i])
			if runes := []rune(port.Comment); len(runes) > 120 {
				port.Comment = string(runes[:120])
			}
		}
		result = append(result, port)
	}
	return result, nil
}

func zoneNames(cfg zones.Config) []string {
	names := make([]string, len(cfg.Zones))
	for i, zone := range cfg.Zones {
		names[i] = zone.Name
	}
	return names
}

func portsText(ports []zones.Port) string {
	items := make([]string, len(ports))
	for i, port := range ports {
		items[i] = port.String()
	}
	return strings.Join(items, ", ")
}

func toSet(items []string) map[string]bool {
	set := make(map[string]bool, len(items))
	for _, item := range items {
		set[item] = true
	}
	return set
}
