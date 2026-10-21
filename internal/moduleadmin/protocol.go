package moduleadmin

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/msteinert/pam/v2"

	"swat/internal/audit"
	"swat/internal/modules"
)

const SocketPath = "/run/swat-privileged/modules.sock"

const (
	maxRequestBytes      = 256 * 1024
	installTimeout       = 15 * time.Minute
	systemSettingTimeout = 30 * time.Second
)

const (
	operationInstallModules    = "install-modules"
	operationAuthenticateLogin = "authenticate-login"
	operationAuthenticateSudo  = "authenticate-sudo"
	operationSetSystemSetting  = "set-system-setting"
	operationAdminAction       = "admin-action"
	operationTransactionStatus = "transaction-status"
)

var accountNamePattern = regexp.MustCompile(`^[a-z_][a-z0-9_-]*$`)

func Available() bool {
	info, err := os.Stat(SocketPath)
	return err == nil && info.Mode()&os.ModeSocket != 0
}

type Request struct {
	Operation string   `json:"operation"`
	Action    string   `json:"action,omitempty"`
	Target    string   `json:"target,omitempty"`
	Modules   []string `json:"modules"`
	Setting   string   `json:"setting,omitempty"`
	Value     string   `json:"value,omitempty"`
	Value2    string   `json:"value2,omitempty"`
	Value3    string   `json:"value3,omitempty"`
	Value4    string   `json:"value4,omitempty"`
	Username  string   `json:"username"`
	Password  string   `json:"password"`
}

type Response struct {
	OK               bool      `json:"ok"`
	Installed        []string  `json:"installed,omitempty"`
	PendingUnits     []string  `json:"pending_units,omitempty"`
	Message          string    `json:"message,omitempty"`
	Error            string    `json:"error,omitempty"`
	Output           string    `json:"output,omitempty"`
	NetworkPending   bool      `json:"network_pending,omitempty"`
	FirewallPending  bool      `json:"firewall_pending,omitempty"`
	NetworkDeadline  time.Time `json:"network_deadline,omitempty"`
	FirewallDeadline time.Time `json:"firewall_deadline,omitempty"`
}

type CommandRunner func(context.Context, string, ...string) ([]byte, error)
type Authorizer func(username, password string) error

type Installer struct {
	Run             CommandRunner
	Authorize       Authorizer
	Login           Authorizer
	Audit           func(audit.Entry) error
	mu              sync.Mutex
	networkPending  *pendingNetwork
	firewallPending *pendingFirewall
}

func PAMAuthorizer(service string) Authorizer {
	if service == "" {
		service = "sudo"
	}
	return func(username, password string) error {
		if username != "root" && !isWheelMember(username) {
			return errors.New("Benutzer ist kein Mitglied der Administratorgruppe wheel")
		}
		return pamCheck(service, username, password)
	}
}

func PAMLoginAuthorizer(service string) Authorizer {
	if service == "" {
		service = "login"
	}
	return func(username, password string) error {
		return pamCheck(service, username, password)
	}
}

func pamCheck(service, username, password string) error {
	transaction, err := pam.StartFunc(service, username, func(style pam.Style, _ string) (string, error) {
		switch style {
		case pam.PromptEchoOff, pam.PromptEchoOn:
			return password, nil
		default:
			return "", errors.New("unerwartete PAM-Anfrage")
		}
	})
	if err != nil {
		return err
	}
	defer transaction.End()
	if err := transaction.Authenticate(0); err != nil {
		return err
	}
	return transaction.AcctMgmt(0)
}

func isWheelMember(username string) bool {
	account, err := user.Lookup(username)
	if err != nil {
		return false
	}
	wheel, err := user.LookupGroup("wheel")
	if err != nil {
		return false
	}
	groups, err := account.GroupIds()
	if err != nil {
		return false
	}
	for _, groupID := range groups {
		if groupID == wheel.Gid {
			return true
		}
	}
	return false
}

func SystemRunner(ctx context.Context, name string, args ...string) ([]byte, error) {
	command := exec.CommandContext(ctx, name, args...)
	command.Env = append(command.Environ(), "LC_ALL=C", "LANG=C")
	return command.CombinedOutput()
}

func (installer *Installer) Install(ctx context.Context, ids []string) (Response, error) {
	installer.mu.Lock()
	defer installer.mu.Unlock()
	if installer.Run == nil {
		installer.Run = SystemRunner
	}
	normalized, err := modules.NormalizeSelection(ids)
	if err != nil {
		return Response{}, err
	}
	packages, err := modules.PackagePlan(normalized)
	if err != nil {
		return Response{}, err
	}
	if len(packages) == 0 {
		return Response{OK: true, Message: "Keine zusätzlichen Pakete erforderlich."}, nil
	}
	missing := make([]string, 0, len(packages))
	for _, packageName := range packages {
		output, queryErr := installer.Run(ctx, "pacman", "-Q", "--", packageName)
		if queryErr != nil || !strings.HasPrefix(string(output), packageName+" ") {
			missing = append(missing, packageName)
		}
	}
	if len(missing) > 0 {
		args := append([]string{"-S", "--needed", "--noconfirm", "--"}, missing...)
		output, installErr := installer.Run(ctx, "pacman", args...)
		if installErr != nil {
			return Response{}, fmt.Errorf("pacman konnte die ausgewählten Abhängigkeiten nicht installieren: %s", summarize(output, installErr))
		}
	}
	var pendingUnits []string
	for _, id := range normalized {
		definition, _ := modules.DefinitionFor(id)
		for _, service := range definition.Services {
			if service.ConfigurationRequired {
				pendingUnits = append(pendingUnits, service.Unit)
			}
		}
	}
	sort.Strings(pendingUnits)
	return Response{
		OK: true, Installed: missing, PendingUnits: pendingUnits,
		Message: "Pakete installiert. Dienste mit erforderlicher Grundkonfiguration bleiben bis zur validierten Einrichtung gestoppt.",
	}, nil
}

func (installer *Installer) SetSystemSetting(ctx context.Context, setting, value string) (Response, error) {
	installer.mu.Lock()
	defer installer.mu.Unlock()
	if installer.Run == nil {
		installer.Run = SystemRunner
	}
	command, args, err := systemSettingCommand(ctx, installer.Run, setting, value)
	if err != nil {
		return Response{}, err
	}
	output, err := installer.Run(ctx, command, args...)
	if err != nil {
		return Response{}, fmt.Errorf("Systemeinstellung konnte nicht geändert werden: %s", summarize(output, err))
	}
	return Response{OK: true, Message: "Systemeinstellung wurde geändert."}, nil
}

func (installer *Installer) AdminAction(ctx context.Context, action, target, value, value2, value3 string) (Response, error) {
	if action == "network-forwarding" {
		return installer.SetForwarding(ctx, target, value)
	}
	if strings.HasPrefix(action, "vm-") || strings.HasPrefix(action, "libvirt-") {
		return installer.VMAction(ctx, action, target, value, value2, value3, "")
	}
	installer.mu.Lock()
	defer installer.mu.Unlock()
	if installer.Run == nil {
		installer.Run = SystemRunner
	}
	if err := validateAdminTarget(action, target, value, value2, ""); err != nil {
		return Response{}, err
	}
	command, args, err := adminActionCommand(action, target, value, value2, value3)
	if err != nil {
		return Response{}, err
	}
	output, err := installer.Run(ctx, command, args...)
	if err != nil {
		return Response{}, fmt.Errorf("Privilegierte Aktion fehlgeschlagen: %s", summarize(output, err))
	}
	return Response{OK: true, Message: "Aktion ausgeführt."}, nil
}

func validateAdminTarget(action, target, value, value2, username string) error {
	switch action {
	case "user-expire-password", "user-delete":
		if !interactiveAccount(target) || action == "user-delete" && username != "" && target == username {
			return errors.New("Systemkonten oder der angemeldete Administrator können hier nicht geändert werden.")
		}
	case "group-membership":
		if !interactiveAccount(target) {
			return errors.New("Nur echte Benutzer können Gruppenmitgliedschaften ändern.")
		}
		if _, err := user.LookupGroup(value); err != nil {
			return errors.New("Gruppe ist auf diesem System nicht vorhanden.")
		}
		if value2 == "remove" && privilegedGroups[value] {
			return errors.New("Administrative Gruppenmitgliedschaften müssen außerhalb von SWAT geändert werden.")
		}
	case "group-create":
		if _, err := user.LookupGroup(target); err == nil {
			return errors.New("Gruppe ist bereits vorhanden.")
		}
	}
	return nil
}

func interactiveAccount(name string) bool {
	account, err := user.Lookup(name)
	if err != nil {
		return false
	}
	uid, err := strconv.ParseUint(account.Uid, 10, 32)
	return err == nil && uid >= 1000
}

func adminActionCommand(action, target, value, value2, value3 string) (string, []string, error) {
	switch action {
	case "user-create":
		if !accountNamePattern.MatchString(target) || len(value2) > 128 || strings.ContainsAny(value2, "\x00\n") {
			return "", nil, errors.New("Ungültige Benutzerdaten.")
		}
		shell := value
		if shell != "/bin/bash" && shell != "/bin/zsh" && shell != "/usr/bin/fish" && shell != "/usr/sbin/nologin" {
			return "", nil, errors.New("Ungültige Login-Shell.")
		}
		home := value3
		if home == "" {
			home = filepath.Join("/home", target)
		}
		if !filepath.IsAbs(home) || strings.Contains(home, "..") || filepath.Clean(home) != filepath.Join("/home", target) {
			return "", nil, errors.New("Das Home-Verzeichnis muss /home/<Benutzername> sein.")
		}
		return "useradd", []string{"-m", "-s", shell, "-c", value2, "-d", home, target}, nil
	case "group-create":
		if !accountNamePattern.MatchString(target) {
			return "", nil, errors.New("Ungültiger Gruppenname.")
		}
		args := []string{"groupadd"}
		if value != "" {
			gid, err := strconv.ParseUint(value, 10, 32)
			if err != nil || gid < 1000 {
				return "", nil, errors.New("Ungültige Gruppen-ID.")
			}
			args = append(args, "-g", value)
		}
		return "groupadd", append(args[1:], target), nil
	case "user-expire-password", "user-delete":
		if !accountNamePattern.MatchString(target) {
			return "", nil, errors.New("Ungültiger Benutzername.")
		}
		if action == "user-expire-password" {
			return "chage", []string{"-d", "0", target}, nil
		}
		return "userdel", []string{target}, nil
	case "group-membership":
		if !accountNamePattern.MatchString(target) || !accountNamePattern.MatchString(value) {
			return "", nil, errors.New("Ungültiger Benutzer oder Gruppe.")
		}
		switch value2 {
		case "add":
			if privilegedGroups[value] {
				return "", nil, errors.New("Administrative Gruppen können nicht über S.W.A.T vergeben werden.")
			}
			return "usermod", []string{"-a", "-G", value, target}, nil
		case "remove":
			return "gpasswd", []string{"-d", target, value}, nil
		default:
			return "", nil, errors.New("Ungültige Gruppenaktion.")
		}
	case "service":
		if !catalogServiceUnit(target) {
			return "", nil, errors.New("Service ist nicht für Helper-Aktionen freigegeben.")
		}
		if value != "start" && value != "stop" && value != "enable" && value != "disable" {
			return "", nil, errors.New("Ungültige Service-Aktion.")
		}
		if value == "start" || value == "enable" {
			if serviceRequiresConfiguration(target) {
				return "", nil, errors.New("Service bleibt bis zur validierten Konfiguration gestoppt.")
			}
		}
		return "systemctl", []string{value, "--", target}, nil
	case "network-forwarding":
		key := ""
		switch target {
		case "ipv4":
			key = "net.ipv4.ip_forward"
		case "ipv6":
			key = "net.ipv6.conf.all.forwarding"
		default:
			return "", nil, errors.New("Ungültige Forwarding-Familie.")
		}
		if value != "0" && value != "1" {
			return "", nil, errors.New("Ungültiger Forwarding-Status.")
		}
		return "sysctl", []string{"-w", key + "=" + value}, nil
	default:
		return "", nil, errors.New("Unbekannte privilegierte Aktion.")
	}
}

func (installer *Installer) SetForwarding(ctx context.Context, family, value string) (Response, error) {
	installer.mu.Lock()
	defer installer.mu.Unlock()
	if installer.Run == nil {
		installer.Run = SystemRunner
	}
	command, args, err := adminActionCommand("network-forwarding", family, value, "", "")
	if err != nil {
		return Response{}, err
	}
	output, err := installer.Run(ctx, command, args...)
	if err != nil {
		return Response{}, fmt.Errorf("Forwarding konnte nicht gesetzt werden: %s", summarize(output, err))
	}
	state := make(map[string]string, 2)
	for _, setting := range []struct{ key, path string }{
		{"net.ipv4.ip_forward", "/proc/sys/net/ipv4/ip_forward"},
		{"net.ipv6.conf.all.forwarding", "/proc/sys/net/ipv6/conf/all/forwarding"},
	} {
		data, readErr := os.ReadFile(setting.path)
		if readErr != nil {
			return Response{}, fmt.Errorf("Forwarding-Zustand %s nicht lesbar: %w", setting.key, readErr)
		}
		state[setting.key] = strings.TrimSpace(string(data))
	}
	content := fmt.Sprintf("# Managed-By: SWAT\nnet.ipv4.ip_forward = %s\nnet.ipv6.conf.all.forwarding = %s\n", state["net.ipv4.ip_forward"], state["net.ipv6.conf.all.forwarding"])
	if err := writeOwnedSystemFile("/etc/sysctl.d/90-swat-forwarding.conf", "# Managed-By: SWAT\n", []byte(content), 0o644); err != nil {
		return Response{}, fmt.Errorf("Forwarding ist aktiv, konnte aber nicht dauerhaft gespeichert werden: %w", err)
	}
	return Response{OK: true, Message: "Forwarding gesetzt und dauerhaft gespeichert."}, nil
}

func writeOwnedSystemFile(path, marker string, content []byte, mode os.FileMode) error {
	if !strings.HasPrefix(string(content), marker) {
		return errors.New("fehlender SWAT-Eigentumsmarker")
	}
	if info, err := os.Lstat(path); err == nil {
		if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
			return errors.New("Zieldatei ist keine reguläre Datei")
		}
		previous, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		if !strings.HasPrefix(string(previous), marker) {
			return errors.New("fremde Konfigurationsdatei wird nicht überschrieben")
		}
	} else if !os.IsNotExist(err) {
		return err
	}
	directory := filepath.Dir(path)
	if err := os.MkdirAll(directory, 0o755); err != nil {
		return err
	}
	temporary, err := os.CreateTemp(directory, ".swat-config-*.tmp")
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
	return os.Rename(temporary.Name(), path)
}

var privilegedGroups = map[string]bool{
	"root": true, "wheel": true, "sudo": true, "admin": true,
	"docker": true, "libvirt": true, "kvm": true, "disk": true, "shadow": true,
}

func catalogServiceUnit(unit string) bool {
	for _, definition := range modules.Catalog() {
		for _, service := range definition.Services {
			if service.Unit == unit {
				return true
			}
		}
	}
	return false
}

func serviceRequiresConfiguration(unit string) bool {
	for _, definition := range modules.Catalog() {
		for _, service := range definition.Services {
			if service.Unit == unit {
				return service.ConfigurationRequired
			}
		}
	}
	return false
}

func systemSettingCommand(ctx context.Context, run CommandRunner, setting, value string) (string, []string, error) {
	switch setting {
	case "hostname":
		if err := validateSystemHostname(value); err != nil {
			return "", nil, err
		}
		return "hostnamectl", []string{"set-hostname", "--static", value}, nil
	case "locale":
		locales, err := run(ctx, "locale", "-a")
		if err != nil || !listedLocale(value, string(locales)) {
			return "", nil, errors.New("Locale ist nicht installiert oder nicht verfügbar.")
		}
		return "localectl", []string{"set-locale", "LANG=" + value}, nil
	case "timezone":
		timezones, err := run(ctx, "timedatectl", "list-timezones")
		if err != nil || !listedValue(value, string(timezones)) {
			return "", nil, errors.New("Zeitzone ist nicht verfügbar.")
		}
		return "timedatectl", []string{"set-timezone", value}, nil
	default:
		return "", nil, errors.New("Unbekannte Systemeinstellung.")
	}
}

func validateSystemHostname(value string) error {
	if value == "" || len(value) > 253 {
		return errors.New("Hostname muss 1 bis 253 Zeichen lang sein.")
	}
	for _, label := range strings.Split(value, ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return fmt.Errorf("Hostname enthält ein ungültiges DNS-Label: %q", label)
		}
		for _, character := range label {
			if (character < 'a' || character > 'z') && (character < 'A' || character > 'Z') && (character < '0' || character > '9') && character != '-' {
				return fmt.Errorf("Hostname enthält ein ungültiges DNS-Label: %q", label)
			}
		}
	}
	return nil
}

func listedLocale(value, output string) bool {
	normalize := func(locale string) string {
		locale = strings.ToLower(strings.TrimSpace(locale))
		return strings.ReplaceAll(locale, ".utf8", ".utf-8")
	}
	wanted := normalize(value)
	for _, locale := range strings.Split(output, "\n") {
		if normalize(locale) == wanted {
			return true
		}
	}
	return false
}

func listedValue(value, output string) bool {
	for _, candidate := range strings.Split(output, "\n") {
		if strings.TrimSpace(candidate) == value {
			return true
		}
	}
	return false
}

func summarize(output []byte, err error) string {
	text := strings.TrimSpace(string(output))
	if len(text) > 1800 {
		text = text[len(text)-1800:]
	}
	if text == "" {
		return err.Error()
	}
	return text
}

func (installer *Installer) Serve(listener net.Listener, allowedUID uint32) error {
	for {
		connection, err := listener.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return nil
			}
			return err
		}
		go func() {
			defer connection.Close()
			_ = installer.serveConnection(connection, allowedUID)
		}()
	}
}

func (installer *Installer) serveConnection(connection net.Conn, allowedUID uint32) error {
	unix, ok := connection.(*net.UnixConn)
	if !ok {
		return errors.New("Unix-Socket erforderlich")
	}
	uid, err := peerUID(unix)
	if err != nil || uid != allowedUID {
		return errors.New("nicht autorisierter lokaler Aufrufer")
	}
	_ = connection.SetDeadline(time.Now().Add(installTimeout + time.Minute))
	decoder := json.NewDecoder(io.LimitReader(connection, maxRequestBytes))
	decoder.DisallowUnknownFields()
	var request Request
	if err := decoder.Decode(&request); err != nil {
		return writeResponse(connection, Response{Error: "Ungültige Anfrage."})
	}
	if request.Operation == operationAuthenticateLogin {
		return installer.serveAuthentication(connection, request.Username, request.Password, installer.Login, "auth/login")
	}
	if request.Operation == operationAuthenticateSudo {
		return installer.serveAuthentication(connection, request.Username, request.Password, installer.Authorize, "auth/sudo")
	}
	if request.Operation == operationTransactionStatus {
		installer.mu.Lock()
		defer installer.mu.Unlock()
		response := Response{OK: true}
		if installer.networkPending != nil {
			response.NetworkPending = true
			response.NetworkDeadline = installer.networkPending.deadline
		}
		if installer.firewallPending != nil {
			response.FirewallPending = true
			response.FirewallDeadline = installer.firewallPending.deadline
		}
		return writeResponse(connection, response)
	}
	if request.Operation == operationSetSystemSetting {
		return installer.serveSystemSetting(connection, request)
	}
	if request.Operation == operationAdminAction {
		return installer.serveAdminAction(connection, request)
	}
	if request.Operation != operationInstallModules {
		return writeResponse(connection, Response{Error: "Nicht erlaubte privilegierte Operation."})
	}
	if request.Username == "" || request.Password == "" || installer.Authorize == nil || installer.Authorize(request.Username, request.Password) != nil {
		request.Password = ""
		return writeResponse(connection, Response{Error: "PAM-Authentifizierung für die Modulinstallation fehlgeschlagen."})
	}
	request.Password = ""
	if len(request.Modules) == 0 || len(request.Modules) > len(modules.Catalog()) {
		return writeResponse(connection, Response{Error: "Ungültige Modulauswahl."})
	}
	normalized, err := modules.NormalizeSelection(request.Modules)
	if err != nil {
		return writeResponse(connection, Response{Error: err.Error()})
	}
	if installer.Audit == nil {
		return writeResponse(connection, Response{Error: "Privilegiertes Audit ist nicht konfiguriert."})
	}
	target := strings.Join(normalized, ",")
	if err := installer.Audit(audit.Entry{User: request.Username, Action: "modules/helper-install-start", Target: target, Result: "started"}); err != nil {
		return writeResponse(connection, Response{Error: "Audit-Log nicht schreibbar; Paketinstallation abgebrochen."})
	}
	ctx, cancel := context.WithTimeout(context.Background(), installTimeout)
	defer cancel()
	result, err := installer.Install(ctx, normalized)
	if err != nil {
		_ = installer.Audit(audit.Entry{User: request.Username, Action: "modules/helper-install", Target: target, Result: "fehler", Detail: err.Error()})
		return writeResponse(connection, Response{Error: err.Error()})
	}
	if err := installer.Audit(audit.Entry{User: request.Username, Action: "modules/helper-install", Target: target, Result: "ok", Detail: strings.Join(result.Installed, ",")}); err != nil {
		return writeResponse(connection, Response{Error: "Pakettransaktion beendet, aber das Abschluss-Audit konnte nicht geschrieben werden."})
	}
	return writeResponse(connection, result)
}

func (installer *Installer) serveAdminAction(connection net.Conn, request Request) error {
	if request.Username == "" || request.Password == "" || installer.Authorize == nil || installer.Authorize(request.Username, request.Password) != nil {
		if installer.Audit != nil && request.Username != "" {
			_ = installer.Audit(audit.Entry{User: request.Username, Action: "auth/privileged-action", Target: request.Action, Result: "fehler"})
		}
		return writeResponse(connection, Response{Error: "PAM-Authentifizierung für die Aktion fehlgeschlagen."})
	}
	request.Password = ""
	if installer.Audit == nil {
		return writeResponse(connection, Response{Error: "Privilegiertes Audit ist nicht konfiguriert."})
	}
	target := adminActionAuditTarget(request)
	if strings.HasPrefix(request.Action, "network-bridge-") {
		target = "systemd-networkd"
	} else if strings.HasPrefix(request.Action, "firewall-") {
		target = "inet swat"
	}
	if err := installer.Audit(audit.Entry{User: request.Username, Action: request.Action + "/start", Target: target, Result: "started"}); err != nil {
		return writeResponse(connection, Response{Error: "Audit-Log nicht schreibbar; Änderung abgebrochen."})
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	var result Response
	var err error
	switch {
	case strings.HasPrefix(request.Action, "network-bridge-"):
		result, err = installer.NetworkAction(ctx, request.Action, request.Value, request.Value2, request.Username)
	case strings.HasPrefix(request.Action, "firewall-"):
		result, err = installer.ApplyFirewall(ctx, request.Action, request.Value, request.Username)
	case strings.HasPrefix(request.Action, "vm-") || strings.HasPrefix(request.Action, "libvirt-"):
		result, err = installer.VMAction(ctx, request.Action, request.Target, request.Value, request.Value2, request.Value3, request.Value4)
	default:
		if err = validateAdminTarget(request.Action, request.Target, request.Value, request.Value2, request.Username); err == nil {
			result, err = installer.AdminAction(ctx, request.Action, request.Target, request.Value, request.Value2, request.Value3)
		}
	}
	auditResult, detail := "ok", ""
	if err != nil {
		auditResult, detail = "fehler", err.Error()
	}
	if auditErr := installer.Audit(audit.Entry{User: request.Username, Action: request.Action, Target: target, Result: auditResult, Detail: detail}); auditErr != nil && err == nil {
		return writeResponse(connection, Response{Error: "Aktion ausgeführt, aber das Abschluss-Audit konnte nicht geschrieben werden."})
	}
	if err != nil {
		return writeResponse(connection, Response{Error: err.Error()})
	}
	return writeResponse(connection, result)
}

func adminActionAuditTarget(request Request) string {
	switch request.Action {
	case "service":
		return strings.Join(nonEmpty(request.Target, request.Value), " ")
	case "user-create", "user-delete", "user-expire-password", "vm-start", "vm-stop", "vm-force-stop", "vm-restart", "vm-delete", "vm-dumpxml", "vm-define", "vm-config-memory", "vm-config-memory-current", "vm-config-cpus", "vm-config-cpus-max", "vm-eject-media", "vm-device-attach", "libvirt-pool-start", "libvirt-pool-stop", "libvirt-network-start", "libvirt-network-stop", "libvirt-pool-create", "libvirt-pool-build", "libvirt-pool-activate", "libvirt-pool-dumpxml", "vm-disk-create", "vm-iso-stage", "vm-iso-delete", "vm-iso-copy":
		return strings.Join(nonEmpty(request.Target, request.Action), " ")
	case "group-create":
		return strings.Join(nonEmpty(request.Target, request.Value), " ")
	case "group-membership":
		return strings.Join(nonEmpty(request.Target, request.Value, request.Value2), " ")
	case "network-forwarding":
		return strings.Join(nonEmpty(request.Target, request.Value), "=")
	default:
		return request.Target
	}
}

func nonEmpty(values ...string) []string {
	result := make([]string, 0, len(values))
	for _, value := range values {
		if value != "" {
			result = append(result, value)
		}
	}
	return result
}

func (installer *Installer) serveSystemSetting(connection net.Conn, request Request) error {
	if request.Username == "" || request.Password == "" || installer.Authorize == nil || installer.Authorize(request.Username, request.Password) != nil {
		return writeResponse(connection, Response{Error: "PAM-Authentifizierung für die Systemeinstellung fehlgeschlagen."})
	}
	request.Password = ""
	if installer.Audit == nil {
		return writeResponse(connection, Response{Error: "Privilegiertes Audit ist nicht konfiguriert."})
	}
	target := request.Setting + "=" + request.Value
	if err := installer.Audit(audit.Entry{User: request.Username, Action: "system/" + request.Setting + "/start", Target: request.Value, Result: "started"}); err != nil {
		return writeResponse(connection, Response{Error: "Audit-Log nicht schreibbar; Änderung abgebrochen."})
	}
	ctx, cancel := context.WithTimeout(context.Background(), systemSettingTimeout)
	defer cancel()
	result, err := installer.SetSystemSetting(ctx, request.Setting, request.Value)
	auditResult, detail := "ok", ""
	if err != nil {
		auditResult, detail = "fehler", err.Error()
	}
	if auditErr := installer.Audit(audit.Entry{User: request.Username, Action: "system/" + request.Setting, Target: target, Result: auditResult, Detail: detail}); auditErr != nil && err == nil {
		return writeResponse(connection, Response{Error: "Systemeinstellung wurde geändert, aber das Abschluss-Audit konnte nicht geschrieben werden."})
	}
	if err != nil {
		return writeResponse(connection, Response{Error: err.Error()})
	}
	return writeResponse(connection, result)
}

func (installer *Installer) serveAuthentication(connection net.Conn, username, password string, authorize Authorizer, action string) error {
	if username == "" || password == "" || authorize == nil {
		return writeResponse(connection, Response{Error: "Authentifizierung fehlgeschlagen."})
	}
	if installer.Audit == nil {
		return writeResponse(connection, Response{Error: "Privilegiertes Audit ist nicht konfiguriert."})
	}
	if err := authorize(username, password); err != nil {
		_ = installer.Audit(audit.Entry{User: username, Action: action, Target: "swat", Result: "fehler"})
		return writeResponse(connection, Response{Error: "Authentifizierung fehlgeschlagen."})
	}
	if err := installer.Audit(audit.Entry{User: username, Action: action, Target: "swat", Result: "ok"}); err != nil {
		return writeResponse(connection, Response{Error: "Audit-Log nicht schreibbar; Authentifizierung abgebrochen."})
	}
	return writeResponse(connection, Response{OK: true})
}

func writeResponse(writer io.Writer, response Response) error {
	return json.NewEncoder(writer).Encode(response)
}

func peerUID(connection *net.UnixConn) (uint32, error) {
	raw, err := connection.SyscallConn()
	if err != nil {
		return 0, err
	}
	var credentials *syscall.Ucred
	var controlErr error
	if err := raw.Control(func(fd uintptr) {
		credentials, controlErr = syscall.GetsockoptUcred(int(fd), syscall.SOL_SOCKET, syscall.SO_PEERCRED)
	}); err != nil {
		return 0, err
	}
	if controlErr != nil {
		return 0, controlErr
	}
	return credentials.Uid, nil
}

func Install(ctx context.Context, ids []string, username, password string) (Response, error) {
	return roundTrip(ctx, Request{Operation: operationInstallModules, Modules: ids, Username: username, Password: password})
}

func SetSystemSetting(ctx context.Context, setting, value, username, password string) error {
	_, err := roundTrip(ctx, Request{Operation: operationSetSystemSetting, Setting: setting, Value: value, Username: username, Password: password})
	return err
}

func PerformAdminAction(ctx context.Context, action, target, value, value2, value3, username, password string) error {
	_, err := roundTrip(ctx, Request{
		Operation: operationAdminAction, Action: action, Target: target,
		Value: value, Value2: value2, Value3: value3, Username: username, Password: password,
	})
	return err
}

func PerformNetworkAction(ctx context.Context, action, configJSON, previousJSON, username, password string) (Response, error) {
	return roundTrip(ctx, Request{
		Operation: operationAdminAction, Action: action, Value: configJSON, Value2: previousJSON,
		Username: username, Password: password,
	})
}

func PerformFirewallAction(ctx context.Context, action, configJSON, username, password string) (Response, error) {
	return roundTrip(ctx, Request{
		Operation: operationAdminAction, Action: action, Value: configJSON,
		Username: username, Password: password,
	})
}

func PerformVMAction(ctx context.Context, action, target, value, value2, value3, value4, username, password string) (Response, error) {
	return roundTrip(ctx, Request{
		Operation: operationAdminAction, Action: action, Target: target,
		Value: value, Value2: value2, Value3: value3, Value4: value4,
		Username: username, Password: password,
	})
}

func TransactionStatus(ctx context.Context) (Response, error) {
	return roundTrip(ctx, Request{Operation: operationTransactionStatus})
}

func AuthenticateLogin(ctx context.Context, username, password string) error {
	return authenticate(ctx, operationAuthenticateLogin, username, password)
}

func AuthenticateSudo(ctx context.Context, username, password string) error {
	return authenticate(ctx, operationAuthenticateSudo, username, password)
}

func authenticate(ctx context.Context, operation, username, password string) error {
	_, err := roundTrip(ctx, Request{Operation: operation, Username: username, Password: password})
	return err
}

func roundTrip(ctx context.Context, request Request) (Response, error) {
	dialer := net.Dialer{Timeout: 5 * time.Second}
	connection, err := dialer.DialContext(ctx, "unix", SocketPath)
	if err != nil {
		return Response{}, fmt.Errorf("SWAT-Modul-Helper ist nicht erreichbar: %w", err)
	}
	defer connection.Close()
	_ = connection.SetDeadline(time.Now().Add(installTimeout + time.Minute))
	if err := json.NewEncoder(connection).Encode(request); err != nil {
		return Response{}, err
	}
	var response Response
	decoder := json.NewDecoder(io.LimitReader(connection, maxRequestBytes))
	if err := decoder.Decode(&response); err != nil {
		return Response{}, err
	}
	if !response.OK {
		if response.Error == "" {
			response.Error = "Helfer-Anfrage fehlgeschlagen."
		}
		return response, errors.New(response.Error)
	}
	return response, nil
}
