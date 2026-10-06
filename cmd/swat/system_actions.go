package main

import (
	"fmt"
	"net/http"
	"os/exec"
	"regexp"
	"strings"

	"swat/internal/audit"
	"swat/internal/collect"
	"swat/internal/zones"
)

type localeOption struct {
	Name     string
	Selected bool
}

type systemConfigView struct {
	Hostname      string
	Locale        string
	Timezone      string
	Locales       []localeOption
	Timezones     []string
	HostnameReady bool
	LocaleReady   bool
	TimezoneReady bool
}

var hostnameLabelPattern = regexp.MustCompile(`^[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$`)

var runSystemSetting = func(password string, args ...string) error {
	return runAsRoot(password, args...)
}

func readSystemConfigView() systemConfigView {
	view := systemConfigView{
		Hostname:      readCommandValue("hostnamectl", "--static"),
		Locale:        systemLocale(),
		Timezone:      readCommandValue("timedatectl", "show", "-p", "Timezone", "--value"),
		HostnameReady: commandAvailable("hostnamectl"),
	}
	if view.Hostname == "" {
		view.Hostname = collect.ReadSystemInfo().Hostname
	}
	localeOutput, localeErr := exec.Command("locale", "-a").Output()
	if localeErr == nil {
		for _, line := range strings.Split(string(localeOutput), "\n") {
			name := strings.TrimSpace(line)
			if name == "" {
				continue
			}
			view.Locales = append(view.Locales, localeOption{Name: name, Selected: localeEquivalent(view.Locale, name)})
		}
	}
	view.LocaleReady = commandAvailable("localectl") && len(view.Locales) > 0
	timezoneOutput, timezoneErr := exec.Command("timedatectl", "list-timezones").Output()
	if timezoneErr == nil {
		for _, line := range strings.Split(string(timezoneOutput), "\n") {
			name := strings.TrimSpace(line)
			if name != "" {
				view.Timezones = append(view.Timezones, name)
			}
		}
	}
	view.TimezoneReady = commandAvailable("timedatectl") && len(view.Timezones) > 0
	return view
}

func systemLocale() string {
	output, err := exec.Command("localectl", "status").Output()
	if err != nil {
		return ""
	}
	for _, line := range strings.Split(string(output), "\n") {
		key, value, ok := strings.Cut(strings.TrimSpace(line), ":")
		if !ok || strings.TrimSpace(key) != "System Locale" {
			continue
		}
		for _, item := range strings.Fields(value) {
			name, locale, found := strings.Cut(item, "=")
			if found && name == "LANG" {
				return locale
			}
		}
	}
	return ""
}

func readCommandValue(command string, args ...string) string {
	output, err := exec.Command(command, args...).Output()
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(output))
}

func commandAvailable(command string) bool {
	_, err := exec.LookPath(command)
	return err == nil
}

func localeEquivalent(left, right string) bool {
	normalize := func(value string) string {
		value = strings.ToLower(strings.TrimSpace(value))
		return strings.ReplaceAll(value, ".utf8", ".utf-8")
	}
	return normalize(left) == normalize(right)
}

func validateHostname(value string) error {
	value = strings.TrimSuffix(strings.TrimSpace(value), ".")
	if value == "" || len(value) > 253 {
		return fmt.Errorf("Hostname muss 1 bis 253 Zeichen lang sein.")
	}
	for _, label := range strings.Split(value, ".") {
		if !hostnameLabelPattern.MatchString(label) {
			return fmt.Errorf("Hostname enthält ein ungültiges DNS-Label: %q", label)
		}
	}
	return nil
}

func validateLocale(value string, options []localeOption) bool {
	for _, option := range options {
		if localeEquivalent(value, option.Name) {
			return true
		}
	}
	return false
}

func validateTimezone(value string, options []string) bool {
	for _, option := range options {
		if value == option {
			return true
		}
	}
	return false
}

func handleSystemSetting(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Methode nicht erlaubt", http.StatusMethodNotAllowed)
		return
	}
	session, err := accountActionSession(r)
	if err != nil {
		renderSystem(w, r, err.Error(), "")
		return
	}
	action := r.FormValue("action")
	value := strings.TrimSpace(r.FormValue("value"))
	options := readSystemConfigView()
	command, target, err := systemSettingCommand(action, value, options)
	if err != nil {
		renderSystem(w, r, err.Error(), "")
		return
	}
	if err := audit.Log(zones.StateDir(), audit.Entry{User: session.Username, Action: "system/" + action, Target: value, Result: "started"}); err != nil {
		renderSystem(w, r, "Audit-Log nicht schreibbar; Änderung wurde nicht ausgeführt.", "")
		return
	}
	err = runSystemSetting(session.SudoPassword, command...)
	result, detail := "ok", ""
	if err != nil {
		result, detail = "fehler", err.Error()
	}
	_ = audit.Log(zones.StateDir(), audit.Entry{User: session.Username, Action: "system/" + action, Target: target, Result: result, Detail: detail})
	if err != nil {
		renderSystem(w, r, "Systemeinstellung konnte nicht geändert werden: "+err.Error(), "")
		return
	}
	renderSystem(w, r, "", "Systemeinstellung wurde geändert.")
}

func systemSettingCommand(action, value string, state systemConfigView) ([]string, string, error) {
	switch action {
	case "hostname":
		value = strings.TrimSuffix(value, ".")
		if err := validateHostname(value); err != nil {
			return nil, "", err
		}
		if !state.HostnameReady {
			return nil, "", fmt.Errorf("hostnamectl ist nicht verfügbar.")
		}
		return []string{"hostnamectl", "set-hostname", "--static", value}, value, nil
	case "locale":
		if !state.LocaleReady || !validateLocale(value, state.Locales) {
			return nil, "", fmt.Errorf("Locale ist nicht installiert oder nicht verfügbar.")
		}
		return []string{"localectl", "set-locale", "LANG=" + value}, value, nil
	case "timezone":
		if !state.TimezoneReady || !validateTimezone(value, state.Timezones) {
			return nil, "", fmt.Errorf("Zeitzone ist nicht verfügbar.")
		}
		return []string{"timedatectl", "set-timezone", value}, value, nil
	default:
		return nil, "", fmt.Errorf("Unbekannte Systemeinstellung.")
	}
}

func renderSystem(w http.ResponseWriter, r *http.Request, actionError, actionSuccess string) {
	render(w, r, "system", "system.html", map[string]any{
		"System":              collect.ReadSystemInfo(),
		"ConfigPage":          collect.SystemSettingsConfig(),
		"SystemSettings":      readSystemConfigView(),
		"SystemActionError":   actionError,
		"SystemActionSuccess": actionSuccess,
	})
}
