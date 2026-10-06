package collect

import (
	"os"
	"os/exec"
	"strconv"
	"strings"
)

// SystemSettingsConfig adapts timezone, locale, keyboard layout and pacman
// settings to the common config view.
func SystemSettingsConfig() ConfigPage {
	timedate, timedateErr := timedatectlValues()
	localectl, localectlErr := localectlValues()

	available := timedateErr == nil || localectlErr == nil
	page := ConfigPage{
		ID:          "system-settings",
		Title:       "Systemeinstellungen",
		Description: "Zeitzone, Locale, Tastaturlayout und Pacman-Konfiguration des Hosts.",
		Owner:       "timedatectl / localectl / pacman",
		Status:      configStatus(available),
		StatusLabel: configStatusLabel(available),
		ReadOnly:    true,
	}

	page.Sections = append(page.Sections, ConfigSection{
		Title:   "Zeitzone",
		Columns: []string{"Bereich", "Wert"},
		Rows: [][]string{
			{"Zeitzone", valueOr(timedate["Timezone"], "unbekannt")},
			{"NTP aktiviert", yesNoLabel(timedate["NTP"])},
			{"NTP synchronisiert", yesNoLabel(timedate["NTPSynchronized"])},
			{"RTC in lokaler Zeit", yesNoLabel(timedate["LocalRTC"])},
		},
		EmptyText: "Keine Zeitzoneninformationen verfügbar.",
	})

	localeRows := make([][]string, 0)
	for _, field := range strings.Fields(localectl["System Locale"]) {
		if key, value, ok := strings.Cut(field, "="); ok {
			localeRows = append(localeRows, []string{key, value})
		}
	}
	page.Sections = append(page.Sections, ConfigSection{
		Title:     "Locale",
		Columns:   []string{"Variable", "Wert"},
		Rows:      localeRows,
		EmptyText: "Keine Locale-Einstellungen gefunden.",
	})

	page.Sections = append(page.Sections, ConfigSection{
		Title:   "Tastaturlayout",
		Columns: []string{"Bereich", "Wert"},
		Rows: [][]string{
			{"Konsole (VC Keymap)", valueOr(localectl["VC Keymap"], "-")},
			{"X11 Layout", valueOr(localectl["X11 Layout"], "-")},
			{"X11 Modell", valueOr(localectl["X11 Model"], "-")},
			{"X11 Variante", valueOr(localectl["X11 Variant"], "-")},
			{"X11 Optionen", valueOr(localectl["X11 Options"], "-")},
		},
		EmptyText: "Keine Tastaturkonfiguration gefunden.",
	})

	options, flags, repos := readPacmanConf("/etc/pacman.conf")
	page.Sections = append(page.Sections, ConfigSection{
		Title:       "Pacman-Konfiguration",
		Description: "Wirksame Werte aus /etc/pacman.conf und /etc/pacman.d/mirrorlist.",
		Columns:     []string{"Bereich", "Wert"},
		Rows: [][]string{
			{"Architektur", valueOr(options["Architecture"], "auto")},
			{"Parallele Downloads", valueOr(options["ParallelDownloads"], "1 (deaktiviert)")},
			{"SigLevel", valueOr(options["SigLevel"], "Default")},
			{"Farbige Ausgabe", boolLabel(flags["Color"])},
			{"Speicherplatzprüfung", boolLabel(flags["CheckSpace"])},
			{"Ausführliche Paketliste", boolLabel(flags["VerbosePkgLists"])},
			{"Aktivierte Repositories", valueOr(strings.Join(repos, ", "), "-")},
			{"Aktive Mirror-Einträge", strconv.Itoa(activeMirrorCount("/etc/pacman.d/mirrorlist"))},
		},
		EmptyText: "Keine Pacman-Konfiguration gefunden.",
	})

	return page
}

// timedatectlValues parses "timedatectl show" into a flat KEY=VALUE map.
func timedatectlValues() (map[string]string, error) {
	values := map[string]string{}
	out, err := exec.Command("timedatectl", "show").Output()
	if err != nil {
		return values, err
	}
	for _, line := range strings.Split(string(out), "\n") {
		if key, value, ok := strings.Cut(strings.TrimSpace(line), "="); ok {
			values[key] = value
		}
	}
	return values, nil
}

// localectlValues parses "localectl status" into a map keyed by its labels,
// joining continuation lines (used for multiple LC_* assignments) with spaces.
func localectlValues() (map[string]string, error) {
	values := map[string]string{}
	out, err := exec.Command("localectl", "status").Output()
	if err != nil {
		return values, err
	}
	labels := []string{"System Locale", "VC Keymap", "X11 Layout", "X11 Model", "X11 Variant", "X11 Options"}
	current := ""
	for _, line := range strings.Split(string(out), "\n") {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" {
			continue
		}
		matched := false
		for _, label := range labels {
			if rest, ok := strings.CutPrefix(trimmed, label+":"); ok {
				current = label
				values[label] = strings.TrimSpace(rest)
				matched = true
				break
			}
		}
		if !matched && current != "" {
			values[current] = strings.TrimSpace(values[current] + " " + trimmed)
		}
	}
	return values, nil
}

// readPacmanConf parses the [options] section and repository order from a
// pacman configuration file.
func readPacmanConf(path string) (options map[string]string, flags map[string]bool, repoOrder []string) {
	options = map[string]string{}
	flags = map[string]bool{}
	data, err := os.ReadFile(path)
	if err != nil {
		return options, flags, repoOrder
	}
	section := ""
	for _, line := range strings.Split(string(data), "\n") {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		if strings.HasPrefix(trimmed, "[") && strings.HasSuffix(trimmed, "]") {
			section = strings.Trim(trimmed, "[]")
			if section != "options" {
				repoOrder = append(repoOrder, section)
			}
			continue
		}
		if section != "options" {
			continue
		}
		if key, value, ok := strings.Cut(trimmed, "="); ok {
			options[strings.TrimSpace(key)] = strings.TrimSpace(value)
		} else {
			flags[trimmed] = true
		}
	}
	return options, flags, repoOrder
}

// activeMirrorCount counts uncommented "Server=" entries in a pacman mirrorlist.
func activeMirrorCount(path string) int {
	data, err := os.ReadFile(path)
	if err != nil {
		return 0
	}
	count := 0
	for _, line := range strings.Split(string(data), "\n") {
		if strings.HasPrefix(strings.TrimSpace(line), "Server") {
			count++
		}
	}
	return count
}

func valueOr(value, fallback string) string {
	if strings.TrimSpace(value) == "" {
		return fallback
	}
	return value
}

func yesNoLabel(value string) string {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "yes":
		return "ja"
	case "no":
		return "nein"
	default:
		return "unbekannt"
	}
}

func boolLabel(value bool) string {
	if value {
		return "aktiviert"
	}
	return "deaktiviert"
}
