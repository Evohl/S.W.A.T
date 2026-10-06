package collect

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os/exec"
	"strconv"
	"strings"
	"time"
)

// Unit represents one systemd unit as reported by `systemctl list-units --output=json`.
type Unit struct {
	Name        string `json:"unit"`
	Load        string `json:"load"`
	Active      string `json:"active"`
	Sub         string `json:"sub"`
	Description string `json:"description"`
}

type UnitDetail struct {
	Unit        Unit
	LoadState   string
	ActiveState string
	SubState    string
	MainPID     string
	Since       string
	Memory      string
	Logs        []JournalEntry
}

// Units runs systemctl and returns all units of the given type (e.g. "service", "socket", "timer").
// unitType may be empty to list all types.
func Units(unitType string) ([]Unit, error) {
	args := []string{"list-units", "--all", "--output=json", "--no-pager", "--no-legend"}
	if unitType != "" {
		args = append(args, "--type="+unitType)
	}

	cmd := exec.Command("systemctl", args...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("systemctl %v: %w: %s", args, err, stderr.String())
	}

	var units []Unit
	if err := json.Unmarshal(stdout.Bytes(), &units); err != nil {
		return nil, fmt.Errorf("parsing systemctl output: %w", err)
	}
	return units, nil
}

// FailedUnits returns only units in a failed state.
func FailedUnits() ([]Unit, error) {
	all, err := Units("")
	if err != nil {
		return nil, err
	}
	var failed []Unit
	for _, u := range all {
		if u.Active == "failed" {
			failed = append(failed, u)
		}
	}
	return failed, nil
}

func UnitDetailFor(name string) (UnitDetail, error) {
	if name == "" || strings.ContainsAny(name, "\r\n\x00") {
		return UnitDetail{}, fmt.Errorf("invalid unit name")
	}

	cmd := exec.Command("systemctl", "show", name, "--no-pager",
		"--property=LoadState,ActiveState,SubState,MainPID,ActiveEnterTimestamp,MemoryCurrent")
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return UnitDetail{}, fmt.Errorf("systemctl show %s: %w: %s", name, err, stderr.String())
	}

	values := make(map[string]string)
	for _, line := range strings.Split(stdout.String(), "\n") {
		key, value, ok := strings.Cut(line, "=")
		if ok {
			values[key] = value
		}
	}
	logs, err := RecentUnitLogs(name, 80)
	if err != nil {
		return UnitDetail{}, err
	}

	return UnitDetail{
		Unit:      Unit{Name: name, Load: values["LoadState"], Active: values["ActiveState"], Sub: values["SubState"]},
		LoadState: values["LoadState"], ActiveState: values["ActiveState"], SubState: values["SubState"],
		MainPID: values["MainPID"], Since: formatTimestamp(values["ActiveEnterTimestamp"]), Memory: formatBytes(values["MemoryCurrent"]), Logs: logs,
	}, nil
}

func formatTimestamp(value string) string {
	value = strings.TrimSpace(value)
	if value == "" || value == "-" {
		return "Not available"
	}
	for _, layout := range []string{"Mon 2006-01-02 15:04:05 MST", "2006-01-02 15:04:05 MST"} {
		if parsed, err := time.Parse(layout, value); err == nil {
			return parsed.Format("2006-01-02 15:04:05 MST")
		}
	}
	return value
}

func formatBytes(value string) string {
	bytes, err := strconv.ParseUint(strings.TrimSpace(value), 10, 64)
	if err != nil {
		return "Not available"
	}
	const unit = uint64(1024)
	if bytes < unit {
		return fmt.Sprintf("%d B", bytes)
	}
	valueFloat := float64(bytes)
	units := []string{"KB", "MB", "GB", "TB"}
	for _, label := range units {
		valueFloat /= float64(unit)
		if valueFloat < float64(unit) || label == "TB" {
			return fmt.Sprintf("%.1f %s", valueFloat, label)
		}
	}
	return "Not available"
}
