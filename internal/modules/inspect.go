package modules

import (
	"fmt"
	"os/exec"
	"sort"
	"strings"
)

type CommandRunner func(name string, args ...string) ([]byte, error)

func Inspect(path string) ([]Status, Selection, error) {
	return InspectWith(path, func(name string, args ...string) ([]byte, error) {
		return exec.Command(name, args...).CombinedOutput()
	})
}

func InspectWith(path string, run CommandRunner) ([]Status, Selection, error) {
	selection, err := Load(path)
	if err != nil {
		return nil, Selection{}, err
	}
	installed := make(map[string]bool)
	serviceStates := make(map[string]ServiceState)
	packageNames := make([]string, 0)
	packageSeen := make(map[string]bool)
	var units []string
	for _, definition := range Catalog() {
		for _, dependency := range definition.Packages {
			if !packageSeen[dependency.Name] {
				packageSeen[dependency.Name] = true
				packageNames = append(packageNames, dependency.Name)
			}
		}
		for _, service := range definition.Services {
			if _, known := serviceStates[service.Unit]; !known {
				serviceStates[service.Unit] = ServiceState{Unit: service.Unit, Active: "unknown", Enabled: "unknown"}
				units = append(units, service.Unit)
			}
		}
	}
	sort.Strings(packageNames)
	packageArgs := append([]string{"-Q", "--"}, packageNames...)
	packageOutput, _ := run("pacman", packageArgs...)
	installedLines := strings.Split(string(packageOutput), "\n")
	for _, line := range installedLines {
		fields := strings.Fields(line)
		if len(fields) > 1 && packageSeen[fields[0]] {
			installed[fields[0]] = true
		}
	}
	activeArgs := append([]string{"is-active"}, units...)
	enabledArgs := append([]string{"is-enabled"}, units...)
	activeOutput, _ := run("systemctl", activeArgs...)
	enabledOutput, _ := run("systemctl", enabledArgs...)
	activeLines := strings.Fields(string(activeOutput))
	enabledLines := strings.Fields(string(enabledOutput))
	for index, unit := range units {
		state := serviceStates[unit]
		if index < len(activeLines) {
			state.Active = activeLines[index]
		}
		if index < len(enabledLines) {
			state.Enabled = enabledLines[index]
		}
		serviceStates[unit] = state
	}
	statuses, err := Statuses(selection, installed, serviceStates)
	if err != nil {
		return nil, Selection{}, fmt.Errorf("Modulstatus konnte nicht erstellt werden: %w", err)
	}
	return statuses, selection, nil
}

func Ready(statuses []Status, id string) bool {
	for _, status := range statuses {
		if status.ID == id {
			return status.Selected && status.Ready
		}
	}
	return false
}
