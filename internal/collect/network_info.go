package collect

import (
	"bufio"
	"bytes"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
)

type NetworkInfo struct {
	Leases        []NetworkLease
	Hosts         []NetworkHost
	Neighbors     []NetworkNeighbor
	LLDPNeighbors []LLDPNeighbor
	LLDP          string
}

type NetworkLease struct {
	Address string
	MAC     string
	Name    string
	Source  string
}

type NetworkHost struct {
	Name    string
	Address string
	Source  string
}

type NetworkNeighbor struct {
	Interface string
	Address   string
	MAC       string
	State     string
}

type LLDPNeighbor struct {
	Interface       string
	ChassisName     string
	ChassisMAC      string
	ManagementIP    string
	Port            string
	PortDescription string
	Description     string
	Age             string
	TTL             string
}

func NetworkInventory() NetworkInfo {
	lldp, rawLLDP := lldpInventory()
	return NetworkInfo{
		Leases:        networkLeases(),
		Hosts:         networkHosts(),
		Neighbors:     networkNeighbors(),
		LLDPNeighbors: lldp,
		LLDP:          rawLLDP,
	}
}

func networkLeases() []NetworkLease {
	paths := []string{
		"/var/lib/dnsmasq/dnsmasq.leases",
		"/var/lib/misc/dnsmasq.leases",
		"/run/systemd/netif/leases",
	}
	leases := make([]NetworkLease, 0)
	for _, path := range paths {
		entries, err := os.ReadDir(path)
		if err == nil {
			for _, entry := range entries {
				if entry.IsDir() {
					continue
				}
				leases = append(leases, parseNetworkdLease(filepath.Join(path, entry.Name()))...)
			}
			continue
		}
		leases = append(leases, parseDnsmasqLeases(path)...)
	}
	return leases
}

func parseDnsmasqLeases(path string) []NetworkLease {
	file, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer file.Close()
	leases := make([]NetworkLease, 0)
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) < 4 {
			continue
		}
		leases = append(leases, NetworkLease{Address: fields[2], MAC: fields[1], Name: fields[3], Source: path})
	}
	return leases
}

func parseNetworkdLease(path string) []NetworkLease {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	values := make(map[string]string)
	for _, line := range strings.Split(string(data), "\n") {
		key, value, ok := strings.Cut(line, "=")
		if ok {
			values[key] = value
		}
	}
	address := values["ADDRESS1"]
	if address == "" {
		address = values["ADDRESS"]
	}
	if address == "" {
		return nil
	}
	return []NetworkLease{{Address: address, Name: values["HOSTNAME"], Source: path}}
}

func networkHosts() []NetworkHost {
	hosts := make([]NetworkHost, 0)
	parseHostsFile("/etc/hosts", &hosts)
	if home, err := os.UserHomeDir(); err == nil {
		parseKnownHosts(filepath.Join(home, ".ssh", "known_hosts"), &hosts)
	}
	return hosts
}

func parseHostsFile(path string, hosts *[]NetworkHost) {
	file, err := os.Open(path)
	if err != nil {
		return
	}
	defer file.Close()
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(strings.SplitN(scanner.Text(), "#", 2)[0])
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		for _, name := range fields[1:] {
			*hosts = append(*hosts, NetworkHost{Address: fields[0], Name: name, Source: path})
		}
	}
}

func parseKnownHosts(path string, hosts *[]NetworkHost) {
	file, err := os.Open(path)
	if err != nil {
		return
	}
	defer file.Close()
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) < 3 || strings.HasPrefix(fields[0], "#") {
			continue
		}
		*hosts = append(*hosts, NetworkHost{Name: fields[0], Address: "known SSH host", Source: path})
	}
}

type neighborJSON struct {
	IfName    string   `json:"dev"`
	Address   string   `json:"dst"`
	LinkLayer string   `json:"lladdr"`
	State     []string `json:"state"`
}

func networkNeighbors() []NetworkNeighbor {
	output, err := exec.Command("ip", "-j", "neigh", "show").Output()
	if err != nil {
		return nil
	}
	var entries []neighborJSON
	if json.Unmarshal(output, &entries) != nil {
		return nil
	}
	neighbors := make([]NetworkNeighbor, 0, len(entries))
	for _, entry := range entries {
		if !usableNetworkNeighbor(entry) {
			continue
		}
		neighbors = append(neighbors, NetworkNeighbor{Interface: entry.IfName, Address: entry.Address, MAC: entry.LinkLayer, State: strings.Join(entry.State, ", ")})
	}
	return neighbors
}

func usableNetworkNeighbor(entry neighborJSON) bool {
	if entry.IfName == "" || entry.Address == "" || entry.LinkLayer == "" {
		return false
	}
	for _, state := range entry.State {
		switch strings.ToUpper(state) {
		case "FAILED", "INCOMPLETE", "NOARP":
			return false
		}
	}
	return len(entry.State) > 0
}

func lldpOutput() string {
	if _, err := exec.LookPath("lldpctl"); err != nil {
		return "LLDP nicht verfügbar: lldpctl ist nicht installiert."
	}
	var stdout, stderr bytes.Buffer
	cmd := exec.Command("lldpctl", "-f", "keyvalue")
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		if stderr.Len() > 0 {
			return "LLDP nicht lesbar: " + strings.TrimSpace(stderr.String())
		}
		return "LLDP nicht lesbar."
	}
	if stdout.Len() == 0 {
		return "Keine LLDP-Nachbarn gefunden."
	}
	return strings.TrimSpace(stdout.String())
}

func lldpInventory() ([]LLDPNeighbor, string) {
	if _, err := exec.LookPath("lldpctl"); err != nil {
		return nil, "LLDP nicht verfügbar: lldpctl ist nicht installiert."
	}
	var stdout, stderr bytes.Buffer
	cmd := exec.Command("lldpctl", "-f", "keyvalue")
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		if stderr.Len() > 0 {
			return nil, "LLDP nicht lesbar: " + strings.TrimSpace(stderr.String())
		}
		return nil, "LLDP nicht lesbar."
	}
	if stdout.Len() == 0 {
		return nil, "Keine LLDP-Nachbarn gefunden."
	}
	raw := strings.TrimSpace(stdout.String())
	return parseLLDPKeyValue(raw), raw
}

func parseLLDPKeyValue(raw string) []LLDPNeighbor {
	groups := make(map[string]map[string]string)
	current := make(map[string]string)
	explicitRID := make(map[string]bool)
	for _, line := range strings.Split(raw, "\n") {
		key, value, ok := strings.Cut(strings.TrimSpace(line), "=")
		if !ok || !strings.HasPrefix(key, "lldp.") {
			continue
		}
		parts := strings.Split(key, ".")
		if len(parts) < 3 {
			continue
		}
		interfaceName := parts[1]
		groupKey := current[interfaceName]
		if groupKey == "" {
			groupKey = interfaceName + "/1"
			current[interfaceName] = groupKey
		}
		values := groups[groupKey]
		if values == nil {
			values = make(map[string]string)
			groups[groupKey] = values
		}
		field := strings.Join(parts[2:], ".")
		if field == "rid" {
			newKey := interfaceName + "/" + value
			if !explicitRID[groupKey] && groupKey != newKey && groups[newKey] == nil {
				groups[newKey] = values
				delete(groups, groupKey)
			}
			if groupKey != newKey {
				groupKey = newKey
				current[interfaceName] = groupKey
				values = groups[groupKey]
				if values == nil {
					values = make(map[string]string)
					groups[groupKey] = values
				}
			}
			explicitRID[groupKey] = true
		}
		values[field] = value
	}

	keys := make([]string, 0, len(groups))
	for key := range groups {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	neighbors := make([]LLDPNeighbor, 0, len(keys))
	for _, key := range keys {
		values := groups[key]
		interfaceName := strings.SplitN(key, "/", 2)[0]
		neighbors = append(neighbors, LLDPNeighbor{
			Interface: interfaceName, ChassisName: values["chassis.name"],
			ChassisMAC: values["chassis.mac"], ManagementIP: values["chassis.mgmt-ip"],
			Port: values["port.local"], PortDescription: values["port.descr"],
			Description: values["chassis.descr"], Age: values["age"], TTL: values["port.ttl"],
		})
	}
	return neighbors
}
