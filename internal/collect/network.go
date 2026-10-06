package collect

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// AddrInfo is one address assigned to an interface.
type AddrInfo struct {
	Family    string `json:"family"`
	Local     string `json:"local"`
	PrefixLen int    `json:"prefixlen"`
	Scope     string `json:"scope"`
}

// Interface represents one network interface as reported by `ip -j addr show`.
type Interface struct {
	Index     int        `json:"ifindex"`
	Name      string     `json:"ifname"`
	Flags     []string   `json:"flags"`
	MTU       int        `json:"mtu"`
	OperState string     `json:"operstate"`
	LinkType  string     `json:"link_type"`
	Address   string     `json:"address"`
	Addrs     []AddrInfo `json:"addr_info"`
	IsBridge  bool       `json:"-"`
}

type NetworkFile struct {
	Name string
	Path string
	Size string
}

type NetworkRuntime struct {
	Networkd       string
	Resolved       string
	IPv4Forwarding string
	IPv6Forwarding string
	DNS            string
	Files          []NetworkFile
}

// Interfaces returns all network interfaces with their addresses.
func Interfaces() ([]Interface, error) {
	cmd := exec.Command("ip", "-j", "addr", "show")
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("ip -j addr show: %w: %s", err, stderr.String())
	}

	var ifaces []Interface
	if err := json.Unmarshal(stdout.Bytes(), &ifaces); err != nil {
		return nil, fmt.Errorf("parsing ip output: %w", err)
	}
	bridges := bridgeInterfaceNames()
	for index := range ifaces {
		if bridges[ifaces[index].Name] {
			ifaces[index].IsBridge = true
		}
	}
	return ifaces, nil
}

func bridgeInterfaceNames() map[string]bool {
	output, err := exec.Command("ip", "-j", "link", "show", "type", "bridge").Output()
	if err != nil {
		return nil
	}
	var bridges []struct {
		Name string `json:"ifname"`
	}
	if err := json.Unmarshal(output, &bridges); err != nil {
		return nil
	}
	names := make(map[string]bool, len(bridges))
	for _, bridge := range bridges {
		names[bridge.Name] = true
	}
	return names
}

func NetworkRuntimeStatus() NetworkRuntime {
	runtime := NetworkRuntime{
		Networkd:       serviceState("systemd-networkd.service"),
		Resolved:       serviceState("systemd-resolved.service"),
		IPv4Forwarding: kernelValue("/proc/sys/net/ipv4/ip_forward"),
		IPv6Forwarding: kernelValue("/proc/sys/net/ipv6/conf/all/forwarding"),
		DNS:            commandOutput("resolvectl", "status"),
	}
	runtime.Files = networkFiles("/etc/systemd/network")
	return runtime
}

func serviceState(unit string) string {
	output, err := exec.Command("systemctl", "is-active", unit).Output()
	if err != nil {
		return "nicht aktiv"
	}
	return strings.TrimSpace(string(output))
}

func kernelValue(path string) string {
	value, err := os.ReadFile(path)
	if err != nil {
		return "nicht verfügbar"
	}
	return strings.TrimSpace(string(value))
}

func commandOutput(command string, args ...string) string {
	output, err := exec.Command(command, args...).CombinedOutput()
	if err != nil {
		return "Nicht verfügbar"
	}
	return strings.TrimSpace(string(output))
}

func networkFiles(directory string) []NetworkFile {
	entries, err := os.ReadDir(directory)
	if err != nil {
		return nil
	}
	files := make([]NetworkFile, 0)
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".network") && !strings.HasSuffix(entry.Name(), ".netdev") && !strings.HasSuffix(entry.Name(), ".link") {
			continue
		}
		info, err := entry.Info()
		if err != nil {
			continue
		}
		files = append(files, NetworkFile{Name: entry.Name(), Path: filepath.Join(directory, entry.Name()), Size: fmt.Sprintf("%d B", info.Size())})
	}
	return files
}
