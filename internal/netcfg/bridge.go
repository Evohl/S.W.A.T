package netcfg

import (
	"encoding/json"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

const (
	maxBridges      = 32
	maxBridgePorts  = 16
	maxAddresses    = 16
	maxDNSServers   = 8
)

var (
	bridgeNamePattern = regexp.MustCompile(`^br[-A-Za-z0-9_.]{1,12}$`)
	linkNamePattern   = regexp.MustCompile(`^[A-Za-z0-9_.:-]{1,15}$`)
)

type Bridge struct {
	Name      string   `json:"name"`
	Ports     []string `json:"ports"`
	Addresses []string `json:"addresses"`
	Gateway   string   `json:"gateway,omitempty"`
	DNS       []string `json:"dns,omitempty"`
	DHCP      bool     `json:"dhcp,omitempty"`
	STP       bool     `json:"stp"`
}

type Config struct {
	Bridges []Bridge `json:"bridges"`
}

func (b Bridge) Validate() error {
	if !bridgeNamePattern.MatchString(b.Name) {
		return fmt.Errorf("Bridge-Name %q ist ungültig (br-..., maximal 15 Zeichen)", b.Name)
	}
	if len(b.Ports) == 0 {
		return fmt.Errorf("Bridge %s braucht mindestens ein Port-Interface", b.Name)
	}
	if len(b.Ports) > maxBridgePorts {
		return fmt.Errorf("Bridge %s unterstützt maximal %d Port-Interfaces", b.Name, maxBridgePorts)
	}
	if len(b.Addresses) > maxAddresses || len(b.DNS) > maxDNSServers {
		return fmt.Errorf("Bridge %s hat zu viele Adressen oder DNS-Server", b.Name)
	}
	seen := make(map[string]bool)
	for _, port := range b.Ports {
		if !linkNamePattern.MatchString(port) || port == "lo" || port == b.Name {
			return fmt.Errorf("ungültiges Port-Interface %q", port)
		}
		if seen[port] {
			return fmt.Errorf("Interface %q wurde mehrfach zugewiesen", port)
		}
		seen[port] = true
	}
	if b.DHCP && (len(b.Addresses) > 0 || b.Gateway != "") {
		return fmt.Errorf("DHCP und statische Adressen oder Gateway können nicht zusammen verwendet werden")
	}
	prefixes := make([]netip.Prefix, 0, len(b.Addresses))
	for _, text := range b.Addresses {
		prefix, err := netip.ParsePrefix(text)
		if err != nil || !prefix.Addr().IsValid() || prefix.Addr().IsUnspecified() || prefix.Addr().IsMulticast() || prefix.Addr().IsLoopback() {
			return fmt.Errorf("ungültige Bridge-Adresse %q (CIDR erwartet)", text)
		}
		for _, existing := range prefixes {
			if existing.Addr() == prefix.Addr() {
				return fmt.Errorf("Bridge-Adresse %q ist doppelt oder hat einen anderen Präfix", text)
			}
		}
		prefixes = append(prefixes, prefix)
	}
	if !b.DHCP && len(prefixes) == 0 {
		return fmt.Errorf("Bridge braucht DHCP oder mindestens eine statische Adresse")
	}
	if b.Gateway != "" {
		gateway, err := netip.ParseAddr(b.Gateway)
		if err != nil || gateway.IsUnspecified() || gateway.IsMulticast() || gateway.IsLoopback() {
			return fmt.Errorf("ungültiges Gateway %q", b.Gateway)
		}
		valid := false
		for _, prefix := range prefixes {
			if prefix.Addr().Is4() == gateway.Is4() && prefix.Contains(gateway) {
				valid = true
				break
			}
		}
		if !valid {
			return fmt.Errorf("Gateway %q muss in einem der Bridge-Subnetze liegen", b.Gateway)
		}
	}
	for _, text := range b.DNS {
		addr, err := netip.ParseAddr(text)
		if err != nil || addr.IsUnspecified() || addr.IsMulticast() {
			return fmt.Errorf("ungültiger DNS-Server %q", text)
		}
	}
	return nil
}

func (c Config) Validate() error {
	if len(c.Bridges) > maxBridges {
		return fmt.Errorf("maximal %d Bridges werden unterstützt", maxBridges)
	}
	seenBridges := make(map[string]bool)
	seenPorts := make(map[string]string)
	type bridgePrefix struct {
		bridge string
		prefix netip.Prefix
	}
	var bridgePrefixes []bridgePrefix
	for _, bridge := range c.Bridges {
		if err := bridge.Validate(); err != nil {
			return err
		}
		if seenBridges[bridge.Name] {
			return fmt.Errorf("Bridge %q ist doppelt vorhanden", bridge.Name)
		}
		seenBridges[bridge.Name] = true
		for _, address := range bridge.Addresses {
			prefix, _ := netip.ParsePrefix(address)
			for _, existing := range bridgePrefixes {
				if existing.prefix.Addr().Is4() == prefix.Addr().Is4() && (existing.prefix.Contains(prefix.Addr()) || prefix.Contains(existing.prefix.Addr())) {
					return fmt.Errorf("Bridge-Netze %s und %s überlappen sich", existing.bridge, bridge.Name)
				}
			}
			bridgePrefixes = append(bridgePrefixes, bridgePrefix{bridge: bridge.Name, prefix: prefix})
		}
		for _, port := range bridge.Ports {
			if owner, exists := seenPorts[port]; exists {
				return fmt.Errorf("Interface %q ist bereits Bridge %q zugewiesen", port, owner)
			}
			seenPorts[port] = bridge.Name
		}
	}
	return nil
}

// Generate creates only SWAT-owned .netdev and .network files.
func Generate(c Config) (map[string][]byte, error) {
	if err := c.Validate(); err != nil {
		return nil, err
	}
	files := make(map[string][]byte, len(c.Bridges)*2)
	for _, bridge := range c.Bridges {
		var netdev strings.Builder
		fmt.Fprintf(&netdev, "# Managed-By: SWAT\n# SWAT-Config-ID: network/bridge/%s\n[NetDev]\nName=%s\nKind=bridge\n[Bridge]\nSTP=%t\n", bridge.Name, bridge.Name, bridge.STP)
		files[BridgeFileName(bridge.Name, "netdev")] = []byte(netdev.String())

		var network strings.Builder
		fmt.Fprintf(&network, "# Managed-By: SWAT\n# SWAT-Config-ID: network/bridge/%s\n[Match]\nName=%s\n[Network]\n", bridge.Name, bridge.Name)
		if bridge.DHCP {
			network.WriteString("DHCP=yes\n")
		}
		for _, address := range bridge.Addresses {
			fmt.Fprintf(&network, "Address=%s\n", address)
		}
		if bridge.Gateway != "" {
			fmt.Fprintf(&network, "Gateway=%s\n", bridge.Gateway)
		}
		for _, dns := range bridge.DNS {
			fmt.Fprintf(&network, "DNS=%s\n", dns)
		}
		files[BridgeFileName(bridge.Name, "network")] = []byte(network.String())

		ports := append([]string(nil), bridge.Ports...)
		sort.Strings(ports)
		for _, port := range ports {
			member := fmt.Sprintf("# Managed-By: SWAT\n# SWAT-Config-ID: network/bridge/%s/port/%s\n[Match]\nName=%s\n[Network]\nBridge=%s\n", bridge.Name, port, port, bridge.Name)
			files[PortFileName(bridge.Name, port)] = []byte(member)
		}
	}
	return files, nil
}

func BridgeFileName(name, suffix string) string { return "90-swat-bridge-" + name + "." + suffix }
func PortFileName(bridge, port string) string   { return "91-swat-port-" + bridge + "-" + port + ".network" }

func Load(path string) (Config, error) {
	data, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return Config{}, nil
	}
	if err != nil {
		return Config{}, err
	}
	var config Config
	if err := json.Unmarshal(data, &config); err != nil {
		return Config{}, err
	}
	return config, config.Validate()
}

func Save(path string, config Config) error {
	if err := config.Validate(); err != nil {
		return err
	}
	data, err := json.MarshalIndent(config, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".network-*.tmp")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), path)
}
