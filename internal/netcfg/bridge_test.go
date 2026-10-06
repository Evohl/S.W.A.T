package netcfg

import (
	"strings"
	"testing"
)

func TestGenerateBridge(t *testing.T) {
	config := Config{Bridges: []Bridge{{
		Name:      "br-lan",
		Ports:     []string{"enp2s0", "enp1s0"},
		Addresses: []string{"192.168.20.1/24", "fd10::1/64"},
		Gateway:   "192.168.20.254",
		DNS:       []string{"192.168.20.2", "fd10::2"},
		STP:       true,
	}}}
	files, err := Generate(config)
	if err != nil {
		t.Fatal(err)
	}
	if len(files) != 4 {
		t.Fatalf("generated %d files, want bridge netdev, bridge network and two port files", len(files))
	}
	wants := map[string]string{
		"90-swat-bridge-br-lan.netdev":  "Kind=bridge\n[Bridge]\nSTP=true",
		"90-swat-bridge-br-lan.network": "Address=192.168.20.1/24\nAddress=fd10::1/64\nGateway=192.168.20.254\nDNS=192.168.20.2\nDNS=fd10::2",
		"91-swat-port-br-lan-enp1s0.network": "Name=enp1s0\n[Network]\nBridge=br-lan",
		"91-swat-port-br-lan-enp2s0.network": "Name=enp2s0\n[Network]\nBridge=br-lan",
	}
	for name, want := range wants {
		content, ok := files[name]
		if !ok || !strings.Contains(string(content), want) {
			t.Errorf("%s missing content %q: %s", name, want, content)
		}
	}
}

func TestValidateBridgeRejectsUnsafeConfigs(t *testing.T) {
	cases := map[string]func(*Config){
		"bad name": func(c *Config) { c.Bridges[0].Name = "br/lan" },
		"no ports": func(c *Config) { c.Bridges[0].Ports = nil },
		"duplicate port": func(c *Config) { c.Bridges[0].Ports = []string{"enp1s0", "enp1s0"} },
		"same port in two bridges": func(c *Config) {
			c.Bridges = append(c.Bridges, Bridge{Name: "br-dmz", Ports: []string{"enp1s0"}, Addresses: []string{"10.0.0.1/24"}})
		},
		"invalid address": func(c *Config) { c.Bridges[0].Addresses = []string{"not-an-address"} },
		"gateway family or subnet mismatch": func(c *Config) { c.Bridges[0].Gateway = "10.0.0.1" },
		"dhcp and static address": func(c *Config) { c.Bridges[0].DHCP = true },
		"no address mode": func(c *Config) { c.Bridges[0].Addresses = nil },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			config := Config{Bridges: []Bridge{{Name: "br-lan", Ports: []string{"enp1s0"}, Addresses: []string{"192.168.1.10/24"}}}}
			mutate(&config)
			if err := config.Validate(); err == nil {
				t.Fatal("expected validation error")
			}
		})
	}
}

func TestBridgeDHCP(t *testing.T) {
	files, err := Generate(Config{Bridges: []Bridge{{Name: "br-vm", Ports: []string{"tap0"}, DHCP: true}}})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(files["90-swat-bridge-br-vm.network"]), "DHCP=yes") {
		t.Fatal("DHCP mode not generated")
	}
}

func TestValidateRejectsOverlappingBridgeNetworks(t *testing.T) {
	config := Config{Bridges: []Bridge{
		{Name: "br-lan", Ports: []string{"enp1s0"}, Addresses: []string{"192.168.1.1/24"}},
		{Name: "br-dmz", Ports: []string{"enp2s0"}, Addresses: []string{"192.168.1.129/25"}},
	}}
	if err := config.Validate(); err == nil {
		t.Fatal("overlapping IPv4 bridge networks should be rejected")
	}
}