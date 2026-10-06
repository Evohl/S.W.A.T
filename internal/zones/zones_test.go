package zones

import (
	"strings"
	"testing"
)

func sampleConfig() Config {
	return Config{
		Zones: []Zone{
			{Name: "wan", Interfaces: []string{"enp5s0"}, Input: InputRestricted, Access: Access{Services: []string{"https"}}},
			{Name: "lan", Interfaces: []string{"bridge0", "wg0"}, Input: InputRestricted, Access: Access{Services: []string{"ssh", "dns", "ping"}}},
		},
		Policies: []Policy{
			{From: "lan", To: "wan", Mode: ModeAllow, Masquerade: true},
			{From: "wan", To: "lan", Mode: ModeLimited, Access: Access{Ports: []Port{{Proto: "tcp", Start: 8000, End: 8100}}}},
		},
	}
}

func TestGenerate(t *testing.T) {
	script, err := Generate(sampleConfig())
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"delete table inet swat",
		`iifname "enp5s0" jump input_wan`,
		"tcp dport { 443 } accept",
		"tcp dport { 22, 53 } accept",
		"udp dport { 53 } accept",
		`iifname { "bridge0", "wg0" } oifname { "enp5s0" } accept comment "lan>wan"`,
		`tcp dport { 8000-8100 } accept comment "wan>lan"`,
		`iifname { "bridge0", "wg0" } oifname { "bridge0", "wg0" } accept`,
		`iifname { "enp5s0", "bridge0", "wg0" } oifname { "enp5s0", "bridge0", "wg0" } drop`,
		`oifname { "enp5s0" } masquerade comment "lan>wan"`,
	} {
		if !strings.Contains(script, want) {
			t.Errorf("script missing %q\n%s", want, script)
		}
	}
}

func TestGenerateBlocksUnlistedPairsLast(t *testing.T) {
	script, _ := Generate(sampleConfig())
	if strings.Index(script, "accept comment \"lan>wan\"") > strings.Index(script, "zwischen Zonen gesperrt") {
		t.Error("default deny must come after explicit policies")
	}
}

func TestValidateRejectsUnsafeInput(t *testing.T) {
	cases := map[string]func(*Config){
		"quote in zone name":     func(c *Config) { c.Zones[0].Name = `wan"; drop` },
		"quote in interface":     func(c *Config) { c.Zones[0].Interfaces[0] = `eth0" accept` },
		"interface in two zones": func(c *Config) { c.Zones[1].Interfaces = append(c.Zones[1].Interfaces, "enp5s0") },
		"unknown zone":           func(c *Config) { c.Policies[0].To = "dmz" },
		"same zone policy":       func(c *Config) { c.Policies[0].To = "lan" },
		"duplicate pair":         func(c *Config) { c.Policies = append(c.Policies, c.Policies[0]) },
		"limited without ports":  func(c *Config) { c.Policies[1].Ports = nil },
		"unknown service":        func(c *Config) { c.Zones[0].Services = []string{"telnet"} },
		"bad port range":         func(c *Config) { c.Policies[1].Ports[0].End = 70000 },
	}
	for name, mutate := range cases {
		cfg := sampleConfig()
		mutate(&cfg)
		if _, err := Generate(cfg); err == nil {
			t.Errorf("%s: expected error", name)
		}
	}
}

func TestParsePorts(t *testing.T) {
	ports, err := ParsePorts("tcp/443, udp/8000-8100")
	if err != nil || len(ports) != 2 || ports[1].String() != "udp/8000-8100" {
		t.Fatalf("got %v, %v", ports, err)
	}
	for _, bad := range []string{"443", "icmp/1", "tcp/0", "tcp/9-1", "tcp/x"} {
		if _, err := ParsePorts(bad); err == nil {
			t.Errorf("%q should fail", bad)
		}
	}
}

func TestSaveLoadRoundTrip(t *testing.T) {
	dir := t.TempDir()
	if err := Save(dir, sampleConfig()); err != nil {
		t.Fatal(err)
	}
	cfg, err := Load(dir)
	if err != nil || len(cfg.Zones) != 2 || len(cfg.Policies) != 2 {
		t.Fatalf("got %+v, %v", cfg, err)
	}
	empty, err := Load(t.TempDir())
	if err != nil || len(empty.Zones) != 0 {
		t.Fatalf("missing file should yield empty config: %+v, %v", empty, err)
	}
}
