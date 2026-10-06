package zones

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestPingServiceReplacesFlag(t *testing.T) {
	script, err := Generate(sampleConfig())
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(script, "icmp type echo-request accept") || !strings.Contains(script, "icmpv6 type echo-request accept") {
		t.Errorf("zone with ping service must accept echo requests\n%s", script)
	}

	cfg := sampleConfig()
	cfg.Zones[0].Services = append(cfg.Zones[0].Services, "ping")
	cfg.Policies[1] = Policy{From: "wan", To: "lan", Mode: ModeLimited, Access: Access{Services: []string{"ping"}}}
	script, err = Generate(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(script, `icmp type echo-request accept comment "wan>lan"`) {
		t.Errorf("policy with ping service must forward echo requests\n%s", script)
	}
}

func TestLoadMigratesLegacyPingFlag(t *testing.T) {
	dir := t.TempDir()
	legacy := map[string]any{"zones": []map[string]any{{"name": "lan", "interfaces": []string{"br0"}, "input": "restricted", "ping": true, "isolated": false}}}
	data, _ := json.Marshal(legacy)
	if err := os.WriteFile(filepath.Join(dir, "zones.json"), data, 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := Load(dir)
	if err != nil || !cfg.Zones[0].HasService(PingService) || cfg.Zones[0].Ping {
		t.Fatalf("legacy ping flag not migrated: %+v, %v", cfg.Zones, err)
	}
}

func TestPortRulesMergeOverlaps(t *testing.T) {
	rules := portRules([]Port{
		{Proto: "tcp", Start: 443, End: 443},
		{Proto: "tcp", Start: 443, End: 443},
		{Proto: "tcp", Start: 8000, End: 8100},
		{Proto: "tcp", Start: 8050, End: 8200},
		{Proto: "tcp", Start: 8201, End: 8300},
		{Proto: "udp", Start: 53, End: 53},
	})
	want := []string{"tcp dport { 443, 8000-8300 }", "udp dport { 53 }"}
	if strings.Join(rules, "|") != strings.Join(want, "|") {
		t.Errorf("got %v, want %v", rules, want)
	}
}

func TestValidateRejectsConflictingTranslations(t *testing.T) {
	cfg := natConfig()
	cfg.Zones = append(cfg.Zones, Zone{Name: "dmz", Interfaces: []string{"eth9"}, Input: InputRestricted})
	cfg.Policies = append(cfg.Policies, Policy{
		From: "wan", To: "dmz", Mode: ModeLimited,
		Access: Access{Ports: []Port{{Proto: "tcp", Start: 2222, End: 2222, To: "10.0.0.9:22"}}},
	})
	if _, err := Generate(cfg); err == nil {
		t.Error("the same port translated twice from one zone must be rejected")
	}
}

func TestValidateCapsCustomPorts(t *testing.T) {
	cfg := sampleConfig()
	for i := 0; i <= maxCustomPorts; i++ {
		cfg.Zones[0].Ports = append(cfg.Zones[0].Ports, Port{Proto: "tcp", Start: i%60000 + 1, End: i%60000 + 1})
	}
	if _, err := Generate(cfg); err == nil {
		t.Error("expected an error for too many custom ports")
	}
}
