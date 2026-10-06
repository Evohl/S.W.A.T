package zones

import (
	"strings"
	"testing"
)

func natConfig() Config {
	cfg := sampleConfig()
	cfg.Policies[1] = Policy{
		From: "wan", To: "lan", Mode: ModeLimited,
		Access: Access{
			Services:   []string{"ntp", "https"},
			ServiceNAT: map[string]string{"ntp": "10123", "https": "192.168.1.10:8443"},
			Ports: []Port{
				{Proto: "tcp", Start: 2222, End: 2222, To: "192.168.1.5:22"},
				{Proto: "udp", Start: 9000, End: 9000},
			},
		},
	}
	return cfg
}

func TestGenerateTranslation(t *testing.T) {
	script, err := Generate(natConfig())
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"chain prerouting {",
		`iifname { "enp5s0" } udp dport 123 dnat to :10123 comment "wan>lan"`,
		`iifname { "enp5s0" } tcp dport 443 dnat ip to 192.168.1.10:8443 comment "wan>lan"`,
		`iifname { "enp5s0" } tcp dport 2222 dnat ip to 192.168.1.5:22 comment "wan>lan"`,
		`oifname { "bridge0", "wg0" } udp dport 10123 accept comment "wan>lan"`,
		`oifname { "bridge0", "wg0" } ip daddr 192.168.1.10 tcp dport 8443 accept comment "wan>lan"`,
		`udp dport { 9000 } accept comment "wan>lan"`,
	} {
		if !strings.Contains(script, want) {
			t.Errorf("script missing %q\n%s", want, script)
		}
	}
	if strings.Contains(script, "dport 123 accept") {
		t.Error("translated port must not be accepted untranslated")
	}
}

func TestValidateTranslation(t *testing.T) {
	cases := map[string]func(*Config){
		"nat on zone":        func(c *Config) { c.Zones[0].ServiceNAT = map[string]string{"https": "8443"} },
		"unselected service": func(c *Config) { c.Policies[1].ServiceNAT = map[string]string{"dns": "5353"} },
		"ambiguous service": func(c *Config) {
			c.Policies[1].Services = []string{"smb"}
			c.Policies[1].ServiceNAT = map[string]string{"smb": "4450"}
		},
		"bad target": func(c *Config) { c.Policies[1].ServiceNAT = map[string]string{"ntp": "host:80"} },
		"range translation": func(c *Config) {
			c.Policies[1].Ports = []Port{{Proto: "tcp", Start: 8000, End: 8100, To: "80"}}
		},
	}
	for name, mutate := range cases {
		cfg := natConfig()
		mutate(&cfg)
		if _, err := Generate(cfg); err == nil {
			t.Errorf("%s: expected error", name)
		}
	}
}

func TestParseTarget(t *testing.T) {
	for text, want := range map[string]int{"80": 80, "10.0.0.5:8080": 8080, "[2001:db8::5]:443": 443} {
		target, err := ParseTarget(text)
		if err != nil || target.Port != want {
			t.Errorf("%q: %+v, %v", text, target, err)
		}
	}
	for _, bad := range []string{"", "0", "70000", "10.0.0.5", "10.0.0.5:0", "name:80"} {
		if _, err := ParseTarget(bad); err == nil {
			t.Errorf("%q should fail", bad)
		}
	}
}
