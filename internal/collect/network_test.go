package collect

import (
	"strings"
	"testing"
)

func TestParsePermanentMAC(t *testing.T) {
	for _, test := range []struct {
		output string
		want   string
	}{
		{"Permanent address: AA:BB:CC:DD:EE:FF\n", "aa:bb:cc:dd:ee:ff"},
		{"Permanent address: not-a-mac\n", ""},
		{"Current hardware address: aa:bb:cc:dd:ee:ff\n", ""},
	} {
		if got := parsePermanentMAC([]byte(test.output)); got != test.want {
			t.Errorf("parsePermanentMAC(%q) = %q, want %q", test.output, got, test.want)
		}
	}
}

func TestInterfaceHardwareUsesDatabaseNames(t *testing.T) {
	got := interfaceHardware(map[string]string{
		"ID_VENDOR_FROM_DATABASE": "Example Vendor",
		"ID_MODEL_FROM_DATABASE":  "Ethernet Controller",
	}, "/no-device")
	if got != "Example Vendor Ethernet Controller" {
		t.Fatalf("interfaceHardware() = %q", got)
	}
}

func TestNetworkConfigIncludesStableAdapterIdentity(t *testing.T) {
	page := NetworkConfig([]Interface{{
		Name:             "enp2s0",
		Address:          "aa:bb:cc:dd:ee:ff",
		PermanentAddress: "aa:bb:cc:dd:ee:ff",
		Hardware:         "Example Vendor Ethernet Controller",
	}}, NetworkRuntime{})
	if len(page.Sections) == 0 || len(page.Sections[0].Rows) != 1 {
		t.Fatal("network adapter row missing")
	}
	row := strings.Join(page.Sections[0].Rows[0], " ")
	for _, want := range []string{"enp2s0", "aa:bb:cc:dd:ee:ff", "Example Vendor Ethernet Controller"} {
		if !strings.Contains(row, want) {
			t.Errorf("adapter identity row missing %q: %s", want, row)
		}
	}
}
