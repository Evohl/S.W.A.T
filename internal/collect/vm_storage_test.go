package collect

import (
	"encoding/json"
	"testing"
)

func TestNormalizeVMState(t *testing.T) {
	tests := map[string]string{
		"running":  "running",
		"shut off": "stopped",
		"shutoff":  "stopped",
		"paused":   "paused",
		"unknown":  "unknown",
		"":         "unknown",
	}

	for raw, want := range tests {
		if got := normalizeVMState(raw); got != want {
			t.Fatalf("normalizeVMState(%q) = %q, want %q", raw, got, want)
		}
	}
}

func TestDisplayStorageDevices_PrunesRaidMembers(t *testing.T) {
	raid := BlockDevice{
		Name:         "md0",
		Type:         "raid1",
		Usage:        "50%",
		UsagePercent: 50,
		Children: []BlockDevice{{
			Name:   "sda1",
			Type:   "part",
			Parent: "md0",
		}},
	}

	got := DisplayStorageDevices([]BlockDevice{raid})
	if len(got) != 1 {
		t.Fatalf("expected 1 displayed device, got %d", len(got))
	}
	if got[0].Name != "md0" {
		t.Fatalf("expected raid device md0, got %q", got[0].Name)
	}
	if len(got[0].Children) != 0 {
		t.Fatalf("expected RAID member children pruned, got %d children", len(got[0].Children))
	}
	member := BlockDevice{Type: "raid member"}
	if member.IsRAID() {
		t.Fatal("raid member must not be classified as a RAID array")
	}
}

func TestParseLLDPKeyValue(t *testing.T) {
	raw := "lldp.enp10s0f0.via=LLDP\n" +
		"lldp.enp10s0f0.rid=1\n" +
		"lldp.enp10s0f0.chassis.name=PROCURVE J9450A\n" +
		"lldp.enp10s0f0.chassis.mgmt-ip=192.168.2.10\n" +
		"lldp.enp10s0f0.port.local=1\n" +
		"lldp.enp10s0f0.port.descr=Port #1\n" +
		"lldp.enp10s0f0.port.ttl=120\n"

	neighbors := parseLLDPKeyValue(raw)
	if len(neighbors) != 1 {
		t.Fatalf("expected one LLDP neighbor, got %d", len(neighbors))
	}
	neighbor := neighbors[0]
	if neighbor.Interface != "enp10s0f0" || neighbor.ChassisName != "PROCURVE J9450A" || neighbor.ManagementIP != "192.168.2.10" {
		t.Fatalf("unexpected LLDP neighbor: %+v", neighbor)
	}
}

func TestUsableNetworkNeighbor(t *testing.T) {
	for _, state := range []string{"REACHABLE", "STALE", "DELAY", "PROBE", "PERMANENT"} {
		entry := neighborJSON{IfName: "enp10s0f0", Address: "192.168.2.10", LinkLayer: "00:11:22:33:44:55", State: []string{state}}
		if !usableNetworkNeighbor(entry) {
			t.Errorf("state %s should be shown", state)
		}
	}
	for _, state := range []string{"FAILED", "INCOMPLETE", "NOARP"} {
		entry := neighborJSON{IfName: "enp10s0f0", Address: "192.168.2.10", LinkLayer: "00:11:22:33:44:55", State: []string{state}}
		if usableNetworkNeighbor(entry) {
			t.Errorf("state %s should be hidden", state)
		}
	}
}

func TestNeighborJSONUsesLinuxDeviceField(t *testing.T) {
	var entry neighborJSON
	if err := json.Unmarshal([]byte(`{"dst":"10.10.0.1","dev":"enp7s0","lladdr":"5e:81:9b:91:40:6e","state":["REACHABLE"]}`), &entry); err != nil {
		t.Fatal(err)
	}
	if !usableNetworkNeighbor(entry) || entry.IfName != "enp7s0" {
		t.Fatalf("expected valid neighbor on enp7s0, got %+v", entry)
	}
}
