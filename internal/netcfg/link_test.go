package netcfg

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestGenerateInterfaceLinks(t *testing.T) {
	files, err := GenerateInterfaceLinks([]InterfaceNameBinding{
		{PermanentMAC: "AA:BB:CC:DD:EE:01", Name: "wan0"},
		{PermanentMAC: "aa:bb:cc:dd:ee:02", Name: "lan0"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(files) != 2 {
		t.Fatalf("got %d files, want 2", len(files))
	}
	content := string(files["10-swat-nic-aa-bb-cc-dd-ee-01.link"])
	for _, want := range []string{"# Managed-By: SWAT", "PermanentMACAddress=aa:bb:cc:dd:ee:01", "NamePolicy=\nName=wan0"} {
		if !strings.Contains(content, want) {
			t.Errorf("generated link file missing %q: %s", want, content)
		}
	}
}

func TestWriteInterfaceLinksUpdatesAndPrunesOwnedFiles(t *testing.T) {
	directory := t.TempDir()
	bindings := []InterfaceNameBinding{
		{PermanentMAC: "02:00:00:00:00:01", Name: "wan0"},
		{PermanentMAC: "02:00:00:00:00:02", Name: "lan0"},
	}
	if err := WriteInterfaceLinks(directory, bindings); err != nil {
		t.Fatal(err)
	}
	updated := []InterfaceNameBinding{{PermanentMAC: "02:00:00:00:00:01", Name: "uplink0"}}
	if err := WriteInterfaceLinks(directory, updated); err != nil {
		t.Fatal(err)
	}
	current := filepath.Join(directory, "10-swat-nic-02-00-00-00-00-01.link")
	content, err := os.ReadFile(current)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(content), "Name=uplink0\n") {
		t.Fatalf("updated file missing name: %s", content)
	}
	stale := filepath.Join(directory, "10-swat-nic-02-00-00-00-00-02.link")
	if _, err := os.Stat(stale); !os.IsNotExist(err) {
		t.Fatalf("stale SWAT file was not removed: %v", err)
	}
}

func TestWriteInterfaceLinksRefusesForeignReservedFile(t *testing.T) {
	directory := t.TempDir()
	path := filepath.Join(directory, "10-swat-nic-02-00-00-00-00-01.link")
	if err := os.WriteFile(path, []byte("# user-owned\n[Match]\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	err := WriteInterfaceLinks(directory, []InterfaceNameBinding{{PermanentMAC: "02:00:00:00:00:01", Name: "wan0"}})
	if err == nil || !strings.Contains(err.Error(), "fremde oder anders verwaltete Datei") {
		t.Fatalf("WriteInterfaceLinks error = %v, want foreign-file refusal", err)
	}
	content, readErr := os.ReadFile(path)
	if readErr != nil || string(content) != "# user-owned\n[Match]\n" {
		t.Fatalf("foreign file changed: content=%q error=%v", content, readErr)
	}
}

func TestSaveAndLoadInterfaceNameBindings(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state", "network-interface-names.json")
	want := []InterfaceNameBinding{{PermanentMAC: "02:00:00:00:00:01", Name: "wan0"}}
	if err := SaveInterfaceNameBindings(path, want); err != nil {
		t.Fatal(err)
	}
	got, err := LoadInterfaceNameBindings(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0] != want[0] {
		t.Fatalf("loaded bindings = %#v, want %#v", got, want)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("state file permissions = %04o, want 0600", info.Mode().Perm())
	}
}

func TestLoadInterfaceNameBindingsRejectsUnsupportedVersion(t *testing.T) {
	path := filepath.Join(t.TempDir(), "network-interface-names.json")
	data, err := json.Marshal(InterfaceNameConfig{Version: 2})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadInterfaceNameBindings(path); err == nil {
		t.Fatal("unsupported config version was accepted")
	}
}

func TestGenerateInterfaceLinksRejectsUnsafeBindings(t *testing.T) {
	valid := InterfaceNameBinding{PermanentMAC: "02:00:00:00:00:01", Name: "lan0"}
	cases := map[string][]InterfaceNameBinding{
		"invalid MAC":       {{PermanentMAC: "not-a-mac", Name: "lan0"}},
		"multicast MAC":     {{PermanentMAC: "01:00:00:00:00:01", Name: "lan0"}},
		"zero MAC":          {{PermanentMAC: "00:00:00:00:00:00", Name: "lan0"}},
		"invalid name":      {{PermanentMAC: valid.PermanentMAC, Name: "lan/0"}},
		"long name":         {{PermanentMAC: valid.PermanentMAC, Name: "interface-name-too-long"}},
		"numeric name":      {{PermanentMAC: valid.PermanentMAC, Name: "123"}},
		"kernel-style name": {{PermanentMAC: valid.PermanentMAC, Name: "eth0"}},
		"duplicate MAC": {
			valid,
			{PermanentMAC: valid.PermanentMAC, Name: "wan0"},
		},
		"duplicate name": {
			valid,
			{PermanentMAC: "02:00:00:00:00:02", Name: valid.Name},
		},
	}
	for name, bindings := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := GenerateInterfaceLinks(bindings); err == nil {
				t.Fatal("expected validation error")
			}
		})
	}
}
