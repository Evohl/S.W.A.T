package modules

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestMailModuleExplainsPackagesAndServices(t *testing.T) {
	definition, ok := DefinitionFor("mail")
	if !ok {
		t.Fatal("mail module not found")
	}
	packages := map[string]bool{}
	for _, dependency := range definition.Packages {
		packages[dependency.Name] = true
	}
	for _, name := range []string{"postfix", "dovecot", "rspamd"} {
		if !packages[name] {
			t.Errorf("mail module missing package %s", name)
		}
	}
	if packages["redis"] == false {
		t.Fatal("mail module should explain the optional Redis dependency")
	}
	if len(definition.Services) < 3 || definition.SafetyNote == "" {
		t.Fatalf("mail dependencies/services are incomplete: %+v", definition)
	}
}

func TestPackagePlanIsAllowlistedSortedAndDeduplicated(t *testing.T) {
	got, err := PackagePlan([]string{"hotspot", "nginx", "hotspot"})
	if err == nil {
		t.Fatal("duplicate modules should be rejected")
	}
	got, err = PackagePlan([]string{"hotspot", "nginx"})
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"dnsmasq", "hostapd", "iproute2", "iw", "nginx", "systemd"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("PackagePlan() = %v, want %v", got, want)
	}
	if _, err := PackagePlan([]string{"../../etc"}); err == nil {
		t.Fatal("unknown module ID was accepted")
	}
	basePlan, err := PackagePlan(nil)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(basePlan, []string{"iproute2", "systemd"}) {
		t.Fatalf("base network package plan = %v", basePlan)
	}
	selection, err := NormalizeSelection(nil)
	if err != nil || !reflect.DeepEqual(selection, []string{"network"}) {
		t.Fatalf("empty selection = %v, error = %v; required network profile should remain selected", selection, err)
	}
}

func TestSaveLoadSelectionAndPackageReadiness(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state", "modules.json")
	saved, err := Save(path, []string{"nginx", "mail"})
	if err != nil {
		t.Fatal(err)
	}
	loaded, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(saved, loaded) {
		t.Fatalf("loaded selection = %#v, want %#v", loaded, saved)
	}
	info, err := os.Stat(path)
	if err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("state permissions = %v, error = %v", info.Mode().Perm(), err)
	}
	statuses, err := Statuses(loaded, map[string]bool{"nginx": true}, nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, status := range statuses {
		if status.ID == "nginx" && (!status.Selected || !status.Ready) {
			t.Fatalf("nginx status = %+v", status)
		}
		if status.ID == "mail" && (!status.Selected || status.Ready) {
			t.Fatalf("mail should remain not-ready while dependencies are missing: %+v", status)
		}
	}
}

func TestInspectUsesFixedPackageAndUnitQueries(t *testing.T) {
	path := filepath.Join(t.TempDir(), "modules.json")
	if _, err := Save(path, []string{"nginx"}); err != nil {
		t.Fatal(err)
	}
	var pacmanQueries, unitQueries int
	statuses, selection, err := InspectWith(path, func(name string, args ...string) ([]byte, error) {
		switch name {
		case "pacman":
			pacmanQueries++
			if len(args) < 3 || args[0] != "-Q" || args[1] != "--" {
				t.Fatalf("unexpected pacman query args: %v", args)
			}
			return []byte("nginx 1.2-1\n"), nil
		case "systemctl":
			unitQueries++
			if args[0] == "is-active" {
				return []byte(strings.Repeat("inactive\n", len(args)-1)), nil
			}
			return []byte(strings.Repeat("disabled\n", len(args)-1)), nil
		default:
			t.Fatalf("unexpected command %q", name)
			return nil, os.ErrNotExist
		}
	})
	if err != nil {
		t.Fatal(err)
	}
	if pacmanQueries != 1 || unitQueries != 2 || !reflect.DeepEqual(selection.Selected, []string{"network", "nginx"}) {
		t.Fatalf("inspect queries/status mismatch: pacman=%d systemctl=%d selection=%+v", pacmanQueries, unitQueries, selection)
	}
	for _, status := range statuses {
		if status.ID == "nginx" && !status.Ready {
			t.Fatalf("installed selected nginx should be ready: %+v", status)
		}
	}
}
