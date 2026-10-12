package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"testing"

	"swat/internal/moduleadmin"
	"swat/internal/modules"
)

func withPAMSuccess(t *testing.T) {
	t.Helper()
	previous := sudoAuthenticate
	sudoAuthenticate = func(string, string) error { return nil }
	t.Cleanup(func() { sudoAuthenticate = previous })
}

func TestModuleInstallRequiresExplicitConfirmation(t *testing.T) {
	directory := t.TempDir()
	t.Setenv("SWAT_STATE_DIR", directory)
	t.Setenv("SWAT_READ_ONLY", "1")
	t.Setenv("SWAT_MODULE_SETUP", "1")
	withPAMSuccess(t)
	form := url.Values{"action": {"install"}, "modules": {"nginx"}, "sudo_password": {"submitted-only-to-pam"}}
	response := httptest.NewRecorder()
	handleModulesAction(response, adminRequest(t, http.MethodPost, "/admin/modules", form))
	if !strings.Contains(response.Body.String(), "bestätige zuerst") {
		t.Fatalf("package install was not held for explicit confirmation: %.400s", response.Body.String())
	}
}

func TestModulesPageExplainsDependencyPackagesAndServiceStatus(t *testing.T) {
	t.Setenv("SWAT_STATE_DIR", t.TempDir())
	response := httptest.NewRecorder()
	handleModules(response, adminRequest(t, http.MethodGet, "/modules", nil))
	if response.Code != http.StatusOK {
		t.Fatalf("GET /modules status = %d: %.300s", response.Code, response.Body.String())
	}
	for _, expected := range []string{"Module und Dienste", "Mailserver", "postfix", "dovecot", "rspamd", "nginx.service", "Dienste starten erst nach sicherer Grundkonfiguration"} {
		if !strings.Contains(response.Body.String(), expected) {
			t.Errorf("module page missing dependency hint %q", expected)
		}
	}
}

func TestVirtualMachinesNavEntryFollowsModuleReadiness(t *testing.T) {
	t.Setenv("SWAT_STATE_DIR", t.TempDir())
	const navLink = `href="/vms"`

	// adminRequest installs its own inspector stub, so build the request first and override afterwards.
	request := adminRequest(t, http.MethodGet, "/modules", nil)
	inspectModuleCatalog = func(string) ([]modules.Status, modules.Selection, error) {
		selection := modules.Selection{Version: modules.CurrentVersion}
		statuses, err := modules.Statuses(selection, map[string]bool{}, nil)
		return statuses, selection, err
	}
	response := httptest.NewRecorder()
	handleModules(response, request)
	if strings.Contains(response.Body.String(), navLink) {
		t.Fatal("virtual machine nav entry shown although the module is not selected or installed")
	}

	request = adminRequest(t, http.MethodGet, "/modules", nil)
	inspectModuleCatalog = func(string) ([]modules.Status, modules.Selection, error) {
		selection := modules.Selection{Version: modules.CurrentVersion, Selected: []string{"virtualization"}}
		statuses, err := modules.Statuses(selection, map[string]bool{"libvirt": true, "qemu-base": true}, nil)
		return statuses, selection, err
	}
	response = httptest.NewRecorder()
	handleModules(response, request)
	if !strings.Contains(response.Body.String(), navLink) {
		t.Fatal("virtual machine nav entry missing although the module is selected and installed")
	}
}

func TestModuleSelectionRequiresPAMAndPersistsDesiredProfiles(t *testing.T) {
	directory := t.TempDir()
	t.Setenv("SWAT_STATE_DIR", directory)
	t.Setenv("SWAT_READ_ONLY", "1")
	withPAMSuccess(t)
	form := url.Values{"action": {"save-selection"}, "modules": {"mail", "nginx"}, "sudo_password": {"submitted-only-to-pam"}}
	response := httptest.NewRecorder()
	handleModulesAction(response, adminRequest(t, http.MethodPost, "/admin/modules", form))
	if !strings.Contains(response.Body.String(), "Modulauswahl gespeichert") {
		t.Fatalf("module selection not saved: %.400s", response.Body.String())
	}
	selection, err := modules.Load(modules.StatePath(directory))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(selection.Selected, ",") != "mail,network,nginx" {
		t.Fatalf("selected modules = %v", selection.Selected)
	}
	if _, err := os.Stat(directory + "/audit.log"); err != nil {
		t.Fatalf("module action not audited: %v", err)
	}
}

func TestModuleInstallStaysDisabledWithoutHelper(t *testing.T) {
	directory := t.TempDir()
	t.Setenv("SWAT_STATE_DIR", directory)
	t.Setenv("SWAT_READ_ONLY", "1")
	t.Setenv("SWAT_MODULE_SETUP", "0")
	withPAMSuccess(t)
	form := url.Values{"action": {"install"}, "modules": {"nginx"}, "sudo_password": {"submitted-only-to-pam"}, "confirm_install": {"1"}}
	response := httptest.NewRecorder()
	handleModulesAction(response, adminRequest(t, http.MethodPost, "/admin/modules", form))
	if !strings.Contains(response.Body.String(), "nicht freigeschaltet") {
		t.Fatalf("module install should be disabled: %.400s", response.Body.String())
	}
	if _, err := modules.Load(modules.StatePath(directory)); err != nil {
		t.Fatalf("desired module profile should still be saved: %v", err)
	}
}

func TestModuleInstallForwardsOnlySelectedProfilesToHelper(t *testing.T) {
	t.Setenv("SWAT_STATE_DIR", t.TempDir())
	t.Setenv("SWAT_READ_ONLY", "1")
	t.Setenv("SWAT_MODULE_SETUP", "1")
	withPAMSuccess(t)
	previousInstaller := installModulePackages
	installModulePackages = func(_ context.Context, ids []string, username, password string) (moduleadmin.Response, error) {
		if strings.Join(ids, ",") != "network,nginx" || username != "tester" || password != "sudo-secret-for-test" {
			t.Fatalf("helper request mismatch: modules=%v username=%q password=%q", ids, username, password)
		}
		return moduleadmin.Response{OK: true, Installed: []string{"nginx"}, PendingUnits: []string{"nginx.service"}, Message: "test plan"}, nil
	}
	t.Cleanup(func() { installModulePackages = previousInstaller })
	form := url.Values{
		"action":          {"install"},
		"modules":         {"nginx"},
		"sudo_password":   {"sudo-secret-for-test"},
		"confirm_install": {"1"},
	}
	response := httptest.NewRecorder()
	handleModulesAction(response, adminRequest(t, http.MethodPost, "/admin/modules", form))
	if !strings.Contains(response.Body.String(), "test plan") || !strings.Contains(response.Body.String(), "nginx.service") {
		t.Fatalf("helper result not shown: %.400s", response.Body.String())
	}
}

func TestModuleActionsRejectInvalidCSRF(t *testing.T) {
	t.Setenv("SWAT_STATE_DIR", t.TempDir())
	form := url.Values{"action": {"save-selection"}, "modules": {"nginx"}, "sudo_password": {"unused"}}
	request := adminRequest(t, http.MethodPost, "/admin/modules", form)
	request.Form.Set("csrf", "invalid")
	response := httptest.NewRecorder()
	handleModulesAction(response, request)
	if !strings.Contains(response.Body.String(), "Ungültige Anfrage") {
		t.Fatalf("invalid CSRF token accepted: %.300s", response.Body.String())
	}
}
