package main

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"swat/internal/modules"
	"swat/internal/nginxcfg"
)

func enableNginxModuleForTest(t *testing.T) {
	t.Helper()
	previous := inspectModuleCatalog
	inspectModuleCatalog = func(string) ([]modules.Status, modules.Selection, error) {
		selection := modules.Selection{Version: modules.CurrentVersion, Selected: []string{"nginx"}}
		statuses, err := modules.Statuses(selection, map[string]bool{"nginx": true}, nil)
		return statuses, selection, err
	}
	t.Cleanup(func() { inspectModuleCatalog = previous })
}

func TestNginxPageRendersDesiredStateAndPreview(t *testing.T) {
	t.Setenv("SWAT_STATE_DIR", t.TempDir())
	enableNginxModuleForTest(t)
	response := httptest.NewRecorder()
	handleNginx(response, adminRequest(t, http.MethodGet, "/nginx", nil))
	if response.Code != http.StatusOK {
		t.Fatalf("GET /nginx status = %d: %.300s", response.Code, response.Body.String())
	}
	for _, expected := range []string{"Nginx", "Desired State", "Vorschau, noch nicht angewendet", "# Managed-By: SWAT", "/admin/nginx"} {
		if !strings.Contains(response.Body.String(), expected) {
			t.Errorf("Nginx page missing %q", expected)
		}
	}
}

func TestNginxActionsSaveEditAndDeleteDesiredState(t *testing.T) {
	directory := t.TempDir()
	t.Setenv("SWAT_STATE_DIR", directory)
	enableNginxModuleForTest(t)
	form := url.Values{
		"action":       {"save"},
		"server_names": {"app.example.test, www.example.test"},
		"mode":         {"proxy"},
		"upstream":     {"http://127.0.0.1:8080"},
	}
	response := httptest.NewRecorder()
	handleNginxAction(response, adminRequest(t, http.MethodPost, "/admin/nginx", form))
	if !strings.Contains(response.Body.String(), "Nginx-vHost als Desired State gespeichert") {
		t.Fatalf("vHost was not saved: %.500s", response.Body.String())
	}
	if !strings.Contains(response.Body.String(), "server {") || !strings.Contains(response.Body.String(), "proxy_pass http://127.0.0.1:8080;") {
		t.Fatalf("generated Nginx preview missing saved vHost: %.700s", response.Body.String())
	}
	configPath := nginxcfg.StatePath(directory)
	config, err := nginxcfg.Load(configPath)
	if err != nil {
		t.Fatal(err)
	}
	if len(config.Sites) != 1 || config.Sites[0].ServerNames[0] != "app.example.test" {
		t.Fatalf("saved config = %#v", config)
	}
	if _, err := os.Stat(configPath); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(configPath)
	if err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("state permissions = %v, error = %v", info.Mode().Perm(), err)
	}

	edit := url.Values{"action": {"save"}, "original_name": {"app.example.test"}, "server_names": {"app.example.test"}, "mode": {"static"}, "document_root": {"/srv/www/app"}}
	response = httptest.NewRecorder()
	handleNginxAction(response, adminRequest(t, http.MethodPost, "/admin/nginx", edit))
	config, err = nginxcfg.Load(configPath)
	if err != nil || len(config.Sites) != 1 || config.Sites[0].Mode != "static" {
		t.Fatalf("updated config = %#v, error = %v", config, err)
	}

	remove := url.Values{"action": {"delete"}, "original_name": {"app.example.test"}}
	response = httptest.NewRecorder()
	handleNginxAction(response, adminRequest(t, http.MethodPost, "/admin/nginx", remove))
	config, err = nginxcfg.Load(configPath)
	if err != nil || len(config.Sites) != 0 {
		t.Fatalf("deleted config = %#v, error = %v", config, err)
	}
	if _, err := os.Stat(filepath.Join(directory, "audit.log")); err != nil {
		t.Fatalf("audit log was not written: %v", err)
	}
}

func TestNginxActionsRequireAdminCSRFAndRejectUnsafeInput(t *testing.T) {
	directory := t.TempDir()
	t.Setenv("SWAT_STATE_DIR", directory)
	t.Setenv("SWAT_READ_ONLY", "0")
	enableNginxModuleForTest(t)
	form := url.Values{"action": {"save"}, "server_names": {"app.example.test"}, "mode": {"proxy"}, "upstream": {"http://127.0.0.1:8080; include /tmp/bad"}}
	response := httptest.NewRecorder()
	handleNginxAction(response, adminRequest(t, http.MethodPost, "/admin/nginx", form))
	if !strings.Contains(response.Body.String(), "Upstream muss") {
		t.Fatalf("unsafe upstream accepted: %.500s", response.Body.String())
	}
	if _, err := os.Stat(nginxcfg.StatePath(directory)); !os.IsNotExist(err) {
		t.Fatalf("invalid state was persisted: %v", err)
	}

	sessionID, _, err := startSession("viewer")
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodPost, "/admin/nginx", strings.NewReader(""))
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	request.AddCookie(&http.Cookie{Name: sessionCookie, Value: sessionID})
	response = httptest.NewRecorder()
	handleNginxAction(response, request)
	if !strings.Contains(response.Body.String(), "Root-Zugriff erforderlich") {
		t.Fatalf("non-admin request was not rejected: %.300s", response.Body.String())
	}

	admin := adminRequest(t, http.MethodPost, "/admin/nginx", url.Values{"action": {"save"}})
	admin.Form.Set("csrf", "invalid")
	response = httptest.NewRecorder()
	handleNginxAction(response, admin)
	if !strings.Contains(response.Body.String(), "Ungültige Anfrage") {
		t.Fatalf("invalid CSRF token was not rejected: %.300s", response.Body.String())
	}
}

func TestNginxPageRequiresSelectedAndInstalledModule(t *testing.T) {
	t.Setenv("SWAT_STATE_DIR", t.TempDir())
	previous := inspectModuleCatalog
	inspectModuleCatalog = modules.Inspect
	t.Cleanup(func() { inspectModuleCatalog = previous })
	sessionID, _, err := startSession("tester")
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodGet, "/nginx", nil)
	request.AddCookie(&http.Cookie{Name: sessionCookie, Value: sessionID})
	response := httptest.NewRecorder()
	handleNginx(response, request)
	if response.Code != http.StatusSeeOther || response.Header().Get("Location") != "/modules?required=nginx" {
		t.Fatalf("unavailable Nginx page response = %d, location %q", response.Code, response.Header().Get("Location"))
	}
}
