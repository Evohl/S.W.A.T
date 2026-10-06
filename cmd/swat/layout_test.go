package main

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// Every page must render through the shared layout without template errors.
func TestPagesRenderThroughLayout(t *testing.T) {
	t.Setenv("SWAT_STATE_DIR", t.TempDir())
	handlers := map[string]http.HandlerFunc{
		"/":             handleOverview,
		"/services":     handleServices,
		"/storage":      handleStorage,
		"/vms":          handleVMs,
		"/logs":         handleLogs,
		"/network":      handleNetwork,
		"/network-info": handleNetworkInfo,
		"/firewall":     handleFirewall,
		"/libvirt":      handleLibvirt,
		"/system":       handleSystem,
		"/users":        handleUsers,
		"/settings":     handleSettings,

		"/service?unit=systemd-journald.service": handleService,
	}
	for path, handler := range handlers {
		response := httptest.NewRecorder()
		handler(response, adminRequest(t, http.MethodGet, path, nil))
		body := response.Body.String()
		if response.Code != http.StatusOK {
			t.Errorf("%s: status %d: %.200s", path, response.Code, body)
			continue
		}
		for _, want := range []string{"<!DOCTYPE html>", `<main class="main">`, `<h1 class="page-title">`, "/static/theme.js", "</html>"} {
			if !strings.Contains(body, want) {
				t.Errorf("%s: missing %q", path, want)
			}
		}
		if strings.Count(body, "<html") != 1 {
			t.Errorf("%s: expected exactly one <html> element", path)
		}
	}
}

func TestLoginUsesAuthLayout(t *testing.T) {
	response := httptest.NewRecorder()
	handleLogin(response, httptest.NewRequest(http.MethodGet, "/login", nil))
	body := response.Body.String()
	if response.Code != http.StatusOK || !strings.Contains(body, `class="auth-page"`) || strings.Contains(body, `class="sidebar`) {
		t.Fatalf("login did not render standalone: %d %.200s", response.Code, body)
	}
}
