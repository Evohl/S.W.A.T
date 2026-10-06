package main

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

func TestReadOnlyModeHidesAndBlocksRootAccess(t *testing.T) {
	t.Setenv("SWAT_READ_ONLY", "1")
	if !readOnlyMode() {
		t.Fatal("read-only mode should be enabled")
	}

	sessionID, session, err := startSession("admin")
	if err != nil {
		t.Fatal(err)
	}
	session.AdminAccess = true
	session.RootAccess = true
	session.RootRequested = true
	session.SudoPassword = "not-used"
	sessions.Lock()
	sessions.items[sessionID] = session
	sessions.Unlock()

	request := httptest.NewRequest(http.MethodPost, "/admin/users/create", nil)
	request.Form = url.Values{"csrf": {session.CSRFToken}}
	request.AddCookie(&http.Cookie{Name: sessionCookie, Value: sessionID})
	view := authData(request)
	if view.RootAccess || view.AdminAccess || view.RootRequested {
		t.Fatalf("read-only mode exposed privilege state: %+v", view)
	}
	if _, err := accountActionSession(request); err == nil || !strings.Contains(err.Error(), "Read-only-Modus") {
		t.Fatalf("account action not blocked in read-only mode: %v", err)
	}
	if err := runAsRoot("unused", "touch", "/tmp/swat-readonly-test"); err == nil || !strings.Contains(err.Error(), "Read-only-Modus") {
		t.Fatalf("root command not blocked in read-only mode: %v", err)
	}
	if _, err := runAsRootCapture("unused", "id"); err == nil || !strings.Contains(err.Error(), "Read-only-Modus") {
		t.Fatalf("root capture not blocked in read-only mode: %v", err)
	}
}

func TestReadOnlyModeRejectsRootRequestWithoutPAM(t *testing.T) {
	t.Setenv("SWAT_READ_ONLY", "1")
	called := false
	original := pamAuthenticate
	pamAuthenticate = func(string, string, string) error {
		called = true
		return nil
	}
	defer func() { pamAuthenticate = original }()

	response := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPost, "/admin/request-root", nil)
	handleRootAccessRequest(response, request)
	if called {
		t.Fatal("read-only mode must not authenticate a root request")
	}
	if !strings.Contains(response.Body.String(), "Read-only-Modus") {
		t.Fatalf("read-only status missing from response: %.200s", response.Body.String())
	}
}
