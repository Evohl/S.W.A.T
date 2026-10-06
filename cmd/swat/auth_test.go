package main

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
)

func TestPAMServiceDefaults(t *testing.T) {
	t.Setenv("SWAT_PAM_SERVICE", "")
	if got := pamService("SWAT_PAM_SERVICE", "login"); got != "login" {
		t.Fatalf("default PAM service = %q, want login", got)
	}
	t.Setenv("SWAT_PAM_SERVICE", "custom-login")
	if got := pamService("SWAT_PAM_SERVICE", "login"); got != "custom-login" {
		t.Fatalf("configured PAM service = %q, want custom-login", got)
	}
}

func TestRootAccessRequestRequiresCSRF(t *testing.T) {
	sessionID, _, err := startSession("SWAT_Admin")
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodPost, "/admin/request-root", nil)
	request.AddCookie(&http.Cookie{Name: sessionCookie, Value: sessionID})
	response := httptest.NewRecorder()
	handleRootAccessRequest(response, request)
	if response.Code != http.StatusBadRequest {
		t.Fatalf("missing CSRF token returned status %d, want %d", response.Code, http.StatusBadRequest)
	}
}

func TestRootAccessRequestActivatesRootAccess(t *testing.T) {
	originalPAMAuthenticate := pamAuthenticate
	pamAuthenticate = func(string, string, string) error { return nil }
	defer func() { pamAuthenticate = originalPAMAuthenticate }()

	sessionID, session, err := startSession("SWAT_Admin")
	if err != nil {
		t.Fatal(err)
	}
	form := url.Values{"csrf": {session.CSRFToken}}
	request := httptest.NewRequest(http.MethodPost, "/admin/request-root", nil)
	request.Form = form
	request.AddCookie(&http.Cookie{Name: sessionCookie, Value: sessionID})
	response := httptest.NewRecorder()
	handleRootAccessRequest(response, request)
	if response.Code != http.StatusSeeOther {
		t.Fatalf("valid root request returned status %d, want %d", response.Code, http.StatusSeeOther)
	}
	_, updated, ok := currentSession(request)
	if !ok || !updated.RootRequested {
		t.Fatal("valid root request should become pending")
	}
	if !updated.RootRequested || !updated.RootAccess || !authData(request).RootAccess {
		t.Fatal("valid sudo authentication should activate root access")
	}
}

func TestRootAccessRestrictionClearsPrivilegeState(t *testing.T) {
	sessionID, session, err := startSession("SWAT_Admin")
	if err != nil {
		t.Fatal(err)
	}
	session.RootRequested = true
	session.AdminAccess = true
	session.RootAccess = true
	session.SudoPassword = "secret"
	sessions.Lock()
	sessions.items[sessionID] = session
	sessions.Unlock()
	form := url.Values{"csrf": {session.CSRFToken}}
	request := httptest.NewRequest(http.MethodPost, "/admin/restrict-root", nil)
	request.Form = form
	request.AddCookie(&http.Cookie{Name: sessionCookie, Value: sessionID})
	response := httptest.NewRecorder()
	handleRootAccessRestriction(response, request)
	if response.Code != http.StatusSeeOther {
		t.Fatalf("root restriction returned status %d, want %d", response.Code, http.StatusSeeOther)
	}
	_, updated, ok := currentSession(request)
	if !ok {
		t.Fatal("restricted session should remain logged in")
	}
	if updated.RootRequested || updated.AdminAccess || updated.RootAccess || updated.SudoPassword != "" {
		t.Fatalf("root restriction did not clear privilege state: %+v", updated)
	}
}

func TestRequireLoginRedirectsBrowserRequests(t *testing.T) {
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusNoContent) })
	handler := requireLogin(next)
	request := httptest.NewRequest(http.MethodGet, "/", nil)
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusSeeOther {
		t.Fatalf("unauthenticated page returned status %d, want %d", response.Code, http.StatusSeeOther)
	}
	if location := response.Header().Get("Location"); location != "/login" {
		t.Fatalf("redirect location = %q, want /login", location)
	}
}

func TestRequireLoginReturnsUnauthorizedForAPI(t *testing.T) {
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusNoContent) })
	handler := requireLogin(next)
	request := httptest.NewRequest(http.MethodGet, "/api/units", nil)
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusUnauthorized {
		t.Fatalf("unauthenticated API returned status %d, want %d", response.Code, http.StatusUnauthorized)
	}
}

func TestRequireLoginAllowsLoginAndStaticAssets(t *testing.T) {
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusNoContent) })
	handler := requireLogin(next)
	for _, path := range []string{"/login", "/static/style.css"} {
		request := httptest.NewRequest(http.MethodGet, path, nil)
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, request)
		if response.Code != http.StatusNoContent {
			t.Fatalf("unauthenticated %s returned status %d, want %d", path, response.Code, http.StatusNoContent)
		}
	}
}
