package main

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

func adminRequest(t *testing.T, method, target string, form url.Values) *http.Request {
	t.Helper()
	sessionID, session, err := startSession("tester")
	if err != nil {
		t.Fatal(err)
	}
	session.AdminAccess, session.RootAccess = true, true
	sessions.Lock()
	sessions.items[sessionID] = session
	sessions.Unlock()
	if form == nil {
		form = url.Values{}
	}
	form.Set("csrf", session.CSRFToken)
	request := httptest.NewRequest(method, target, nil)
	request.Form = form
	request.AddCookie(&http.Cookie{Name: sessionCookie, Value: sessionID})
	return request
}

func TestZonesEditAndRender(t *testing.T) {
	t.Setenv("SWAT_STATE_DIR", t.TempDir())
	for _, zone := range []url.Values{
		{"action": {"save-zone"}, "name": {"lan"}, "input": {"restricted"}, "interfaces": {"br0"}, "services": {"ssh"}},
		{"action": {"save-zone"}, "name": {"wan"}, "input": {"restricted"}, "interfaces": {"eth0"}},
	} {
		response := httptest.NewRecorder()
		handleZonesAction(response, adminRequest(t, http.MethodPost, "/admin/zones/action", zone))
		if !strings.Contains(response.Body.String(), "gespeichert") {
			t.Fatalf("zone not saved: %s", response.Body.String())
		}
	}
	policy := url.Values{"action": {"save-policy"}, "from": {"lan"}, "to": {"wan"}, "mode": {"allow"}, "masquerade": {"1"}}
	response := httptest.NewRecorder()
	handleZonesAction(response, adminRequest(t, http.MethodPost, "/admin/zones/action", policy))
	if !strings.Contains(response.Body.String(), "Richtlinie lan → wan gespeichert") {
		t.Fatalf("policy not saved: %s", response.Body.String())
	}

	response = httptest.NewRecorder()
	handleFirewall(response, adminRequest(t, http.MethodGet, "/firewall", nil))
	body := response.Body.String()
	for _, want := range []string{"erlaubt", "gesperrt", "masquerade", "jump input_lan"} {
		if !strings.Contains(body, want) {
			t.Errorf("page missing %q", want)
		}
	}
}

func TestZonesRejectsInvalidAndUnauthorized(t *testing.T) {
	t.Setenv("SWAT_STATE_DIR", t.TempDir())
	bad := url.Values{"action": {"save-zone"}, "name": {`x"; drop`}, "input": {"restricted"}}
	response := httptest.NewRecorder()
	handleZonesAction(response, adminRequest(t, http.MethodPost, "/admin/zones/action", bad))
	if !strings.Contains(response.Body.String(), "ungültiger Zonenname") {
		t.Fatalf("invalid zone accepted: %s", response.Body.String())
	}

	sessionID, _, _ := startSession("viewer")
	request := httptest.NewRequest(http.MethodPost, "/admin/zones/action", nil)
	request.Form = url.Values{"action": {"apply"}}
	request.AddCookie(&http.Cookie{Name: sessionCookie, Value: sessionID})
	response = httptest.NewRecorder()
	handleZonesAction(response, request)
	if !strings.Contains(response.Body.String(), "Root-Zugriff erforderlich") {
		t.Fatalf("non-admin action not rejected: %s", response.Body.String())
	}
}
