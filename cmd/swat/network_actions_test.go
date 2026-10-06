package main

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

func TestNetworkPageShowsForwardingControls(t *testing.T) {
	t.Setenv("SWAT_STATE_DIR", t.TempDir())
	response := httptest.NewRecorder()
	handleNetwork(response, adminRequest(t, http.MethodGet, "/network", nil))
	body := response.Body.String()
	for _, want := range []string{"IP-Forwarding", `name="family" value="ipv4"`, `name="family" value="ipv6"`, "/admin/network/forwarding", "Interfaces und Bridges", `name="addresses"`, `name="dhcp"`, `name="ports"`} {
		if !strings.Contains(body, want) {
			t.Errorf("network page missing %q", want)
		}
	}
}

func TestParseNetworkdNetworkFile(t *testing.T) {
	for _, test := range []struct {
		output string
		want   string
		ok     bool
	}{
		{"● 2: enp1s0\n Network File: /etc/systemd/network/90-swat-port.network\n", "/etc/systemd/network/90-swat-port.network", true},
		{"Network File: n/a\n", "n/a", true},
		{"● 2: enp1s0\n", "", false},
	} {
		got, ok := ParseNetworkFile(test.output)
		if got != test.want || ok != test.ok {
			t.Errorf("parseNetworkFile(%q) = %q, %t; want %q, %t", test.output, got, ok, test.want, test.ok)
		}
	}
}

func TestBridgeActionRequiresRoot(t *testing.T) {
	t.Setenv("SWAT_STATE_DIR", t.TempDir())
	sessionID, _, err := startSession("viewer")
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodPost, "/admin/network/bridge", nil)
	request.Form = url.Values{"action": {"apply"}}
	request.AddCookie(&http.Cookie{Name: sessionCookie, Value: sessionID})
	response := httptest.NewRecorder()
	handleNetworkBridgeAction(response, request)
	if !strings.Contains(response.Body.String(), "Root-Zugriff erforderlich") {
		t.Fatalf("non-root bridge action was not rejected: %.300s", response.Body.String())
	}
}

func TestForwardingRejectsInvalidFamilyAndNonRoot(t *testing.T) {
	t.Setenv("SWAT_STATE_DIR", t.TempDir())
	form := url.Values{"family": {"ipv5"}, "enable": {"1"}}
	response := httptest.NewRecorder()
	handleNetworkForwarding(response, adminRequest(t, http.MethodPost, "/admin/network/forwarding", form))
	if !strings.Contains(response.Body.String(), "Ungültiges Protokoll") {
		t.Fatalf("invalid family accepted: %.300s", response.Body.String())
	}

	sessionID, _, _ := startSession("viewer")
	request := httptest.NewRequest(http.MethodPost, "/admin/network/forwarding", nil)
	request.Form = url.Values{"family": {"ipv4"}, "enable": {"1"}}
	request.AddCookie(&http.Cookie{Name: sessionCookie, Value: sessionID})
	response = httptest.NewRecorder()
	handleNetworkForwarding(response, request)
	if !strings.Contains(response.Body.String(), "Root-Zugriff erforderlich") {
		t.Fatalf("non-root change not rejected: %.300s", response.Body.String())
	}
}
