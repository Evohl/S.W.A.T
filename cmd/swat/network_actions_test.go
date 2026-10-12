package main

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"swat/internal/collect"
	"swat/internal/netcfg"
)

func TestNetworkPageShowsForwardingControls(t *testing.T) {
	t.Setenv("SWAT_STATE_DIR", t.TempDir())
	response := httptest.NewRecorder()
	handleNetwork(response, adminRequest(t, http.MethodGet, "/network", nil))
	body := response.Body.String()
	for _, want := range []string{"IP-Forwarding", `name="family" value="ipv4"`, `name="family" value="ipv6"`, "/admin/network/forwarding", "Netzwerkadapter", "Permanente MAC", "Hardwarebezeichnung", "Interfaces und Bridges", `name="addresses"`, `name="dhcp"`, `name="ports"`} {
		if !strings.Contains(body, want) {
			t.Errorf("network page missing %q", want)
		}
	}
}

func TestUpdateInterfaceNameBindingsRequiresKnownMACsAndUniqueSafeNames(t *testing.T) {
	interfaces := []collect.Interface{{Name: "enp1s0", PermanentAddress: "02:00:00:00:00:01"}}
	updated, err := updateInterfaceNameBindings(interfaces, []string{"02:00:00:00:00:01"}, []string{"wan0"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(updated) != 1 || updated[0].Name != "wan0" {
		t.Fatalf("updated bindings = %#v", updated)
	}
	if _, err := updateInterfaceNameBindings(interfaces, []string{"02:00:00:00:00:99"}, []string{"wan0"}, nil); err == nil {
		t.Fatal("unknown MAC was accepted")
	}
	if _, err := updateInterfaceNameBindings(interfaces, []string{"02:00:00:00:00:01"}, []string{"eth0"}, nil); err == nil {
		t.Fatal("kernel-colliding name was accepted")
	}
	if _, err := updateInterfaceNameBindings(
		append(interfaces, collect.Interface{Name: "br-lan"}),
		[]string{"02:00:00:00:00:01"}, []string{"br-lan"}, nil,
	); err == nil {
		t.Fatal("name colliding with a virtual interface was accepted")
	}
}

func TestNetworkInterfaceNameActionRequiresAdminAndCSRF(t *testing.T) {
	t.Setenv("SWAT_STATE_DIR", t.TempDir())
	t.Setenv("SWAT_READ_ONLY", "0")
	sessionID, _, err := startSession("viewer")
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodPost, "/admin/network/interface-names", strings.NewReader(""))
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	request.AddCookie(&http.Cookie{Name: sessionCookie, Value: sessionID})
	response := httptest.NewRecorder()
	handleNetworkInterfaceNames(response, request)
	if !strings.Contains(response.Body.String(), "Root-Zugriff erforderlich") {
		t.Fatalf("non-admin request was not rejected: %.300s", response.Body.String())
	}

	adminRequest := adminRequest(t, http.MethodPost, "/admin/network/interface-names", url.Values{})
	adminRequest.Form.Set("csrf", "invalid")
	response = httptest.NewRecorder()
	handleNetworkInterfaceNames(response, adminRequest)
	if !strings.Contains(response.Body.String(), "Ungültige Anfrage") {
		t.Fatalf("invalid CSRF token was not rejected: %.300s", response.Body.String())
	}
}

func TestInterfaceNamesPageShowsDesiredStateEditor(t *testing.T) {
	t.Setenv("SWAT_STATE_DIR", t.TempDir())
	response := httptest.NewRecorder()
	handleNetwork(response, adminRequest(t, http.MethodGet, "/network", nil))
	body := response.Body.String()
	for _, want := range []string{"Stabile Netzwerknamen", "/admin/network/interface-names", "Permanente MAC", "Vorschau, noch nicht angewendet"} {
		if !strings.Contains(body, want) {
			t.Errorf("network page missing %q", want)
		}
	}
}

func TestSavedInterfaceNameBindingsRetainDisconnectedAdapters(t *testing.T) {
	updated, err := updateInterfaceNameBindings(
		[]collect.Interface{{Name: "enp1s0", PermanentAddress: "02:00:00:00:00:01"}},
		[]string{"02:00:00:00:00:01"}, []string{"wan0"},
		[]netcfg.InterfaceNameBinding{{PermanentMAC: "02:00:00:00:00:02", Name: "lan0"}},
	)
	if err != nil {
		t.Fatal(err)
	}
	if len(updated) != 2 {
		t.Fatalf("updated bindings = %#v, want connected and disconnected adapters retained", updated)
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
