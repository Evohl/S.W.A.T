package main

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

func TestPolicyPortTranslationRoundTrip(t *testing.T) {
	t.Setenv("SWAT_STATE_DIR", t.TempDir())
	post := func(form url.Values) string {
		response := httptest.NewRecorder()
		handleZonesAction(response, adminRequest(t, http.MethodPost, "/admin/zones/action", form))
		return response.Body.String()
	}
	post(url.Values{"action": {"save-zone"}, "name": {"lan"}, "input": {"restricted"}, "interfaces": {"br0"}})
	post(url.Values{"action": {"save-zone"}, "name": {"wan"}, "input": {"restricted"}, "interfaces": {"eth0"}})

	body := post(url.Values{
		"action": {"save-policy"}, "from": {"wan"}, "to": {"lan"}, "mode": {"limited"},
		"services": {"ntp"}, "nat_ntp": {"10123"},
		"custom_port": {"", "tcp/2222"}, "custom_to": {"", "192.168.1.5:22"}, "custom_comment": {"", "SSH nach NAS"},
	})
	if !strings.Contains(body, "Richtlinie wan → lan gespeichert") {
		t.Fatalf("policy not saved: %.400s", body)
	}
	for _, want := range []string{"dnat to :10123", "dnat ip to 192.168.1.5:22", "Port-NAT"} {
		if !strings.Contains(body, want) {
			t.Errorf("page missing %q", want)
		}
	}

	response := httptest.NewRecorder()
	handleFirewall(response, adminRequest(t, http.MethodGet, "/firewall?from=wan&to=lan", nil))
	edit := response.Body.String()
	for _, want := range []string{`name="nat_ntp" value="10123"`, `name="custom_port" value="tcp/2222"`, `name="custom_to" value="192.168.1.5:22"`, `name="custom_comment" value="SSH nach NAS"`} {
		if !strings.Contains(edit, want) {
			t.Errorf("edit form missing %q", want)
		}
	}

	bad := post(url.Values{"action": {"save-policy"}, "from": {"wan"}, "to": {"lan"}, "mode": {"limited"}, "services": {"ntp"}, "nat_ntp": {"host:1"}})
	if !strings.Contains(bad, "ungültiges NAT-Ziel") {
		t.Errorf("invalid target accepted: %.400s", bad)
	}
}
