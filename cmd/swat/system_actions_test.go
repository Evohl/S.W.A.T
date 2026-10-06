package main

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

func TestHostnameValidation(t *testing.T) {
	for _, hostname := range []string{"host-01", "host.example.net", "a", "xn--example-ova"} {
		if err := validateHostname(hostname); err != nil {
			t.Errorf("valid hostname %q rejected: %v", hostname, err)
		}
	}
	for _, hostname := range []string{"", "-host", "host-", "bad_name", "host;id", "a..b", strings.Repeat("a", 64)} {
		if err := validateHostname(hostname); err == nil {
			t.Errorf("invalid hostname %q accepted", hostname)
		}
	}
}

func TestSystemSettingCommandAllowlist(t *testing.T) {
	state := systemConfigView{
		HostnameReady: true,
		LocaleReady:   true,
		TimezoneReady: true,
		Locales:       []localeOption{{Name: "de_DE.utf8"}, {Name: "en_US.utf8"}},
		Timezones:     []string{"Europe/Berlin", "UTC"},
	}
	cases := []struct {
		action  string
		value   string
		command []string
	}{
		{"hostname", "srv-01.home", []string{"hostnamectl", "set-hostname", "--static", "srv-01.home"}},
		{"locale", "de_DE.UTF-8", []string{"localectl", "set-locale", "LANG=de_DE.UTF-8"}},
		{"timezone", "Europe/Berlin", []string{"timedatectl", "set-timezone", "Europe/Berlin"}},
	}
	for _, test := range cases {
		got, _, err := systemSettingCommand(test.action, test.value, state)
		if err != nil {
			t.Errorf("%s rejected: %v", test.action, err)
			continue
		}
		if strings.Join(got, "\x00") != strings.Join(test.command, "\x00") {
			t.Errorf("%s command = %q, want %q", test.action, got, test.command)
		}
	}
	for _, test := range []struct{ action, value string }{
		{"hostname", "host;touch /tmp/pwn"},
		{"locale", "../../locale"},
		{"timezone", "../../etc"},
		{"unknown", "value"},
	} {
		if _, _, err := systemSettingCommand(test.action, test.value, state); err == nil {
			t.Errorf("unsafe system setting accepted: %s=%q", test.action, test.value)
		}
	}
}

func TestLocaleOptionsCompareUTF8Aliases(t *testing.T) {
	if !localeEquivalent("de_DE.UTF-8", "de_DE.utf8") || !validateLocale("de_DE.UTF-8", []localeOption{{Name: "de_DE.utf8"}}) {
		t.Fatal("equivalent UTF-8 locale aliases should be accepted")
	}
	if validateLocale("de_DE.UTF-8;id", []localeOption{{Name: "de_DE.utf8"}}) {
		t.Fatal("unlisted locale must be rejected")
	}
}

func TestSystemSettingRequiresRoot(t *testing.T) {
	t.Setenv("SWAT_STATE_DIR", t.TempDir())
	sessionID, _, err := startSession("viewer")
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodPost, "/admin/system/setting", nil)
	request.Form = url.Values{"action": {"hostname"}, "value": {"server01"}}
	request.AddCookie(&http.Cookie{Name: sessionCookie, Value: sessionID})
	response := httptest.NewRecorder()
	handleSystemSetting(response, request)
	if !strings.Contains(response.Body.String(), "Root-Zugriff erforderlich") {
		t.Fatalf("non-root system change was not rejected: %.300s", response.Body.String())
	}
}

func TestSystemPageRendersSettingsAndKeepsFormInvalidSafe(t *testing.T) {
	t.Setenv("SWAT_STATE_DIR", t.TempDir())
	response := httptest.NewRecorder()
	handleSystem(response, adminRequest(t, http.MethodGet, "/system", nil))
	if response.Code != http.StatusOK || !strings.Contains(response.Body.String(), "Hostname, Sprache und Zeitzone") {
		t.Fatalf("system settings did not render: status %d, %.300s", response.Code, response.Body.String())
	}

	form := url.Values{"action": {"hostname"}, "value": {"invalid;command"}}
	response = httptest.NewRecorder()
	handleSystemSetting(response, adminRequest(t, http.MethodPost, "/admin/system/setting", form))
	if !strings.Contains(response.Body.String(), "ungültiges DNS-Label") {
		t.Fatalf("invalid hostname was not rejected: %.300s", response.Body.String())
	}
}
