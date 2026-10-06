package main

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestApplyStaysEnabledWithoutZones(t *testing.T) {
	t.Setenv("SWAT_STATE_DIR", t.TempDir())
	response := httptest.NewRecorder()
	handleFirewall(response, adminRequest(t, http.MethodGet, "/firewall", nil))
	body := response.Body.String()
	start := strings.Index(body, `value="apply"`)
	if start < 0 {
		t.Fatal("apply button missing")
	}
	button := body[start : start+strings.Index(body[start:], "</button>")]
	if strings.Contains(button, "disabled") {
		t.Errorf("apply must stay available so deleting the last zone can be applied: %s", button)
	}
}
