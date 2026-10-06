package main

import (
	"net/http"
	"regexp"

	"swat/internal/collect"
)

var serviceUnitPattern = regexp.MustCompile(`^[A-Za-z0-9_@%:.,\\-]+\.service$`)

func handleServiceAction(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Methode nicht erlaubt", http.StatusMethodNotAllowed)
		return
	}
	session, err := accountActionSession(r)
	if err != nil {
		renderServiceAction(w, r, r.FormValue("unit"), err.Error(), "")
		return
	}
	unit := r.FormValue("unit")
	if !serviceUnitPattern.MatchString(unit) {
		renderServiceAction(w, r, unit, "Ungültige Service-Unit.", "")
		return
	}
	action := r.FormValue("action")
	if action != "start" && action != "stop" && action != "enable" && action != "disable" {
		renderServiceAction(w, r, unit, "Ungültige Service-Aktion.", "")
		return
	}
	if err := runAsRoot(session.SudoPassword, "systemctl", action, "--", unit); err != nil {
		renderServiceAction(w, r, unit, "Service-Aktion fehlgeschlagen: "+err.Error(), "")
		return
	}
	renderServiceAction(w, r, unit, "", "Service-Aktion ausgeführt.")
}

func renderServiceAction(w http.ResponseWriter, r *http.Request, unit, actionError, actionSuccess string) {
	detail, err := collect.UnitDetailFor(unit)
	if err != nil {
		http.Error(w, "Service-Details konnten nicht geladen werden", http.StatusNotFound)
		return
	}
	render(w, r, "service", "service.html", map[string]any{
		"Detail":               detail,
		"ServiceActionError":   actionError,
		"ServiceActionSuccess": actionSuccess,
	})
}
