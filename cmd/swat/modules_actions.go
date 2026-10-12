package main

import (
	"context"
	"crypto/subtle"
	"fmt"
	"net/http"
	"os"
	"sort"
	"strings"

	"swat/internal/audit"
	"swat/internal/moduleadmin"
	"swat/internal/modules"
	"swat/internal/zones"
)

type modulesPageData struct {
	Statuses       []modules.Status
	Error          string
	Success        string
	RequiredModule string
	HelperEnabled  bool
}

var inspectModuleCatalog = modules.Inspect
var installModulePackages = moduleadmin.Install

func moduleSelectionPath() string {
	return modules.StatePath(zones.StateDir())
}

func moduleStatuses() ([]modules.Status, modules.Selection, error) {
	return inspectModuleCatalog(moduleSelectionPath())
}

func modulePageReady(id string) bool {
	statuses, _, err := moduleStatuses()
	return err == nil && modules.Ready(statuses, id)
}

func modulePageFlags() map[string]bool {
	statuses, _, err := moduleStatuses()
	flags := make(map[string]bool)
	if err != nil {
		return flags
	}
	for _, status := range statuses {
		if status.PagePath != "" {
			flags[status.ID] = status.Selected && status.Ready
		}
	}
	return flags
}

func handleModules(w http.ResponseWriter, r *http.Request) {
	page := loadModulesPage(r.URL.Query().Get("required"), "", "")
	render(w, r, "modules", "modules.html", modulesPageMap(page))
}

func handleModulesAction(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Methode nicht erlaubt", http.StatusMethodNotAllowed)
		return
	}
	_, session, ok := currentSession(r)
	if !ok {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}
	if err := r.ParseForm(); err != nil {
		renderModules(w, r, "Ungültige Anfrage.", "")
		return
	}
	if subtle.ConstantTimeCompare([]byte(session.CSRFToken), []byte(r.FormValue("csrf"))) != 1 {
		renderModules(w, r, "Ungültige Anfrage.", "")
		return
	}
	password := r.FormValue("sudo_password")
	if sudoAuthenticate(session.Username, password) != nil {
		renderModules(w, r, "Sudo-Authentifizierung fehlgeschlagen. Es wurden keine Moduländerungen ausgeführt.", "")
		return
	}
	selected, err := modules.NormalizeSelection(r.Form["modules"])
	if err != nil {
		renderModules(w, r, err.Error(), "")
		return
	}
	action := r.FormValue("action")
	if action != "save-selection" && action != "install" {
		renderModules(w, r, "Ungültige Modulaktion.", "")
		return
	}
	if action == "install" && r.FormValue("confirm_install") != "1" {
		renderModules(w, r, "Bitte bestätige zuerst die angezeigten Pakete, deren Abhängigkeiten und Paket-Skripte.", "")
		return
	}
	if err := audit.Log(zones.StateDir(), audit.Entry{User: session.Username, Action: "modules/" + action + "/start", Target: strings.Join(selected, ","), Result: "started"}); err != nil {
		renderModules(w, r, "Audit-Log nicht schreibbar; Änderung wurde nicht ausgeführt.", "")
		return
	}
	if _, err := modules.Save(moduleSelectionPath(), selected); err != nil {
		_ = audit.Log(zones.StateDir(), audit.Entry{User: session.Username, Action: "modules/" + action, Target: strings.Join(selected, ","), Result: "fehler", Detail: err.Error()})
		renderModules(w, r, "Modulauswahl konnte nicht gespeichert werden: "+err.Error(), "")
		return
	}
	if action == "save-selection" {
		_ = audit.Log(zones.StateDir(), audit.Entry{User: session.Username, Action: "modules/save-selection", Target: strings.Join(selected, ","), Result: "ok"})
		renderModules(w, r, "", "Modulauswahl gespeichert. Es wurden keine Pakete oder Dienste verändert.")
		return
	}
	if os.Getenv("SWAT_MODULE_SETUP") != "1" {
		err := fmt.Errorf("Paketinstallation ist in dieser SWAT-Instanz nicht freigeschaltet")
		_ = audit.Log(zones.StateDir(), audit.Entry{User: session.Username, Action: "modules/install", Target: strings.Join(selected, ","), Result: "fehler", Detail: err.Error()})
		renderModules(w, r, err.Error(), "")
		return
	}
	result, err := installModulePackages(context.Background(), selected, session.Username, password)
	if err != nil {
		_ = audit.Log(zones.StateDir(), audit.Entry{User: session.Username, Action: "modules/install", Target: strings.Join(selected, ","), Result: "fehler", Detail: err.Error()})
		renderModules(w, r, "Modulabhängigkeiten konnten nicht installiert werden: "+err.Error(), "")
		return
	}
	message := result.Message
	if len(result.Installed) > 0 {
		message += " Installierte Pakete: " + strings.Join(result.Installed, ", ") + "."
	}
	if len(result.PendingUnits) > 0 {
		message += " Noch gestoppte Units: " + strings.Join(result.PendingUnits, ", ") + "."
	}
	_ = audit.Log(zones.StateDir(), audit.Entry{User: session.Username, Action: "modules/install", Target: strings.Join(selected, ","), Result: "ok", Detail: strings.Join(result.Installed, ",")})
	renderModules(w, r, "", message)
}

func renderModules(w http.ResponseWriter, r *http.Request, actionError, actionSuccess string) {
	page := loadModulesPage(r.URL.Query().Get("required"), actionError, actionSuccess)
	render(w, r, "modules", "modules.html", modulesPageMap(page))
}

func loadModulesPage(required, actionError, actionSuccess string) modulesPageData {
	statuses, _, err := moduleStatuses()
	page := modulesPageData{
		Error: actionError, Success: actionSuccess, RequiredModule: required,
		HelperEnabled: os.Getenv("SWAT_MODULE_SETUP") == "1" && moduleadmin.Available(),
	}
	if err != nil {
		page.Error = "Modulstatus konnte nicht gelesen werden: " + err.Error()
		return page
	}
	page.Statuses = statuses
	sort.Slice(page.Statuses, func(i, j int) bool { return page.Statuses[i].ID < page.Statuses[j].ID })
	return page
}

func modulesPageMap(page modulesPageData) map[string]any {
	return map[string]any{
		"Modules": page.Statuses, "ModuleError": page.Error, "ModuleSuccess": page.Success,
		"RequiredModule": page.RequiredModule, "ModuleHelperEnabled": page.HelperEnabled,
	}
}
