package main

import (
	"context"
	"crypto/subtle"
	"fmt"
	"net/http"
	"regexp"

	"swat/internal/collect"
	"swat/internal/moduleadmin"
)

var accountNamePattern = regexp.MustCompile(`^[a-z_][a-z0-9_-]*$`)

func handleCreateUser(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Methode nicht erlaubt", http.StatusMethodNotAllowed)
		return
	}
	session, err := accountActionSession(r)
	if err != nil {
		renderAccountAction(w, r, err.Error(), "")
		return
	}
	username := r.FormValue("username")
	if !accountNamePattern.MatchString(username) {
		renderAccountAction(w, r, "Der Benutzername ist ungültig.", "")
		return
	}
	if err := performAdminAction(session, "user-create", username, allowedShell(r.FormValue("shell")), r.FormValue("fullname"), r.FormValue("home")); err != nil {
		renderAccountAction(w, r, "Benutzer konnte nicht angelegt werden: "+err.Error(), "")
		return
	}
	renderAccountAction(w, r, "", "Benutzer "+username+" wurde angelegt.")
}

func handleCreateGroup(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Methode nicht erlaubt", http.StatusMethodNotAllowed)
		return
	}
	session, err := accountActionSession(r)
	if err != nil {
		renderAccountAction(w, r, err.Error(), "")
		return
	}
	group := r.FormValue("groupname")
	if !accountNamePattern.MatchString(group) {
		renderAccountAction(w, r, "Der Gruppenname ist ungültig.", "")
		return
	}
	if err := performAdminAction(session, "group-create", group, r.FormValue("gid"), "", ""); err != nil {
		renderAccountAction(w, r, "Gruppe konnte nicht angelegt werden: "+err.Error(), "")
		return
	}
	renderAccountAction(w, r, "", "Gruppe "+group+" wurde angelegt.")
}

func handleExpirePassword(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Methode nicht erlaubt", http.StatusMethodNotAllowed)
		return
	}
	session, err := accountActionSession(r)
	if err != nil {
		renderAccountAction(w, r, err.Error(), "")
		return
	}
	username := r.FormValue("username")
	if !manageableUser(r, username, session.Username) {
		renderAccountAction(w, r, "Systemkonten oder der aktuell angemeldete Benutzer können hier nicht geändert werden.", "")
		return
	}
	if err := performAdminAction(session, "user-expire-password", username, "", "", ""); err != nil {
		renderAccountAction(w, r, "Passwortänderung konnte nicht erzwungen werden: "+err.Error(), "")
		return
	}
	renderAccountAction(w, r, "", "Beim nächsten Login muss "+username+" das Passwort ändern.")
}

func handleDeleteUser(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Methode nicht erlaubt", http.StatusMethodNotAllowed)
		return
	}
	session, err := accountActionSession(r)
	if err != nil {
		renderAccountAction(w, r, err.Error(), "")
		return
	}
	username := r.FormValue("username")
	if !manageableUser(r, username, session.Username) {
		renderAccountAction(w, r, "Systemkonten oder der aktuell angemeldete Benutzer können nicht gelöscht werden.", "")
		return
	}
	if err := performAdminAction(session, "user-delete", username, "", "", ""); err != nil {
		renderAccountAction(w, r, "Benutzer konnte nicht gelöscht werden: "+err.Error(), "")
		return
	}
	renderAccountAction(w, r, "", "Benutzer "+username+" wurde gelöscht. Das Home-Verzeichnis bleibt erhalten.")
}

func handleChangeUserGroup(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Methode nicht erlaubt", http.StatusMethodNotAllowed)
		return
	}
	session, err := accountActionSession(r)
	if err != nil {
		renderAccountAction(w, r, err.Error(), "")
		return
	}
	username := r.FormValue("username")
	group := r.FormValue("groupname")
	if !manageableGroupUser(username) {
		renderAccountAction(w, r, "Nur echte Benutzer können Gruppen zugewiesen werden.", "")
		return
	}
	if !manageableGroup(group) {
		renderAccountAction(w, r, "Die Gruppe ist ungültig oder eine Systemgruppe.", "")
		return
	}
	action := r.FormValue("action")
	var success string
	switch action {
	case "add":
		success = "Benutzer " + username + " wurde der Gruppe " + group + " hinzugefügt. Eine neue Anmeldung ist erforderlich, damit die Gruppenmitgliedschaft aktiv wird."
	case "remove":
		success = "Benutzer " + username + " wurde aus der Gruppe " + group + " entfernt. Eine neue Anmeldung ist erforderlich, damit die Gruppenmitgliedschaft aktualisiert wird."
	default:
		renderAccountAction(w, r, "Ungültige Gruppenaktion.", "")
		return
	}
	if err := performAdminAction(session, "group-membership", username, group, action, ""); err != nil {
		renderAccountAction(w, r, "Gruppenzugehörigkeit konnte nicht geändert werden: "+err.Error(), "")
		return
	}
	renderAccountAction(w, r, "", success)
}

func accountActionSession(r *http.Request) (authSession, error) {
	if readOnlyMode() {
		return authSession{}, fmt.Errorf("diese Installation läuft ausdrücklich im Read-only-Modus")
	}
	_, session, ok := currentSession(r)
	if !ok || (!session.RootAccess && !session.AdminAccess) {
		return authSession{}, fmt.Errorf("Root-Zugriff erforderlich")
	}
	if subtle.ConstantTimeCompare([]byte(session.CSRFToken), []byte(r.FormValue("csrf"))) != 1 {
		return authSession{}, fmt.Errorf("Ungültige Anfrage")
	}
	return session, nil
}

func allowedShell(shell string) string {
	switch shell {
	case "/bin/zsh", "/usr/bin/fish", "/usr/sbin/nologin":
		return shell
	default:
		return "/bin/bash"
	}
}

func manageableUser(r *http.Request, username, current string) bool {
	if username == "" || username == current || !accountNamePattern.MatchString(username) {
		return false
	}
	for _, user := range collect.Accounts().Users {
		if user.Name == username {
			return !user.System
		}
	}
	return false
}

func manageableGroupUser(username string) bool {
	if username == "" || !accountNamePattern.MatchString(username) {
		return false
	}
	for _, user := range collect.Accounts().Users {
		if user.Name == username {
			return !user.System
		}
	}
	return false
}

func manageableGroup(group string) bool {
	if !accountNamePattern.MatchString(group) {
		return false
	}
	for _, account := range collect.Accounts().Groups {
		if account.Name == group {
			return true
		}
	}
	return false
}

func performAdminAction(session authSession, action, target, value, value2, value3 string) error {
	return moduleadmin.PerformAdminAction(context.Background(), action, target, value, value2, value3, session.Username, session.AdminPassword)
}

func renderAccountAction(w http.ResponseWriter, r *http.Request, actionError, actionSuccess string) {
	render(w, r, "users", "users.html", map[string]any{
		"System":               collect.ReadSystemInfo(),
		"Accounts":             collect.Accounts(),
		"AccountActionError":   actionError,
		"AccountActionSuccess": actionSuccess,
	})
}
