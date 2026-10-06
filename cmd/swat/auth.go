package main

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"fmt"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/msteinert/pam/v2"
)

const (
	sessionCookie = "swat_session"
	sessionTTL    = 15 * time.Minute
)

func readOnlyMode() bool { return os.Getenv("SWAT_READ_ONLY") == "1" }

type authSession struct {
	Username      string
	CSRFToken     string
	ExpiresAt     time.Time
	RootRequested bool
	AdminAccess   bool
	RootAccess    bool
	SudoPassword  string
}

type authView struct {
	Authenticated bool
	Username      string
	ExpiresAt     time.Time
	RootRequested bool
	RootAccess    bool
	AdminAccess   bool
	CSRFToken     string
}

var sessions = struct {
	sync.Mutex
	items map[string]authSession
}{items: make(map[string]authSession)}

func pamService(environment, fallback string) string {
	if service := os.Getenv(environment); service != "" {
		return service
	}
	return fallback
}

func authenticatePAM(service, username, password string) error {
	transaction, err := pam.StartFunc(service, username, func(style pam.Style, message string) (string, error) {
		switch style {
		case pam.PromptEchoOff, pam.PromptEchoOn:
			return password, nil
		default:
			return "", fmt.Errorf("unerwartete PAM-Anfrage")
		}
	})
	if err != nil {
		return err
	}
	defer transaction.End()
	if err := transaction.Authenticate(0); err != nil {
		return err
	}
	return transaction.AcctMgmt(0)
}

var pamAuthenticate = authenticatePAM

func randomToken() (string, error) {
	buffer := make([]byte, 32)
	if _, err := rand.Read(buffer); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(buffer), nil
}

func startSession(username string) (string, authSession, error) {
	sessionID, err := randomToken()
	if err != nil {
		return "", authSession{}, err
	}
	csrf, err := randomToken()
	if err != nil {
		return "", authSession{}, err
	}
	session := authSession{Username: username, CSRFToken: csrf, ExpiresAt: time.Now().Add(sessionTTL)}
	sessions.Lock()
	sessions.items[sessionID] = session
	sessions.Unlock()
	return sessionID, session, nil
}

func currentSession(r *http.Request) (string, authSession, bool) {
	cookie, err := r.Cookie(sessionCookie)
	if err != nil {
		return "", authSession{}, false
	}
	sessions.Lock()
	session, ok := sessions.items[cookie.Value]
	if ok && time.Now().After(session.ExpiresAt) {
		delete(sessions.items, cookie.Value)
		ok = false
	}
	sessions.Unlock()
	return cookie.Value, session, ok
}

func setSessionCookie(w http.ResponseWriter, sessionID string) {
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookie,
		Value:    sessionID,
		Path:     "/",
		MaxAge:   int(sessionTTL.Seconds()),
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		Secure:   os.Getenv("SWAT_COOKIE_SECURE") == "1",
	})
}

func clearSessionCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{Name: sessionCookie, Value: "", Path: "/", MaxAge: -1, HttpOnly: true, SameSite: http.SameSiteLaxMode})
}

func authData(r *http.Request) authView {
	_, session, ok := currentSession(r)
	if !ok {
		return authView{}
	}
	return authView{
		Authenticated: true,
		Username:      session.Username,
		ExpiresAt:     session.ExpiresAt,
		RootRequested: session.RootRequested && !readOnlyMode(),
		RootAccess:    !readOnlyMode() && (session.RootAccess || session.AdminAccess),
		AdminAccess:   session.AdminAccess && !readOnlyMode(),
		CSRFToken:     session.CSRFToken,
	}
}

func handleLogin(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		render(w, r, "login", "login.html", map[string]any{"LoginError": ""})
		return
	}
	if r.Method != http.MethodPost {
		http.Error(w, "Methode nicht erlaubt", http.StatusMethodNotAllowed)
		return
	}
	if err := r.ParseForm(); err != nil {
		render(w, r, "login", "login.html", map[string]any{"LoginError": "Ungültige Anmeldedaten."})
		return
	}
	username := r.FormValue("username")
	if username == "" || authenticatePAM(pamService("SWAT_PAM_SERVICE", "login"), username, r.FormValue("password")) != nil {
		render(w, r, "login", "login.html", map[string]any{"LoginError": "Anmeldung über das Systemkonto fehlgeschlagen."})
		return
	}
	sessionID, _, err := startSession(username)
	if err != nil {
		http.Error(w, "Sitzung konnte nicht erstellt werden", http.StatusInternalServerError)
		return
	}
	setSessionCookie(w, sessionID)
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func requireLogin(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/login" || r.URL.Path == "/logout" || strings.HasPrefix(r.URL.Path, "/static/") {
			next.ServeHTTP(w, r)
			return
		}
		if _, _, ok := currentSession(r); ok {
			next.ServeHTTP(w, r)
			return
		}
		if strings.HasPrefix(r.URL.Path, "/api/") {
			http.Error(w, "Anmeldung erforderlich", http.StatusUnauthorized)
			return
		}
		http.Redirect(w, r, "/login", http.StatusSeeOther)
	})
}

func handleLogout(w http.ResponseWriter, r *http.Request) {
	if sessionID, _, ok := currentSession(r); ok {
		sessions.Lock()
		delete(sessions.items, sessionID)
		sessions.Unlock()
	}
	clearSessionCookie(w)
	http.Redirect(w, r, "/login", http.StatusSeeOther)
}

func handleRootAccessRequest(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Methode nicht erlaubt", http.StatusMethodNotAllowed)
		return
	}
	if readOnlyMode() {
		render(w, r, "settings", "settings.html", map[string]any{"RootError": "Diese Installation läuft ausdrücklich im Read-only-Modus."})
		return
	}
	sessionID, session, ok := currentSession(r)
	if !ok {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}
	if subtle.ConstantTimeCompare([]byte(session.CSRFToken), []byte(r.FormValue("csrf"))) != 1 {
		http.Error(w, "Ungültige Anfrage", http.StatusBadRequest)
		return
	}
	if pamAuthenticate(pamService("SWAT_SUDO_PAM_SERVICE", "sudo"), session.Username, r.FormValue("sudo_password")) != nil {
		render(w, r, "settings", "settings.html", map[string]any{"RootError": "Sudo-Authentifizierung fehlgeschlagen. Es wurden keine Root-Rechte aktiviert."})
		return
	}
	session.RootRequested = true
	session.AdminAccess = true
	session.RootAccess = true
	session.SudoPassword = r.FormValue("sudo_password")
	sessions.Lock()
	sessions.items[sessionID] = session
	sessions.Unlock()
	http.Redirect(w, r, "/settings", http.StatusSeeOther)
}

func handleRootAccessRestriction(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Methode nicht erlaubt", http.StatusMethodNotAllowed)
		return
	}
	sessionID, session, ok := currentSession(r)
	if !ok {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}
	if subtle.ConstantTimeCompare([]byte(session.CSRFToken), []byte(r.FormValue("csrf"))) != 1 {
		http.Error(w, "Ungültige Anfrage", http.StatusBadRequest)
		return
	}
	session.RootRequested = false
	session.AdminAccess = false
	session.RootAccess = false
	session.SudoPassword = ""
	sessions.Lock()
	sessions.items[sessionID] = session
	sessions.Unlock()
	http.Redirect(w, r, "/settings", http.StatusSeeOther)
}
