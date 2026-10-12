package moduleadmin

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"os/user"
	"sort"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/msteinert/pam/v2"

	"swat/internal/audit"
	"swat/internal/modules"
)

const SocketPath = "/run/swat-privileged/modules.sock"

const (
	maxRequestBytes = 16 * 1024
	installTimeout  = 15 * time.Minute
)

const (
	operationInstallModules    = "install-modules"
	operationAuthenticateLogin = "authenticate-login"
	operationAuthenticateSudo  = "authenticate-sudo"
)

func Available() bool {
	info, err := os.Stat(SocketPath)
	return err == nil && info.Mode()&os.ModeSocket != 0
}

type Request struct {
	Operation string   `json:"operation"`
	Modules   []string `json:"modules"`
	Username  string   `json:"username"`
	Password  string   `json:"password"`
}

type Response struct {
	OK           bool     `json:"ok"`
	Installed    []string `json:"installed,omitempty"`
	PendingUnits []string `json:"pending_units,omitempty"`
	Message      string   `json:"message,omitempty"`
	Error        string   `json:"error,omitempty"`
}

type CommandRunner func(context.Context, string, ...string) ([]byte, error)
type Authorizer func(username, password string) error

type Installer struct {
	Run       CommandRunner
	Authorize Authorizer
	Login     Authorizer
	Audit     func(audit.Entry) error
	mu        sync.Mutex
}

func PAMAuthorizer(service string) Authorizer {
	if service == "" {
		service = "sudo"
	}
	return func(username, password string) error {
		if username != "root" && !isWheelMember(username) {
			return errors.New("Benutzer ist kein Mitglied der Administratorgruppe wheel")
		}
		return pamCheck(service, username, password)
	}
}

func PAMLoginAuthorizer(service string) Authorizer {
	if service == "" {
		service = "login"
	}
	return func(username, password string) error {
		return pamCheck(service, username, password)
	}
}

func pamCheck(service, username, password string) error {
	transaction, err := pam.StartFunc(service, username, func(style pam.Style, _ string) (string, error) {
		switch style {
		case pam.PromptEchoOff, pam.PromptEchoOn:
			return password, nil
		default:
			return "", errors.New("unerwartete PAM-Anfrage")
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

func isWheelMember(username string) bool {
	account, err := user.Lookup(username)
	if err != nil {
		return false
	}
	wheel, err := user.LookupGroup("wheel")
	if err != nil {
		return false
	}
	groups, err := account.GroupIds()
	if err != nil {
		return false
	}
	for _, groupID := range groups {
		if groupID == wheel.Gid {
			return true
		}
	}
	return false
}

func SystemRunner(ctx context.Context, name string, args ...string) ([]byte, error) {
	command := exec.CommandContext(ctx, name, args...)
	command.Env = append(command.Environ(), "LC_ALL=C", "LANG=C")
	return command.CombinedOutput()
}

func (installer *Installer) Install(ctx context.Context, ids []string) (Response, error) {
	installer.mu.Lock()
	defer installer.mu.Unlock()
	if installer.Run == nil {
		installer.Run = SystemRunner
	}
	normalized, err := modules.NormalizeSelection(ids)
	if err != nil {
		return Response{}, err
	}
	packages, err := modules.PackagePlan(normalized)
	if err != nil {
		return Response{}, err
	}
	if len(packages) == 0 {
		return Response{OK: true, Message: "Keine zusätzlichen Pakete erforderlich."}, nil
	}
	missing := make([]string, 0, len(packages))
	for _, packageName := range packages {
		output, queryErr := installer.Run(ctx, "pacman", "-Q", "--", packageName)
		if queryErr != nil || !strings.HasPrefix(string(output), packageName+" ") {
			missing = append(missing, packageName)
		}
	}
	if len(missing) > 0 {
		args := append([]string{"-S", "--needed", "--noconfirm", "--"}, missing...)
		output, installErr := installer.Run(ctx, "pacman", args...)
		if installErr != nil {
			return Response{}, fmt.Errorf("pacman konnte die ausgewählten Abhängigkeiten nicht installieren: %s", summarize(output, installErr))
		}
	}
	var pendingUnits []string
	for _, id := range normalized {
		definition, _ := modules.DefinitionFor(id)
		for _, service := range definition.Services {
			if service.ConfigurationRequired {
				pendingUnits = append(pendingUnits, service.Unit)
			}
		}
	}
	sort.Strings(pendingUnits)
	return Response{
		OK: true, Installed: missing, PendingUnits: pendingUnits,
		Message: "Pakete installiert. Dienste mit erforderlicher Grundkonfiguration bleiben bis zur validierten Einrichtung gestoppt.",
	}, nil
}

func summarize(output []byte, err error) string {
	text := strings.TrimSpace(string(output))
	if len(text) > 1800 {
		text = text[len(text)-1800:]
	}
	if text == "" {
		return err.Error()
	}
	return text
}

func (installer *Installer) Serve(listener net.Listener, allowedUID uint32) error {
	for {
		connection, err := listener.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return nil
			}
			return err
		}
		go func() {
			defer connection.Close()
			_ = installer.serveConnection(connection, allowedUID)
		}()
	}
}

func (installer *Installer) serveConnection(connection net.Conn, allowedUID uint32) error {
	unix, ok := connection.(*net.UnixConn)
	if !ok {
		return errors.New("Unix-Socket erforderlich")
	}
	uid, err := peerUID(unix)
	if err != nil || uid != allowedUID {
		return errors.New("nicht autorisierter lokaler Aufrufer")
	}
	_ = connection.SetDeadline(time.Now().Add(installTimeout + time.Minute))
	decoder := json.NewDecoder(io.LimitReader(connection, maxRequestBytes))
	decoder.DisallowUnknownFields()
	var request Request
	if err := decoder.Decode(&request); err != nil {
		return writeResponse(connection, Response{Error: "Ungültige Anfrage."})
	}
	if request.Operation == operationAuthenticateLogin {
		return installer.serveAuthentication(connection, request.Username, request.Password, installer.Login, "auth/login")
	}
	if request.Operation == operationAuthenticateSudo {
		return installer.serveAuthentication(connection, request.Username, request.Password, installer.Authorize, "auth/sudo")
	}
	if request.Operation != operationInstallModules {
		return writeResponse(connection, Response{Error: "Nicht erlaubte privilegierte Operation."})
	}
	if request.Username == "" || request.Password == "" || installer.Authorize == nil || installer.Authorize(request.Username, request.Password) != nil {
		request.Password = ""
		return writeResponse(connection, Response{Error: "PAM-Authentifizierung für die Modulinstallation fehlgeschlagen."})
	}
	request.Password = ""
	if len(request.Modules) == 0 || len(request.Modules) > len(modules.Catalog()) {
		return writeResponse(connection, Response{Error: "Ungültige Modulauswahl."})
	}
	normalized, err := modules.NormalizeSelection(request.Modules)
	if err != nil {
		return writeResponse(connection, Response{Error: err.Error()})
	}
	if installer.Audit == nil {
		return writeResponse(connection, Response{Error: "Privilegiertes Audit ist nicht konfiguriert."})
	}
	target := strings.Join(normalized, ",")
	if err := installer.Audit(audit.Entry{User: request.Username, Action: "modules/helper-install-start", Target: target, Result: "started"}); err != nil {
		return writeResponse(connection, Response{Error: "Audit-Log nicht schreibbar; Paketinstallation abgebrochen."})
	}
	ctx, cancel := context.WithTimeout(context.Background(), installTimeout)
	defer cancel()
	result, err := installer.Install(ctx, normalized)
	if err != nil {
		_ = installer.Audit(audit.Entry{User: request.Username, Action: "modules/helper-install", Target: target, Result: "fehler", Detail: err.Error()})
		return writeResponse(connection, Response{Error: err.Error()})
	}
	if err := installer.Audit(audit.Entry{User: request.Username, Action: "modules/helper-install", Target: target, Result: "ok", Detail: strings.Join(result.Installed, ",")}); err != nil {
		return writeResponse(connection, Response{Error: "Pakettransaktion beendet, aber das Abschluss-Audit konnte nicht geschrieben werden."})
	}
	return writeResponse(connection, result)
}

func (installer *Installer) serveAuthentication(connection net.Conn, username, password string, authorize Authorizer, action string) error {
	if username == "" || password == "" || authorize == nil {
		return writeResponse(connection, Response{Error: "Authentifizierung fehlgeschlagen."})
	}
	if installer.Audit == nil {
		return writeResponse(connection, Response{Error: "Privilegiertes Audit ist nicht konfiguriert."})
	}
	if err := authorize(username, password); err != nil {
		_ = installer.Audit(audit.Entry{User: username, Action: action, Target: "swat", Result: "fehler"})
		return writeResponse(connection, Response{Error: "Authentifizierung fehlgeschlagen."})
	}
	if err := installer.Audit(audit.Entry{User: username, Action: action, Target: "swat", Result: "ok"}); err != nil {
		return writeResponse(connection, Response{Error: "Audit-Log nicht schreibbar; Authentifizierung abgebrochen."})
	}
	return writeResponse(connection, Response{OK: true})
}

func writeResponse(writer io.Writer, response Response) error {
	return json.NewEncoder(writer).Encode(response)
}

func peerUID(connection *net.UnixConn) (uint32, error) {
	raw, err := connection.SyscallConn()
	if err != nil {
		return 0, err
	}
	var credentials *syscall.Ucred
	var controlErr error
	if err := raw.Control(func(fd uintptr) {
		credentials, controlErr = syscall.GetsockoptUcred(int(fd), syscall.SOL_SOCKET, syscall.SO_PEERCRED)
	}); err != nil {
		return 0, err
	}
	if controlErr != nil {
		return 0, controlErr
	}
	return credentials.Uid, nil
}

func Install(ctx context.Context, ids []string, username, password string) (Response, error) {
	return roundTrip(ctx, Request{Operation: operationInstallModules, Modules: ids, Username: username, Password: password})
}

func AuthenticateLogin(ctx context.Context, username, password string) error {
	return authenticate(ctx, operationAuthenticateLogin, username, password)
}

func AuthenticateSudo(ctx context.Context, username, password string) error {
	return authenticate(ctx, operationAuthenticateSudo, username, password)
}

func authenticate(ctx context.Context, operation, username, password string) error {
	_, err := roundTrip(ctx, Request{Operation: operation, Username: username, Password: password})
	return err
}

func roundTrip(ctx context.Context, request Request) (Response, error) {
	dialer := net.Dialer{Timeout: 5 * time.Second}
	connection, err := dialer.DialContext(ctx, "unix", SocketPath)
	if err != nil {
		return Response{}, fmt.Errorf("SWAT-Modul-Helper ist nicht erreichbar: %w", err)
	}
	defer connection.Close()
	_ = connection.SetDeadline(time.Now().Add(installTimeout + time.Minute))
	if err := json.NewEncoder(connection).Encode(request); err != nil {
		return Response{}, err
	}
	var response Response
	decoder := json.NewDecoder(io.LimitReader(connection, maxRequestBytes))
	if err := decoder.Decode(&response); err != nil {
		return Response{}, err
	}
	if !response.OK {
		if response.Error == "" {
			response.Error = "Helfer-Anfrage fehlgeschlagen."
		}
		return response, errors.New(response.Error)
	}
	return response, nil
}
