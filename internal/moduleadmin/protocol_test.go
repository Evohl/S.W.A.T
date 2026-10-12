package moduleadmin

import (
	"context"
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"swat/internal/audit"
)

func TestInstallerUsesOnlyAllowlistedPackagePlan(t *testing.T) {
	var calls [][]string
	installer := Installer{Run: func(_ context.Context, command string, args ...string) ([]byte, error) {
		if command != "pacman" {
			t.Fatalf("unexpected command %q", command)
		}
		calls = append(calls, append([]string(nil), args...))
		if len(args) == 3 && args[0] == "-Q" && args[2] == "nginx" {
			return []byte("nginx 1.2-1\n"), nil
		}
		if len(args) == 3 && args[0] == "-Q" && args[2] == "dnsmasq" {
			return []byte("dnsmasq 2.8-1\n"), nil
		}
		return []byte("ok\n"), nil
	}}
	result, err := installer.Install(context.Background(), []string{"nginx", "hotspot"})
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(result.Installed, []string{"hostapd", "iproute2", "iw", "systemd"}) {
		t.Fatalf("installed package plan = %v", result.Installed)
	}
	last := calls[len(calls)-1]
	want := []string{"-S", "--needed", "--noconfirm", "--", "hostapd", "iproute2", "iw", "systemd"}
	if !reflect.DeepEqual(last, want) {
		t.Fatalf("install args = %v, want %v", last, want)
	}
	if len(result.PendingUnits) != 5 {
		t.Fatalf("pending units = %v, want network and config-gated hotspot/nginx services", result.PendingUnits)
	}
}

func TestInstallerRejectsUnknownModulesBeforeRunningCommands(t *testing.T) {
	called := false
	installer := Installer{Run: func(context.Context, string, ...string) ([]byte, error) {
		called = true
		return nil, nil
	}}
	if _, err := installer.Install(context.Background(), []string{"nginx", "../../etc"}); err == nil {
		t.Fatal("unknown module accepted")
	}
	if called {
		t.Fatal("package manager called for invalid module selection")
	}
}

func TestInstallerDoesNotStartServicesBeforeConfiguration(t *testing.T) {
	var commands []string
	installer := Installer{Run: func(_ context.Context, name string, args ...string) ([]byte, error) {
		commands = append(commands, name+" "+strings.Join(args, " "))
		return nil, nil
	}}
	result, err := installer.Install(context.Background(), []string{"mail"})
	if err != nil {
		t.Fatal(err)
	}
	for _, command := range commands {
		if strings.HasPrefix(command, "systemctl ") {
			t.Fatalf("service was activated before validated configuration: %s", command)
		}
	}
	if len(result.PendingUnits) != 6 {
		t.Fatalf("mail pending units = %v", result.PendingUnits)
	}
}

func TestHelperRejectsUnauthorizedPeerUIDBeforePackageCommands(t *testing.T) {
	listener, err := net.Listen("unix", filepath.Join(t.TempDir(), "installer.sock"))
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	client, err := net.Dial("unix", listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	server, err := listener.Accept()
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	called := false
	installer := Installer{Run: func(context.Context, string, ...string) ([]byte, error) {
		called = true
		return nil, nil
	}}
	if err := installer.serveConnection(server, uint32(os.Getuid()+1)); err == nil || !strings.Contains(err.Error(), "nicht autorisierter") {
		t.Fatalf("unauthorized peer result = %v", err)
	}
	if called {
		t.Fatal("pacman ran for unauthorized peer")
	}
}

func TestHelperRequiresIndependentPAMAuthorization(t *testing.T) {
	socketPath := filepath.Join(t.TempDir(), "installer-auth.sock")
	listener, err := net.Listen("unix", socketPath)
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	client, err := net.Dial("unix", socketPath)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	server, err := listener.Accept()
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	packageCommandCalled := false
	authorizerCalled := false
	installer := Installer{
		Authorize: func(username, password string) error {
			authorizerCalled = true
			if username != "admin" || password != "bad-password" {
				t.Fatalf("unexpected helper credentials %q / %q", username, password)
			}
			return os.ErrPermission
		},
		Run: func(context.Context, string, ...string) ([]byte, error) {
			packageCommandCalled = true
			return nil, nil
		},
	}
	done := make(chan error, 1)
	go func() { done <- installer.serveConnection(server, uint32(os.Getuid())) }()
	if err := json.NewEncoder(client).Encode(Request{Operation: "install-modules", Modules: []string{"nginx"}, Username: "admin", Password: "bad-password"}); err != nil {
		t.Fatal(err)
	}
	var response Response
	if err := json.NewDecoder(client).Decode(&response); err != nil {
		t.Fatal(err)
	}
	if response.OK || !strings.Contains(response.Error, "PAM-Authentifizierung") {
		t.Fatalf("helper response = %+v", response)
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if !authorizerCalled || packageCommandCalled {
		t.Fatalf("authorization/package command order invalid: auth=%t pacman=%t", authorizerCalled, packageCommandCalled)
	}
}

func TestHelperRefusesInstallWhenAuditStartCannotBeWritten(t *testing.T) {
	listener, err := net.Listen("unix", filepath.Join(t.TempDir(), "installer-audit.sock"))
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	client, err := net.Dial("unix", listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	server, err := listener.Accept()
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	packageCommandCalled := false
	installer := Installer{
		Authorize: func(string, string) error { return nil },
		Audit:     func(audit.Entry) error { return os.ErrPermission },
		Run: func(context.Context, string, ...string) ([]byte, error) {
			packageCommandCalled = true
			return nil, nil
		},
	}
	done := make(chan error, 1)
	go func() { done <- installer.serveConnection(server, uint32(os.Getuid())) }()
	if err := json.NewEncoder(client).Encode(Request{Operation: "install-modules", Modules: []string{"nginx"}, Username: "admin", Password: "validated"}); err != nil {
		t.Fatal(err)
	}
	var response Response
	if err := json.NewDecoder(client).Decode(&response); err != nil {
		t.Fatal(err)
	}
	if response.OK || !strings.Contains(response.Error, "Audit-Log nicht schreibbar") {
		t.Fatalf("helper response = %+v", response)
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if packageCommandCalled {
		t.Fatal("pacman ran even though the audit start record failed")
	}
}
