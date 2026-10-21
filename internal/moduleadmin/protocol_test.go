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

func TestSystemSettingUsesOnlyValidatedNativeCommands(t *testing.T) {
	var commands []string
	run := func(_ context.Context, name string, args ...string) ([]byte, error) {
		commands = append(commands, name+" "+strings.Join(args, " "))
		switch name {
		case "locale":
			return []byte("de_DE.utf8\nen_US.utf8\n"), nil
		case "timedatectl":
			if len(args) == 1 && args[0] == "list-timezones" {
				return []byte("Europe/Berlin\nUTC\n"), nil
			}
		}
		return nil, nil
	}
	ctx := context.Background()
	tests := []struct {
		setting string
		value   string
		command string
	}{
		{"hostname", "server01.example.test", "hostnamectl set-hostname --static server01.example.test"},
		{"locale", "de_DE.UTF-8", "localectl set-locale LANG=de_DE.UTF-8"},
		{"timezone", "Europe/Berlin", "timedatectl set-timezone Europe/Berlin"},
	}
	for _, test := range tests {
		command, args, err := systemSettingCommand(ctx, run, test.setting, test.value)
		if err != nil {
			t.Fatalf("%s rejected: %v", test.setting, err)
		}
		if got := command + " " + strings.Join(args, " "); got != test.command {
			t.Errorf("%s command = %q, want %q", test.setting, got, test.command)
		}
	}
	for _, test := range []struct{ setting, value string }{
		{"hostname", "server;touch /tmp/nope"},
		{"locale", "../../etc/passwd"},
		{"timezone", "../../etc"},
		{"systemctl", "restart"},
	} {
		if _, _, err := systemSettingCommand(ctx, run, test.setting, test.value); err == nil {
			t.Errorf("unsafe system setting accepted: %s=%q", test.setting, test.value)
		}
	}
}

func TestAdminActionCommandAllowlist(t *testing.T) {
	cases := []struct {
		action string
		target string
		value  string
		value2 string
		value3 string
		want   string
	}{
		{"user-create", "alice", "/bin/bash", "Alice Example", "/home/alice", "useradd -m -s /bin/bash -c Alice Example -d /home/alice alice"},
		{"group-create", "admins", "1001", "", "", "groupadd -g 1001 admins"},
		{"user-expire-password", "alice", "", "", "", "chage -d 0 alice"},
		{"user-delete", "alice", "", "", "", "userdel alice"},
		{"group-membership", "alice", "admins", "add", "", "usermod -a -G admins alice"},
		{"group-membership", "alice", "admins", "remove", "", "gpasswd -d alice admins"},
		{"service", "nginx.service", "stop", "", "", "systemctl stop -- nginx.service"},
	}
	for _, test := range cases {
		command, args, err := adminActionCommand(test.action, test.target, test.value, test.value2, test.value3)
		if err != nil {
			t.Errorf("%s rejected: %v", test.action, err)
			continue
		}
		if got := command + " " + strings.Join(args, " "); got != test.want {
			t.Errorf("%s command = %q, want %q", test.action, got, test.want)
		}
	}
	for _, test := range []struct{ action, target, value, value2, value3 string }{
		{"service", "sshd.service", "stop", "", ""},
		{"service", "nginx.service", "start;id", "", ""},
		{"service", "nginx.service", "start", "", ""},
		{"service", "postfix.service", "enable", "", ""},
		{"user-create", "alice", "/bin/sh", "", "/etc"},
		{"group-create", "admins", "1", "", ""},
		{"group-membership", "alice", "wheel", "add", ""},
		{"group-membership", "alice", "docker", "add", ""},
		{"unknown", "", "", "", ""},
	} {
		if test.action == "service" && (test.value == "start" || test.value == "enable") && serviceRequiresConfiguration(test.target) {
			if _, _, err := adminActionCommand(test.action, test.target, test.value, test.value2, test.value3); err == nil {
				t.Errorf("configuration-required service action accepted: %+v", test)
			}
			continue
		}
		if _, _, err := adminActionCommand(test.action, test.target, test.value, test.value2, test.value3); err == nil {
			t.Errorf("unsafe admin action accepted: %+v", test)
		}
	}
}

func TestVMActionCommandAllowlist(t *testing.T) {
	cases := []struct {
		action string
		target string
		value  string
		value2 string
		want   string
	}{
		{"vm-start", "test-vm", "", "", "virsh --connect qemu:///system start test-vm"},
		{"vm-delete", "test-vm", "", "", "virsh --connect qemu:///system undefine test-vm --nvram"},
		{"vm-eject-media", "test-vm", "sda", "", "virsh --connect qemu:///system change-media test-vm sda --eject --config"},
		{"libvirt-pool-start", "images", "", "", "virsh --connect qemu:///system pool-start images"},
		{"libvirt-network-stop", "default", "", "", "virsh --connect qemu:///system net-destroy default"},
		{"libvirt-pool-create", "images", "/var/lib/libvirt/images/extra", "", "virsh --connect qemu:///system pool-define-as images dir --target /var/lib/libvirt/images/extra"},
		{"vm-config-memory", "test-vm", "4096", "", "virsh --connect qemu:///system setmaxmem test-vm 4096MiB --config"},
	}
	for _, test := range cases {
		command, args, err := vmActionCommand(test.action, test.target, test.value, test.value2, "", "")
		if err != nil {
			t.Errorf("%s rejected: %v", test.action, err)
			continue
		}
		if got := command + " " + strings.Join(args, " "); got != test.want {
			t.Errorf("%s = %q, want %q", test.action, got, test.want)
		}
	}
	for _, test := range []struct{ action, target, value, value2 string }{
		{"vm-start", "../../etc", "", ""},
		{"libvirt-pool-create", "images", "/etc", ""},
		{"vm-config-memory", "test-vm", "99999999", ""},
		{"vm-iso-delete", "pool", "../../etc/passwd", ""},
		{"vm-define", "test-vm", "<!DOCTYPE domain><domain><name>test-vm</name></domain>", ""},
		{"systemctl", "nginx.service", "stop", ""},
	} {
		if test.action == "vm-define" {
			if validDomainXML(test.value, test.target) {
				t.Errorf("unsafe XML accepted: %+v", test)
			}
			continue
		}
		command, args, err := vmActionCommand(test.action, test.target, test.value, test.value2, "", "")
		if err == nil {
			t.Errorf("unsafe VM action accepted: %+v -> %s %v", test, command, args)
		}
	}
}

func TestAdminActionHelperAuditsUserAndExecutesFixedServiceCommand(t *testing.T) {
	listener, err := net.Listen("unix", filepath.Join(t.TempDir(), "admin-action.sock"))
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
	var audits []audit.Entry
	var commands []string
	installer := Installer{
		Authorize: func(username, password string) error {
			if username != "admin" || password != "verified" {
				t.Fatalf("unexpected authorization identity %q", username)
			}
			return nil
		},
		Audit: func(entry audit.Entry) error {
			audits = append(audits, entry)
			return nil
		},
		Run: func(_ context.Context, command string, args ...string) ([]byte, error) {
			commands = append(commands, command+" "+strings.Join(args, " "))
			return nil, nil
		},
	}
	done := make(chan error, 1)
	go func() { done <- installer.serveConnection(server, uint32(os.Getuid())) }()
	if err := json.NewEncoder(client).Encode(Request{
		Operation: operationAdminAction, Action: "service", Target: "nginx.service", Value: "stop",
		Username: "admin", Password: "verified",
	}); err != nil {
		t.Fatal(err)
	}
	var response Response
	if err := json.NewDecoder(client).Decode(&response); err != nil {
		t.Fatal(err)
	}
	if !response.OK {
		t.Fatalf("helper response = %+v", response)
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(commands, []string{"systemctl stop -- nginx.service"}) {
		t.Fatalf("commands = %v", commands)
	}
	if len(audits) != 2 || audits[0].User != "admin" || audits[0].Result != "started" || audits[1].User != "admin" || audits[1].Result != "ok" || audits[1].Target != "nginx.service stop" {
		t.Fatalf("audit events = %+v", audits)
	}
}

func TestSystemSettingHelperAuthorizesAuditsAndApplies(t *testing.T) {
	socketPath := filepath.Join(t.TempDir(), "system-setting.sock")
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
	var audits []audit.Entry
	var commands []string
	installer := Installer{
		Authorize: func(username, password string) error {
			if username != "admin" || password != "verified" {
				t.Fatalf("unexpected helper credentials %q / %q", username, password)
			}
			return nil
		},
		Audit: func(entry audit.Entry) error {
			audits = append(audits, entry)
			return nil
		},
		Run: func(_ context.Context, name string, args ...string) ([]byte, error) {
			commands = append(commands, name+" "+strings.Join(args, " "))
			if name == "locale" {
				return []byte("de_DE.utf8\n"), nil
			}
			return nil, nil
		},
	}
	done := make(chan error, 1)
	go func() { done <- installer.serveConnection(server, uint32(os.Getuid())) }()
	if err := json.NewEncoder(client).Encode(Request{
		Operation: operationSetSystemSetting, Setting: "locale", Value: "de_DE.UTF-8",
		Username: "admin", Password: "verified",
	}); err != nil {
		t.Fatal(err)
	}
	var response Response
	if err := json.NewDecoder(client).Decode(&response); err != nil {
		t.Fatal(err)
	}
	if !response.OK {
		t.Fatalf("helper response = %+v", response)
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(commands, []string{"locale -a", "localectl set-locale LANG=de_DE.UTF-8"}) {
		t.Fatalf("commands = %v", commands)
	}
	if len(audits) != 2 || audits[0].Action != "system/locale/start" || audits[1].Action != "system/locale" || audits[1].Result != "ok" {
		t.Fatalf("audit sequence = %+v", audits)
	}
}

func TestSystemSettingHelperRequiresAuditBeforeApplying(t *testing.T) {
	listener, err := net.Listen("unix", filepath.Join(t.TempDir(), "system-setting-audit.sock"))
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
	commandCalled := false
	installer := Installer{
		Authorize: func(string, string) error { return nil },
		Audit:     func(audit.Entry) error { return os.ErrPermission },
		Run: func(context.Context, string, ...string) ([]byte, error) {
			commandCalled = true
			return nil, nil
		},
	}
	done := make(chan error, 1)
	go func() { done <- installer.serveConnection(server, uint32(os.Getuid())) }()
	if err := json.NewEncoder(client).Encode(Request{
		Operation: operationSetSystemSetting, Setting: "hostname", Value: "server01",
		Username: "admin", Password: "verified",
	}); err != nil {
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
	if commandCalled {
		t.Fatal("system command ran before audit start was recorded")
	}
}

func TestSystemSettingHelperRejectsFailedAuthorization(t *testing.T) {
	listener, err := net.Listen("unix", filepath.Join(t.TempDir(), "system-setting-auth.sock"))
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
	commandCalled := false
	installer := Installer{
		Authorize: func(string, string) error { return os.ErrPermission },
		Audit:     func(audit.Entry) error { return nil },
		Run: func(context.Context, string, ...string) ([]byte, error) {
			commandCalled = true
			return nil, nil
		},
	}
	done := make(chan error, 1)
	go func() { done <- installer.serveConnection(server, uint32(os.Getuid())) }()
	if err := json.NewEncoder(client).Encode(Request{
		Operation: operationSetSystemSetting, Setting: "hostname", Value: "server01",
		Username: "admin", Password: "incorrect",
	}); err != nil {
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
	if commandCalled {
		t.Fatal("system command ran despite failed PAM authorization")
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
