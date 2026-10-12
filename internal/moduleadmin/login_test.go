package moduleadmin

import (
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"testing"

	"swat/internal/audit"
)

func TestHelperAuthenticationUsesPAMAndAudits(t *testing.T) {
	for _, tc := range []struct {
		name      string
		operation string
		action    string
		authOK    bool
		result    string
	}{
		{name: "login accepted", operation: operationAuthenticateLogin, action: "auth/login", authOK: true, result: "ok"},
		{name: "login rejected", operation: operationAuthenticateLogin, action: "auth/login", authOK: false, result: "fehler"},
		{name: "sudo accepted", operation: operationAuthenticateSudo, action: "auth/sudo", authOK: true, result: "ok"},
		{name: "sudo rejected", operation: operationAuthenticateSudo, action: "auth/sudo", authOK: false, result: "fehler"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			socketPath := filepath.Join(t.TempDir(), "login.sock")
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
			go func() {
				_ = json.NewEncoder(client).Encode(Request{Operation: tc.operation, Username: "evohl", Password: "secret"})
			}()
			var audited []audit.Entry
			authorizer := func(username, password string) error {
				if username != "evohl" || password != "secret" {
					t.Fatalf("unexpected credentials %q / %q", username, password)
				}
				if !tc.authOK {
					return os.ErrPermission
				}
				return nil
			}
			installer := Installer{
				Login:     authorizer,
				Authorize: authorizer,
				Audit: func(entry audit.Entry) error {
					audited = append(audited, entry)
					return nil
				},
			}
			if err := installer.serveConnection(server, uint32(os.Getuid())); err != nil {
				t.Fatal(err)
			}
			var response Response
			if err := json.NewDecoder(client).Decode(&response); err != nil {
				t.Fatal(err)
			}
			if response.OK != tc.authOK {
				t.Fatalf("response OK = %v, want %v", response.OK, tc.authOK)
			}
			if len(audited) != 1 || audited[0].Action != tc.action || audited[0].Result != tc.result {
				t.Fatalf("audit entries = %+v", audited)
			}
		})
	}
}
