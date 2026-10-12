package nginxcfg

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestGenerateReverseProxyAndStaticSites(t *testing.T) {
	config := Config{Version: CurrentVersion, Sites: []Site{
		{ServerNames: []string{"app.example.test"}, Mode: "proxy", Upstream: "http://127.0.0.1:8080"},
		{ServerNames: []string{"www.example.test", "example.test"}, Mode: "static", DocumentRoot: "/srv/www/example"},
	}}
	generated, err := Generate(config)
	if err != nil {
		t.Fatal(err)
	}
	text := string(generated)
	for _, expected := range []string{
		"# Managed-By: SWAT", "# SWAT-Config-ID: nginx/sites", "server_name app.example.test;",
		"proxy_pass http://127.0.0.1:8080;", "proxy_set_header X-Forwarded-Proto $scheme;",
		"root \"/srv/www/example\";", "try_files $uri $uri/ =404;",
	} {
		if !strings.Contains(text, expected) {
			t.Errorf("generated config missing %q", expected)
		}
	}
}

func TestGenerateTLSConfig(t *testing.T) {
	generated, err := Generate(Config{Version: CurrentVersion, Sites: []Site{{
		ServerNames: []string{"mail.example.test"}, Mode: "proxy", Upstream: "https://127.0.0.1:8443",
		TLSCertificate: "/etc/letsencrypt/live/mail.example.test/fullchain.pem",
		TLSKey:         "/etc/letsencrypt/live/mail.example.test/privkey.pem",
	}}})
	if err != nil {
		t.Fatal(err)
	}
	for _, expected := range []string{"listen 443 ssl;", "ssl_protocols TLSv1.2 TLSv1.3;", "ssl_certificate \"/etc/letsencrypt/live/mail.example.test/fullchain.pem\";"} {
		if !strings.Contains(string(generated), expected) {
			t.Errorf("TLS config missing %q", expected)
		}
	}
}

func TestValidateRejectsDirectiveInjectionAndConflicts(t *testing.T) {
	base := Site{ServerNames: []string{"app.example.test"}, Mode: "proxy", Upstream: "http://127.0.0.1:8080"}
	cases := map[string]Config{
		"bad server name":    {Version: CurrentVersion, Sites: []Site{{ServerNames: []string{"app.example.test; return 200"}, Mode: "static", DocumentRoot: "/srv/www/app"}}},
		"upstream injection": {Version: CurrentVersion, Sites: []Site{{ServerNames: []string{"app.example.test"}, Mode: "proxy", Upstream: "http://127.0.0.1:80;include /tmp/x"}}},
		"root traversal":     {Version: CurrentVersion, Sites: []Site{{ServerNames: []string{"app.example.test"}, Mode: "static", DocumentRoot: "/srv/www/../etc"}}},
		"unpaired TLS":       {Version: CurrentVersion, Sites: []Site{{ServerNames: []string{"app.example.test"}, Mode: "proxy", Upstream: base.Upstream, TLSCertificate: "/etc/cert.pem"}}},
		"duplicate name":     {Version: CurrentVersion, Sites: []Site{base, {ServerNames: []string{"app.example.test"}, Mode: "static", DocumentRoot: "/srv/www/app"}}},
	}
	for name, config := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := Generate(config); err == nil {
				t.Fatal("unsafe configuration was accepted")
			}
		})
	}
}

func TestSaveAndLoadDesiredState(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state", "nginx-sites.json")
	want := Config{Version: CurrentVersion, Sites: []Site{{ServerNames: []string{"app.example.test"}, Mode: "proxy", Upstream: "http://127.0.0.1:8080"}}}
	if err := Save(path, want); err != nil {
		t.Fatal(err)
	}
	got, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Sites) != 1 || got.Sites[0].Upstream != want.Sites[0].Upstream {
		t.Fatalf("loaded config = %#v", got)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("desired state mode = %04o, want 0600", info.Mode().Perm())
	}
}
