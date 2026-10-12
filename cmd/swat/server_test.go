package main

import (
	"crypto/tls"
	"crypto/x509"
	"os"
	"path/filepath"
	"testing"
)

func TestServerConfigDefaultsToLoopbackHTTP(t *testing.T) {
	t.Setenv("SWAT_ADDR", "")
	t.Setenv("SWAT_TLS_CERT", "")
	t.Setenv("SWAT_TLS_KEY", "")
	t.Setenv("SWAT_TLS_SELF_SIGNED", "")

	config, err := serverConfigFromEnvironment()
	if err != nil {
		t.Fatal(err)
	}
	if config.addr != "127.0.0.1:8443" || config.tlsCert != "" || config.tlsKey != "" {
		t.Fatalf("default server config = %+v", config)
	}
}

func TestServerConfigRequiresTLSOutsideLoopback(t *testing.T) {
	for _, addr := range []string{":8443", "0.0.0.0:8443", "192.0.2.10:8443", "[::]:8443"} {
		t.Run(addr, func(t *testing.T) {
			t.Setenv("SWAT_ADDR", addr)
			t.Setenv("SWAT_TLS_CERT", "")
			t.Setenv("SWAT_TLS_KEY", "")
			t.Setenv("SWAT_TLS_SELF_SIGNED", "")
			if _, err := serverConfigFromEnvironment(); err == nil {
				t.Fatal("non-loopback HTTP listener was accepted without TLS")
			}
		})
	}
}

func TestServerConfigAcceptsTLSOutsideLoopback(t *testing.T) {
	stateDir := t.TempDir()
	t.Setenv("SWAT_ADDR", "0.0.0.0:8443")
	t.Setenv("SWAT_TLS_CERT", "/run/credentials/swat.service/tls-cert")
	t.Setenv("SWAT_TLS_KEY", "/run/credentials/swat.service/tls-key")
	t.Setenv("SWAT_TLS_SELF_SIGNED", "1")
	t.Setenv("SWAT_TLS_SERVER_NAME", "")
	t.Setenv("SWAT_STATE_DIR", stateDir)

	config, err := serverConfigFromEnvironment()
	if err != nil {
		t.Fatal(err)
	}
	if config.addr != "0.0.0.0:8443" || config.tlsCert != "/run/credentials/swat.service/tls-cert" || config.tlsKey != "/run/credentials/swat.service/tls-key" {
		t.Fatalf("TLS server config = %+v", config)
	}
	if _, err := os.Stat(filepath.Join(stateDir, "tls")); !os.IsNotExist(err) {
		t.Fatalf("self-signed certificate was generated despite custom credentials: %v", err)
	}
}

func TestServerConfigGeneratesSelfSignedCertificateWhenEnabled(t *testing.T) {
	stateDir := t.TempDir()
	t.Setenv("SWAT_ADDR", "0.0.0.0:8443")
	t.Setenv("SWAT_TLS_CERT", "")
	t.Setenv("SWAT_TLS_KEY", "")
	t.Setenv("SWAT_TLS_SELF_SIGNED", "1")
	t.Setenv("SWAT_TLS_SERVER_NAME", "45.155.173.94")
	t.Setenv("SWAT_STATE_DIR", stateDir)

	config, err := serverConfigFromEnvironment()
	if err != nil {
		t.Fatal(err)
	}
	if config.tlsCert != filepath.Join(stateDir, "tls", "self-signed.crt") || config.tlsKey != filepath.Join(stateDir, "tls", "self-signed.key") {
		t.Fatalf("generated TLS paths = %q, %q", config.tlsCert, config.tlsKey)
	}
	if _, err := tls.LoadX509KeyPair(config.tlsCert, config.tlsKey); err != nil {
		t.Fatalf("generated TLS pair is invalid: %v", err)
	}
	certificateData, err := os.ReadFile(config.tlsCert)
	if err != nil {
		t.Fatal(err)
	}
	keyInfo, err := os.Stat(config.tlsKey)
	if err != nil {
		t.Fatal(err)
	}
	if keyInfo.Mode().Perm() != 0o600 {
		t.Fatalf("private key permissions = %04o, want 0600", keyInfo.Mode().Perm())
	}
	directoryInfo, err := os.Stat(filepath.Dir(config.tlsCert))
	if err != nil {
		t.Fatal(err)
	}
	if directoryInfo.Mode().Perm() != 0o700 {
		t.Fatalf("TLS directory permissions = %04o, want 0700", directoryInfo.Mode().Perm())
	}
	pair, err := tls.LoadX509KeyPair(config.tlsCert, config.tlsKey)
	if err != nil {
		t.Fatal(err)
	}
	certificate, err := x509.ParseCertificate(pair.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	if err := certificate.VerifyHostname("45.155.173.94"); err != nil {
		t.Fatalf("certificate SAN does not cover configured IP: %v", err)
	}
	if _, _, err := ensureSelfSignedCertificate(stateDir, "45.155.173.94"); err != nil {
		t.Fatal(err)
	}
	if after, err := os.ReadFile(config.tlsCert); err != nil || string(after) != string(certificateData) {
		t.Fatalf("certificate was not preserved on restart: error=%v", err)
	}
	if err := os.Chmod(filepath.Dir(config.tlsCert), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(config.tlsKey, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, _, err := ensureSelfSignedCertificate(stateDir, "45.155.173.94"); err != nil {
		t.Fatal(err)
	}
	keyInfo, err = os.Stat(config.tlsKey)
	if err != nil || keyInfo.Mode().Perm() != 0o600 {
		t.Fatalf("private key permissions after repair = %v, error = %v", keyInfo.Mode().Perm(), err)
	}
	directoryInfo, err = os.Stat(filepath.Dir(config.tlsCert))
	if err != nil || directoryInfo.Mode().Perm() != 0o700 {
		t.Fatalf("TLS directory permissions after repair = %v, error = %v", directoryInfo.Mode().Perm(), err)
	}
}

func TestServerConfigRejectsIncompleteTLSAndInvalidAddress(t *testing.T) {
	t.Setenv("SWAT_ADDR", "127.0.0.1:8443")
	t.Setenv("SWAT_TLS_CERT", "/run/credentials/swat.service/tls-cert")
	t.Setenv("SWAT_TLS_KEY", "")
	t.Setenv("SWAT_TLS_SELF_SIGNED", "")
	if _, err := serverConfigFromEnvironment(); err == nil {
		t.Fatal("incomplete TLS configuration was accepted")
	}

	t.Setenv("SWAT_TLS_CERT", "")
	t.Setenv("SWAT_ADDR", "not-an-address")
	if _, err := serverConfigFromEnvironment(); err == nil {
		t.Fatal("invalid listen address was accepted")
	}
}
