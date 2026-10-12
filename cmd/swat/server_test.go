package main

import "testing"

func TestServerConfigDefaultsToLoopbackHTTP(t *testing.T) {
	t.Setenv("SWAT_ADDR", "")
	t.Setenv("SWAT_TLS_CERT", "")
	t.Setenv("SWAT_TLS_KEY", "")

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
			if _, err := serverConfigFromEnvironment(); err == nil {
				t.Fatal("non-loopback HTTP listener was accepted without TLS")
			}
		})
	}
}

func TestServerConfigAcceptsTLSOutsideLoopback(t *testing.T) {
	t.Setenv("SWAT_ADDR", "0.0.0.0:443")
	t.Setenv("SWAT_TLS_CERT", "/run/credentials/swat.service/tls-cert")
	t.Setenv("SWAT_TLS_KEY", "/run/credentials/swat.service/tls-key")

	config, err := serverConfigFromEnvironment()
	if err != nil {
		t.Fatal(err)
	}
	if config.addr != "0.0.0.0:443" || config.tlsCert == "" || config.tlsKey == "" {
		t.Fatalf("TLS server config = %+v", config)
	}
}

func TestServerConfigRejectsIncompleteTLSAndInvalidAddress(t *testing.T) {
	t.Setenv("SWAT_ADDR", "127.0.0.1:8443")
	t.Setenv("SWAT_TLS_CERT", "/run/credentials/swat.service/tls-cert")
	t.Setenv("SWAT_TLS_KEY", "")
	if _, err := serverConfigFromEnvironment(); err == nil {
		t.Fatal("incomplete TLS configuration was accepted")
	}

	t.Setenv("SWAT_TLS_CERT", "")
	t.Setenv("SWAT_ADDR", "not-an-address")
	if _, err := serverConfigFromEnvironment(); err == nil {
		t.Fatal("invalid listen address was accepted")
	}
}
