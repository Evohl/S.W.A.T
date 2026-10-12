package main

import (
	"fmt"
	"net"
	"net/http"
	"os"
	"strings"
)

type serverConfig struct {
	addr    string
	tlsCert string
	tlsKey  string
}

func serverConfigFromEnvironment() (serverConfig, error) {
	addr := strings.TrimSpace(os.Getenv("SWAT_ADDR"))
	if addr == "" {
		addr = "127.0.0.1:8443"
	}
	config := serverConfig{
		addr:    addr,
		tlsCert: strings.TrimSpace(os.Getenv("SWAT_TLS_CERT")),
		tlsKey:  strings.TrimSpace(os.Getenv("SWAT_TLS_KEY")),
	}
	if (config.tlsCert == "") != (config.tlsKey == "") {
		return serverConfig{}, fmt.Errorf("SWAT_TLS_CERT and SWAT_TLS_KEY must both be configured")
	}
	if _, _, err := net.SplitHostPort(config.addr); err != nil {
		return serverConfig{}, fmt.Errorf("SWAT_ADDR must be a host:port address: %w", err)
	}
	if config.tlsCert == "" && !loopbackAddress(config.addr) {
		return serverConfig{}, fmt.Errorf("TLS certificate and key are required when SWAT listens on a non-loopback address")
	}
	return config, nil
}

func loopbackAddress(addr string) bool {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return false
	}
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

func (config serverConfig) serve(handler http.Handler) error {
	server := &http.Server{Addr: config.addr, Handler: handler}
	if config.tlsCert != "" {
		return server.ListenAndServeTLS(config.tlsCert, config.tlsKey)
	}
	return server.ListenAndServe()
}
