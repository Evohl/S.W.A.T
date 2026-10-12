package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

const selfSignedCertificateValidity = 365 * 24 * time.Hour

func ensureSelfSignedCertificate(stateDir, serverName string) (string, string, error) {
	directory := filepath.Join(stateDir, "tls")
	certPath := filepath.Join(directory, "self-signed.crt")
	keyPath := filepath.Join(directory, "self-signed.key")
	if selfSignedCertificateIsUsable(certPath, keyPath, serverName) {
		if err := os.Chmod(directory, 0o700); err != nil {
			return "", "", err
		}
		if err := os.Chmod(keyPath, 0o600); err != nil {
			return "", "", err
		}
		if err := os.Chmod(certPath, 0o644); err != nil {
			return "", "", err
		}
		return certPath, keyPath, nil
	}
	if err := os.MkdirAll(directory, 0o700); err != nil {
		return "", "", err
	}
	if err := os.Chmod(directory, 0o700); err != nil {
		return "", "", err
	}
	certificate, privateKey, err := generateSelfSignedCertificate(serverName)
	if err != nil {
		return "", "", err
	}
	if err := writeTLSFileAtomic(keyPath, privateKey, 0o600); err != nil {
		return "", "", err
	}
	if err := writeTLSFileAtomic(certPath, certificate, 0o644); err != nil {
		return "", "", err
	}
	return certPath, keyPath, nil
}

func selfSignedCertificateIsUsable(certPath, keyPath, serverName string) bool {
	pair, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err != nil || len(pair.Certificate) == 0 {
		return false
	}
	certificate, err := x509.ParseCertificate(pair.Certificate[0])
	if err != nil || time.Until(certificate.NotAfter) < 30*24*time.Hour {
		return false
	}
	serverName = strings.TrimSpace(serverName)
	return serverName == "" || certificate.VerifyHostname(serverName) == nil
}

func generateSelfSignedCertificate(serverName string) ([]byte, []byte, error) {
	dnsNames := make(map[string]struct{})
	ipAddresses := make(map[string]net.IP)
	addName := func(name string, required bool) error {
		name = strings.TrimSpace(name)
		if name == "" {
			return nil
		}
		if ip := net.ParseIP(name); ip != nil {
			ipAddresses[ip.String()] = ip
			return nil
		}
		name = strings.TrimSuffix(name, ".")
		if validCertificateDNSName(name) {
			dnsNames[name] = struct{}{}
			return nil
		}
		if required {
			return fmt.Errorf("SWAT_TLS_SERVER_NAME must be a DNS name or IP address")
		}
		return nil
	}

	hostname, _ := os.Hostname()
	if err := addName(hostname, false); err != nil {
		return nil, nil, err
	}
	if err := addName(serverName, true); err != nil {
		return nil, nil, err
	}
	interfaces, err := net.Interfaces()
	if err != nil {
		return nil, nil, err
	}
	for _, networkInterface := range interfaces {
		addresses, err := networkInterface.Addrs()
		if err != nil {
			continue
		}
		for _, address := range addresses {
			ip, _, err := net.ParseCIDR(address.String())
			if err == nil {
				ipAddresses[ip.String()] = ip
			}
		}
	}
	if len(dnsNames) == 0 && len(ipAddresses) == 0 {
		ipAddresses["127.0.0.1"] = net.ParseIP("127.0.0.1")
		ipAddresses["::1"] = net.ParseIP("::1")
	}

	dns := make([]string, 0, len(dnsNames))
	for name := range dnsNames {
		dns = append(dns, name)
	}
	sort.Strings(dns)
	ips := make([]net.IP, 0, len(ipAddresses))
	for _, ip := range ipAddresses {
		ips = append(ips, ip)
	}
	sort.Slice(ips, func(i, j int) bool { return ips[i].String() < ips[j].String() })

	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	serialLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serial, err := rand.Int(rand.Reader, serialLimit)
	if err != nil {
		return nil, nil, err
	}
	now := time.Now()
	template := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: "S.W.A.T self-signed"},
		NotBefore:             now.Add(-5 * time.Minute),
		NotAfter:              now.Add(selfSignedCertificateValidity),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		DNSNames:              dns,
		IPAddresses:           ips,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &privateKey.PublicKey, privateKey)
	if err != nil {
		return nil, nil, err
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		return nil, nil, err
	}
	certificatePEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	privateKeyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
	return certificatePEM, privateKeyPEM, nil
}

func validCertificateDNSName(name string) bool {
	if len(name) == 0 || len(name) > 253 {
		return false
	}
	for _, label := range strings.Split(name, ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, character := range label {
			if !((character >= 'a' && character <= 'z') || (character >= 'A' && character <= 'Z') || (character >= '0' && character <= '9') || character == '-') {
				return false
			}
		}
	}
	return true
}

func writeTLSFileAtomic(path string, data []byte, mode os.FileMode) error {
	temporary, err := os.CreateTemp(filepath.Dir(path), ".swat-tls-*")
	if err != nil {
		return err
	}
	temporaryPath := temporary.Name()
	defer os.Remove(temporaryPath)
	if err := temporary.Chmod(mode); err != nil {
		temporary.Close()
		return err
	}
	if _, err := temporary.Write(data); err != nil {
		temporary.Close()
		return err
	}
	if err := temporary.Sync(); err != nil {
		temporary.Close()
		return err
	}
	if err := temporary.Close(); err != nil {
		return err
	}
	return os.Rename(temporaryPath, path)
}
