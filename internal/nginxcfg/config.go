package nginxcfg

import (
	"encoding/json"
	"fmt"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

const CurrentVersion = 1

type Site struct {
	ServerNames    []string `json:"server_names"`
	Mode           string   `json:"mode"`
	Upstream       string   `json:"upstream,omitempty"`
	DocumentRoot   string   `json:"document_root,omitempty"`
	TLSCertificate string   `json:"tls_certificate,omitempty"`
	TLSKey         string   `json:"tls_key,omitempty"`
}

type Config struct {
	Version int    `json:"version"`
	Sites   []Site `json:"sites"`
}

var domainLabelPattern = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$`)
var staticRootPattern = regexp.MustCompile(`^/srv/www/[A-Za-z0-9_./-]+$`)

func (site Site) Validate() error {
	if len(site.ServerNames) == 0 || len(site.ServerNames) > 32 {
		return fmt.Errorf("jeder vHost benötigt 1 bis 32 Servernamen")
	}
	for _, name := range site.ServerNames {
		if err := validateServerName(name); err != nil {
			return err
		}
	}
	switch site.Mode {
	case "proxy":
		if err := validateUpstream(site.Upstream); err != nil {
			return err
		}
		if site.DocumentRoot != "" {
			return fmt.Errorf("Reverse-Proxy-vHosts dürfen keinen Dokumentenpfad setzen")
		}
	case "static":
		if !staticRootPattern.MatchString(site.DocumentRoot) || strings.Contains(site.DocumentRoot, "..") || strings.HasSuffix(site.DocumentRoot, "/") {
			return fmt.Errorf("Dokumentenpfad muss ein sicherer Pfad unter /srv/www sein")
		}
		if site.Upstream != "" {
			return fmt.Errorf("statische vHosts dürfen kein Upstream-Ziel setzen")
		}
	default:
		return fmt.Errorf("unbekannter vHost-Modus %q", site.Mode)
	}
	if (site.TLSCertificate == "") != (site.TLSKey == "") {
		return fmt.Errorf("TLS-Zertifikat und Schlüssel müssen gemeinsam angegeben werden")
	}
	if site.TLSCertificate != "" {
		if err := validateTLSPath(site.TLSCertificate); err != nil {
			return fmt.Errorf("TLS-Zertifikat: %w", err)
		}
		if err := validateTLSPath(site.TLSKey); err != nil {
			return fmt.Errorf("TLS-Schlüssel: %w", err)
		}
	}
	return nil
}

func (config Config) Validate() error {
	if config.Version != CurrentVersion {
		return fmt.Errorf("nicht unterstützte Nginx-Konfigurationsversion %d", config.Version)
	}
	if len(config.Sites) > 128 {
		return fmt.Errorf("maximal 128 Nginx-vHosts werden unterstützt")
	}
	owners := make(map[string]int)
	for index, site := range config.Sites {
		if err := site.Validate(); err != nil {
			return fmt.Errorf("vHost %d: %w", index+1, err)
		}
		for _, serverName := range site.ServerNames {
			key := strings.ToLower(serverName)
			if previous, exists := owners[key]; exists {
				return fmt.Errorf("Servername %q ist in vHost %d und %d mehrfach definiert", serverName, previous+1, index+1)
			}
			owners[key] = index
		}
	}
	return nil
}

func validateServerName(name string) error {
	name = strings.TrimSpace(name)
	if name == "" || len(name) > 253 || strings.HasSuffix(name, ".") {
		return fmt.Errorf("ungültiger Nginx-Servername %q", name)
	}
	for _, label := range strings.Split(strings.ToLower(name), ".") {
		if !domainLabelPattern.MatchString(label) {
			return fmt.Errorf("ungültiger Nginx-Servername %q", name)
		}
	}
	return nil
}

func validateUpstream(value string) error {
	parsed, err := url.Parse(value)
	if err != nil || (parsed.Scheme != "http" && parsed.Scheme != "https") || parsed.Host == "" || parsed.User != nil || parsed.Path != "" || parsed.RawQuery != "" || parsed.Fragment != "" {
		return fmt.Errorf("Upstream muss eine HTTP(S)-Adresse mit Host und Port sein, zum Beispiel http://127.0.0.1:8080")
	}
	portText := parsed.Port()
	port, err := strconv.Atoi(portText)
	if err != nil || port < 1 || port > 65535 {
		return fmt.Errorf("Upstream benötigt einen gültigen Port")
	}
	host := parsed.Hostname()
	if host == "" || strings.ContainsAny(host, " \t\r\n;{}$") {
		return fmt.Errorf("ungültiger Upstream-Host")
	}
	if net.ParseIP(host) == nil {
		for _, label := range strings.Split(strings.ToLower(host), ".") {
			if !domainLabelPattern.MatchString(label) {
				return fmt.Errorf("ungültiger Upstream-Host")
			}
		}
	}
	return nil
}

func validateTLSPath(path string) error {
	if !filepath.IsAbs(path) || strings.Contains(path, "..") || strings.ContainsAny(path, " \t\r\n;{}$") {
		return fmt.Errorf("es wird ein absoluter, einfacher Dateipfad ohne Direktiven erwartet")
	}
	return nil
}

func Generate(config Config) ([]byte, error) {
	if err := config.Validate(); err != nil {
		return nil, err
	}
	sites := append([]Site(nil), config.Sites...)
	sort.Slice(sites, func(i, j int) bool {
		return strings.ToLower(sites[i].ServerNames[0]) < strings.ToLower(sites[j].ServerNames[0])
	})
	var output strings.Builder
	output.WriteString("# Managed-By: SWAT\n# SWAT-Config-ID: nginx/sites\n")
	for _, site := range sites {
		names := append([]string(nil), site.ServerNames...)
		sort.Slice(names, func(i, j int) bool { return strings.ToLower(names[i]) < strings.ToLower(names[j]) })
		output.WriteString("\nserver {\n")
		if site.TLSCertificate == "" {
			output.WriteString("    listen 80;\n")
		} else {
			output.WriteString("    listen 443 ssl;\n    ssl_protocols TLSv1.2 TLSv1.3;\n")
			fmt.Fprintf(&output, "    ssl_certificate %s;\n", nginxQuote(site.TLSCertificate))
			fmt.Fprintf(&output, "    ssl_certificate_key %s;\n", nginxQuote(site.TLSKey))
		}
		fmt.Fprintf(&output, "    server_name %s;\n", strings.Join(names, " "))
		if site.Mode == "proxy" {
			output.WriteString("\n    location / {\n")
			fmt.Fprintf(&output, "        proxy_pass %s;\n", site.Upstream)
			output.WriteString("        proxy_set_header Host $host;\n        proxy_set_header X-Real-IP $remote_addr;\n        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;\n        proxy_set_header X-Forwarded-Proto $scheme;\n    }\n")
		} else {
			fmt.Fprintf(&output, "    root %s;\n", nginxQuote(site.DocumentRoot))
			output.WriteString("    index index.html;\n\n    location / {\n        try_files $uri $uri/ =404;\n    }\n")
		}
		output.WriteString("}\n")
	}
	return []byte(output.String()), nil
}

func nginxQuote(value string) string {
	value = strings.ReplaceAll(value, `\`, `\\`)
	value = strings.ReplaceAll(value, `"`, `\"`)
	return `"` + value + `"`
}

func Load(path string) (Config, error) {
	data, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return Config{Version: CurrentVersion}, nil
	}
	if err != nil {
		return Config{}, err
	}
	var config Config
	if err := json.Unmarshal(data, &config); err != nil {
		return Config{}, err
	}
	return config, config.Validate()
}

func Save(path string, config Config) error {
	if err := config.Validate(); err != nil {
		return err
	}
	data, err := json.MarshalIndent(config, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	temporary, err := os.CreateTemp(filepath.Dir(path), ".nginx-desired-*.tmp")
	if err != nil {
		return err
	}
	defer os.Remove(temporary.Name())
	if err := temporary.Chmod(0o600); err != nil {
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
	return os.Rename(temporary.Name(), path)
}

func StatePath(directory string) string {
	return filepath.Join(directory, "nginx-sites.json")
}
