package main

import (
	"fmt"
	"net/http"
	"sort"
	"strings"

	"swat/internal/audit"
	"swat/internal/nginxcfg"
	"swat/internal/zones"
)

type nginxForm struct {
	OriginalName string
	ServerNames  string
	Mode         string
	Upstream     string
	DocumentRoot string
	TLS          bool
	Certificate  string
	Key          string
}

type nginxSiteRow struct {
	Name   string
	Names  string
	Mode   string
	Target string
	TLS    bool
}

type nginxPageData struct {
	Config  nginxcfg.Config
	Sites   []nginxSiteRow
	Form    nginxForm
	Preview string
	Error   string
	Success string
}

func handleNginx(w http.ResponseWriter, r *http.Request) {
	if !modulePageReady("nginx") {
		http.Redirect(w, r, "/modules?required=nginx", http.StatusSeeOther)
		return
	}
	page := loadNginxPage(r.URL.Query().Get("edit"), "", "")
	render(w, r, "nginx", "nginx.html", nginxPageMap(page))
}

func handleNginxAction(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Methode nicht erlaubt", http.StatusMethodNotAllowed)
		return
	}
	session, err := accountActionSession(r)
	if err != nil {
		page := loadNginxPage("", err.Error(), "")
		render(w, r, "nginx", "nginx.html", nginxPageMap(page))
		return
	}
	if !modulePageReady("nginx") {
		http.Redirect(w, r, "/modules?required=nginx", http.StatusSeeOther)
		return
	}
	if err := r.ParseForm(); err != nil {
		page := loadNginxPage("", "Ungültige Anfrage.", "")
		render(w, r, "nginx", "nginx.html", nginxPageMap(page))
		return
	}
	config, err := nginxcfg.Load(nginxcfg.StatePath(zones.StateDir()))
	if err != nil {
		page := loadNginxPage("", "Gespeicherte Nginx-Konfiguration ist ungültig: "+err.Error(), "")
		render(w, r, "nginx", "nginx.html", nginxPageMap(page))
		return
	}
	action := r.FormValue("action")
	target := strings.TrimSpace(r.FormValue("original_name"))
	if err := audit.Log(zones.StateDir(), audit.Entry{User: session.Username, Action: "nginx/" + action + "/start", Target: target, Result: "started"}); err != nil {
		page := nginxPage(config, nginxForm{}, "Audit-Log nicht schreibbar; Änderung wurde nicht gespeichert.", "")
		render(w, r, "nginx", "nginx.html", nginxPageMap(page))
		return
	}
	var success string
	switch action {
	case "save":
		config, err = saveNginxSite(config, r)
		success = "Nginx-vHost als Desired State gespeichert. Noch nicht auf dem System angewendet."
	case "delete":
		config, err = deleteNginxSite(config, target)
		success = "Nginx-vHost aus dem Desired State entfernt. Systemdateien wurden nicht verändert."
	default:
		err = fmt.Errorf("Ungültige Nginx-Aktion.")
	}
	result, detail := "ok", ""
	if err != nil {
		result, detail = "fehler", err.Error()
	}
	if auditErr := audit.Log(zones.StateDir(), audit.Entry{User: session.Username, Action: "nginx/" + action, Target: target, Result: result, Detail: detail}); auditErr != nil && err == nil {
		err = fmt.Errorf("Audit-Log nicht schreibbar; Änderung wurde nicht gespeichert: %w", auditErr)
	}
	message := ""
	if err != nil {
		message = err.Error()
		success = ""
	}
	form := nginxForm{}
	if action == "save" && err != nil {
		form = nginxForm{
			OriginalName: target,
			ServerNames:  r.FormValue("server_names"), Mode: r.FormValue("mode"),
			Upstream: r.FormValue("upstream"), DocumentRoot: r.FormValue("document_root"),
			TLS: r.FormValue("tls") == "1", Certificate: r.FormValue("certificate"), Key: r.FormValue("key"),
		}
	}
	page := nginxPage(config, form, message, success)
	render(w, r, "nginx", "nginx.html", nginxPageMap(page))
}

func saveNginxSite(config nginxcfg.Config, r *http.Request) (nginxcfg.Config, error) {
	names := splitNginxServerNames(r.FormValue("server_names"))
	site := nginxcfg.Site{
		ServerNames:  names,
		Mode:         r.FormValue("mode"),
		Upstream:     strings.TrimSpace(r.FormValue("upstream")),
		DocumentRoot: strings.TrimSpace(r.FormValue("document_root")),
	}
	if r.FormValue("tls") == "1" {
		site.TLSCertificate = strings.TrimSpace(r.FormValue("certificate"))
		site.TLSKey = strings.TrimSpace(r.FormValue("key"))
	}
	if err := site.Validate(); err != nil {
		return config, err
	}
	originalName := strings.ToLower(strings.TrimSpace(r.FormValue("original_name")))
	if originalName == "" {
		config.Sites = append(config.Sites, site)
	} else {
		found := false
		for index := range config.Sites {
			if strings.EqualFold(config.Sites[index].ServerNames[0], originalName) {
				config.Sites[index] = site
				found = true
				break
			}
		}
		if !found {
			return config, fmt.Errorf("zu bearbeitender Nginx-vHost %q wurde nicht gefunden", originalName)
		}
	}
	if err := config.Validate(); err != nil {
		return config, err
	}
	if err := nginxcfg.Save(nginxcfg.StatePath(zones.StateDir()), config); err != nil {
		return config, fmt.Errorf("Nginx-Desired-State konnte nicht gespeichert werden: %w", err)
	}
	return config, nil
}

func deleteNginxSite(config nginxcfg.Config, name string) (nginxcfg.Config, error) {
	if name == "" {
		return config, fmt.Errorf("Nginx-vHost zum Entfernen fehlt")
	}
	kept := make([]nginxcfg.Site, 0, len(config.Sites))
	found := false
	for _, site := range config.Sites {
		if strings.EqualFold(site.ServerNames[0], name) {
			found = true
			continue
		}
		kept = append(kept, site)
	}
	if !found {
		return config, fmt.Errorf("Nginx-vHost %q wurde nicht gefunden", name)
	}
	config.Sites = kept
	if err := nginxcfg.Save(nginxcfg.StatePath(zones.StateDir()), config); err != nil {
		return config, err
	}
	return config, nil
}

func splitNginxServerNames(value string) []string {
	return cleanFields(strings.FieldsFunc(value, func(character rune) bool {
		return character == ',' || character == ' ' || character == '\n' || character == '\t'
	}))
}

func nginxPageMap(page nginxPageData) map[string]any {
	return map[string]any{
		"Config": page.Config, "Sites": page.Sites, "Form": page.Form,
		"Preview": page.Preview, "Error": page.Error, "Success": page.Success,
	}
}

func loadNginxPage(editName, actionError, actionSuccess string) nginxPageData {
	config, err := nginxcfg.Load(nginxcfg.StatePath(zones.StateDir()))
	if err != nil {
		return nginxPage(nginxcfg.Config{Version: nginxcfg.CurrentVersion}, nginxForm{}, "Gespeicherte Nginx-Konfiguration ist ungültig: "+err.Error(), "")
	}
	form := nginxForm{Mode: "proxy"}
	if editName != "" {
		for _, site := range config.Sites {
			if strings.EqualFold(site.ServerNames[0], editName) {
				form = nginxForm{
					OriginalName: site.ServerNames[0],
					ServerNames:  strings.Join(site.ServerNames, ", "), Mode: site.Mode,
					Upstream: site.Upstream, DocumentRoot: site.DocumentRoot,
					TLS: site.TLSCertificate != "", Certificate: site.TLSCertificate, Key: site.TLSKey,
				}
				break
			}
		}
	}
	return nginxPage(config, form, actionError, actionSuccess)
}

func nginxPage(config nginxcfg.Config, form nginxForm, actionError, actionSuccess string) nginxPageData {
	page := nginxPageData{Config: config, Form: form, Error: actionError, Success: actionSuccess}
	for _, site := range config.Sites {
		target := site.Upstream
		if site.Mode == "static" {
			target = site.DocumentRoot
		}
		page.Sites = append(page.Sites, nginxSiteRow{
			Name: site.ServerNames[0], Names: strings.Join(site.ServerNames, ", "), Mode: site.Mode,
			Target: target, TLS: site.TLSCertificate != "",
		})
	}
	sort.Slice(page.Sites, func(i, j int) bool { return page.Sites[i].Name < page.Sites[j].Name })
	preview, err := nginxcfg.Generate(config)
	if err != nil {
		page.Error = err.Error()
	} else {
		page.Preview = string(preview)
	}
	return page
}
