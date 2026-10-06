package main

import (
	"embed"
	"encoding/json"
	"html/template"
	"io/fs"
	"log"
	"net/http"
	"net/url"
	"os"
	"path"
	"slices"
	"strings"

	"swat/internal/collect"
)

//go:embed web/templates/*.html
var templatesFS embed.FS

//go:embed web/static/*
var staticFS embed.FS

func statusClass(value string) string {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "active", "running", "laufend", "up", "enabled", "ok", "available", "verfügbar", "1":
		return "ok"
	case "inactive", "inaktiv", "nicht aktiv", "unknown", "unbekannt", "not-found", "missing", "fehlt", "unavailable", "nicht verfügbar", "down", "disabled", "0", "lokal", "virtuell", "stopped":
		return "muted"
	case "warning", "warn", "conflict", "konflikt", "änderungen gesperrt", "degraded", "paused":
		return "warn"
	case "failed", "failure", "error", "fail":
		return "fail"
	default:
		return ""
	}
}

func statusLabel(value string) string {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "running":
		return "laufend"
	case "stopped", "shut off", "shutoff":
		return "aus"
	case "inactive", "inaktiv", "nicht aktiv":
		return "inaktiv"
	case "unknown", "unbekannt":
		return "unbekannt"
	case "not-found", "missing":
		return "nicht gefunden"
	case "unavailable", "nicht verfügbar":
		return "nicht verfügbar"
	default:
		return value
	}
}

// pages holds one template set per page file; each is the shared layout plus that page's blocks.
var pages = loadPages()

func loadPages() map[string]*template.Template {
	funcs := template.FuncMap{
		"statusClass": statusClass,
		"statusLabel": statusLabel,
		"urlquery":    url.QueryEscape,
	}
	shared := []string{"layout.html", "nav.html", "partials.html"}
	sharedPaths := make([]string, len(shared))
	for i, name := range shared {
		sharedPaths[i] = "web/templates/" + name
	}
	base := template.Must(template.New("base").Funcs(funcs).ParseFS(templatesFS, sharedPaths...))
	files, err := fs.Glob(templatesFS, "web/templates/*.html")
	if err != nil {
		log.Fatal(err)
	}
	result := make(map[string]*template.Template, len(files))
	for _, file := range files {
		name := path.Base(file)
		if slices.Contains(shared, name) {
			continue
		}
		result[name] = template.Must(template.Must(base.Clone()).ParseFS(templatesFS, file))
	}
	return result
}

func main() {
	addr := os.Getenv("SWAT_ADDR")
	if addr == "" {
		addr = ":8443"
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/", handleOverview)
	mux.HandleFunc("/services", handleServices)
	mux.HandleFunc("/service", handleService)
	mux.HandleFunc("/storage", handleStorage)
	mux.HandleFunc("/vms", handleVMs)
	mux.HandleFunc("/vm", handleVM)
	mux.HandleFunc("/vm-create", handleVMCreate)
	mux.HandleFunc("/vm-action", handleVMAction)
	mux.HandleFunc("/vm-config", handleVMConfig)
	mux.HandleFunc("/vm-console", handleVMConsole)
	mux.HandleFunc("/vm-spice", handleVMSpice)
	mux.HandleFunc("/libvirt-resource-action", handleLibvirtResourceAction)
	mux.HandleFunc("/logs", handleLogs)
	mux.HandleFunc("/network", handleNetwork)
	mux.HandleFunc("/network-info", handleNetworkInfo)
	mux.HandleFunc("/firewall", handleFirewall)
	mux.Handle("/zones", http.RedirectHandler("/firewall", http.StatusMovedPermanently))
	mux.HandleFunc("/admin/zones/action", handleZonesAction)
	mux.HandleFunc("/admin/network/forwarding", handleNetworkForwarding)
	mux.HandleFunc("/admin/network/bridge", handleNetworkBridgeAction)
	mux.HandleFunc("/admin/system/setting", handleSystemSetting)
	mux.HandleFunc("/libvirt", handleLibvirt)
	mux.HandleFunc("/system", handleSystem)
	mux.HandleFunc("/users", handleUsers)
	mux.HandleFunc("/settings", handleSettings)
	mux.HandleFunc("/login", handleLogin)
	mux.HandleFunc("/logout", handleLogout)
	mux.HandleFunc("/admin/request-root", handleRootAccessRequest)
	mux.HandleFunc("/admin/restrict-root", handleRootAccessRestriction)
	mux.HandleFunc("/admin/users/create", handleCreateUser)
	mux.HandleFunc("/admin/users/delete", handleDeleteUser)
	mux.HandleFunc("/admin/users/expire-password", handleExpirePassword)
	mux.HandleFunc("/admin/users/group", handleChangeUserGroup)
	mux.HandleFunc("/admin/groups/create", handleCreateGroup)
	mux.HandleFunc("/admin/service-action", handleServiceAction)
	staticSub, err := fs.Sub(staticFS, "web/static")
	if err != nil {
		log.Fatal(err)
	}
	mux.Handle("/static/", http.StripPrefix("/static/", http.FileServer(http.FS(staticSub))))
	mux.HandleFunc("/api/units", handleAPIUnits)
	mux.HandleFunc("/api/network", handleAPINetwork)
	mux.HandleFunc("/api/nftables", handleAPINftables)
	mux.HandleFunc("/api/storage", handleAPIStorage)

	log.Printf("swat listening on %s", addr)
	if err := http.ListenAndServe(addr, requireLogin(mux)); err != nil {
		log.Fatal(err)
	}
}

func render(w http.ResponseWriter, r *http.Request, page, name string, data map[string]any) {
	if data == nil {
		data = map[string]any{}
	}
	data["Page"] = page
	auth := authData(r)
	data["Authenticated"] = auth.Authenticated
	data["Username"] = auth.Username
	data["RootRequested"] = auth.RootRequested
	data["RootAccess"] = auth.RootAccess
	data["AdminAccess"] = auth.AdminAccess
	data["CSRFToken"] = auth.CSRFToken
	set, ok := pages[name]
	if !ok {
		http.Error(w, "Template nicht gefunden: "+name, http.StatusInternalServerError)
		return
	}
	if err := set.ExecuteTemplate(w, name, data); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

func handleOverview(w http.ResponseWriter, r *http.Request) {
	system := collect.ReadSystemInfo()
	failed, err := collect.FailedUnits()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	ifaces, err := collect.Interfaces()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	ruleset, err := collect.ListRuleset()
	if err != nil {
		ruleset = &collect.Ruleset{}
	}
	ownership := collect.ServiceOwnerships()
	devices, err := collect.BlockDevices()
	storageSummary := collect.StorageSummary{}
	if err == nil {
		devices = collect.DisplayStorageDevices(devices)
		storageSummary = collect.SummarizeStorage(devices)
	}
	vmInventory, err := collect.VMs()
	if err != nil {
		vmInventory = collect.VMInventory{Hint: "VM-Status nicht verfügbar."}
	}

	render(w, r, "overview", "overview.html", map[string]any{
		"System":         system,
		"FailedUnits":    failed,
		"Interfaces":     ifaces,
		"Ruleset":        ruleset,
		"Ownership":      ownership,
		"Storage":        storageSummary,
		"StorageDevices": devices,
		"VMInventory":    vmInventory,
	})
}

func handleServices(w http.ResponseWriter, r *http.Request) {
	units, err := collect.Units("service")
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	render(w, r, "services", "services.html", map[string]any{"Units": units})
}

func handleService(w http.ResponseWriter, r *http.Request) {
	unit := r.URL.Query().Get("unit")
	detail, err := collect.UnitDetailFor(unit)
	if err != nil {
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}
	render(w, r, "service", "service.html", map[string]any{"Detail": detail})
}

func handleStorage(w http.ResponseWriter, r *http.Request) {
	devices, err := collect.BlockDevices()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	devices = collect.DisplayStorageDevices(devices)
	render(w, r, "storage", "storage.html", map[string]any{
		"Devices": devices,
		"Summary": collect.SummarizeStorage(devices),
	})
}

func handleVMs(w http.ResponseWriter, r *http.Request) {
	inventory, err := collect.VMs()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	render(w, r, "vms", "vms.html", vmPageData(r, inventory, nil))
}

func vmPageData(r *http.Request, inventory collect.VMInventory, extra map[string]any) map[string]any {
	libvirt := collect.LibvirtRuntimeStatus()
	details := collect.VMDetailsForList(inventory)
	data := map[string]any{
		"Inventory":      inventory,
		"VMDetails":      details,
		"Libvirt":        libvirt,
		"HostInterfaces": hostInterfaces(),
		"PoolISOs":       poolISOs(libvirt.Pools),
	}
	applyFlash(r, data)
	for key, value := range extra {
		data[key] = value
	}
	return vmAccessData(r, data)
}

func applyFlash(r *http.Request, data map[string]any) {
	if msg, ok := popFlash(r.URL.Query().Get("flash")); ok {
		data["VMActionError"] = msg.Error
		data["VMActionSuccess"] = msg.Success
	}
}

func poolISOs(pools [][]string) map[string][]collect.ISOFile {
	result := make(map[string][]collect.ISOFile)
	for _, pool := range pools {
		if len(pool) == 0 {
			continue
		}
		result[pool[0]] = collect.PoolISOs(pool[0])
	}
	return result
}

func hostInterfaces() []collect.Interface {
	interfaces, err := collect.Interfaces()
	if err != nil {
		return nil
	}
	return interfaces
}

func handleVM(w http.ResponseWriter, r *http.Request) {
	detail, err := collect.VMByName(r.URL.Query().Get("name"))
	if err != nil {
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}
	render(w, r, "vm", "vm.html", vmDetailData(r, detail, nil))
}

func vmDetailData(r *http.Request, detail collect.VMDetail, extra map[string]any) map[string]any {
	data := map[string]any{
		"Detail":         detail,
		"Libvirt":        collect.LibvirtRuntimeStatus(),
		"HostInterfaces": hostInterfaces(),
		"HostDevices":    collect.HostDevices(),
	}
	applyFlash(r, data)
	for key, value := range extra {
		data[key] = value
	}
	return vmAccessData(r, data)
}

func vmAccessData(r *http.Request, data map[string]any) map[string]any {
	if data == nil {
		data = map[string]any{}
	}
	auth := authData(r)
	reason := collect.ServiceRestriction("Virtualisierung", "libvirtd.service oder virtqemud.service", "libvirtd.service", "virtqemud.service")
	data["VMReadOnly"] = !auth.RootAccess || reason != ""
	data["VMReadOnlyReason"] = reason
	return data
}

func handleLogs(w http.ResponseWriter, r *http.Request) {
	query := r.URL.Query()
	levelsProvided := query.Has("info") || query.Has("warning") || query.Has("error")
	filter := collect.LogFilter{
		ShowInfo:    !levelsProvided || query.Get("info") == "1",
		ShowWarning: !levelsProvided || query.Get("warning") == "1",
		ShowError:   !levelsProvided || query.Get("error") == "1",
		Search:      strings.TrimSpace(query.Get("search")),
		Limit:       200,
	}
	if len(filter.Search) > 120 {
		filter.Search = filter.Search[:120]
	}
	entries, err := collect.RecentLogsFiltered(filter)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	render(w, r, "logs", "logs.html", map[string]any{"Entries": entries, "Filter": filter})
}

func handleNetworkInfo(w http.ResponseWriter, r *http.Request) {
	render(w, r, "network-info", "network-info.html", map[string]any{"NetworkInfo": collect.NetworkInventory()})
}

func handleLibvirt(w http.ResponseWriter, r *http.Request) {
	page := collect.LibvirtConfig(collect.LibvirtRuntimeStatus())
	if authData(r).RootAccess {
		page.ReadOnly = false
	}
	render(w, r, "libvirt", "config.html", map[string]any{"ConfigPage": page})
}

func handleSystem(w http.ResponseWriter, r *http.Request) {
	renderSystem(w, r, "", "")
}

func handleUsers(w http.ResponseWriter, r *http.Request) {
	render(w, r, "users", "users.html", map[string]any{"Accounts": collect.Accounts()})
}

func handleSettings(w http.ResponseWriter, r *http.Request) {
	render(w, r, "settings", "settings.html", nil)
}

func handleAPIUnits(w http.ResponseWriter, r *http.Request) {
	units, err := collect.Units("service")
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	writeJSON(w, units)
}

func handleAPINetwork(w http.ResponseWriter, r *http.Request) {
	ifaces, err := collect.Interfaces()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	writeJSON(w, ifaces)
}

func handleAPINftables(w http.ResponseWriter, r *http.Request) {
	ruleset, err := collect.ListRuleset()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	writeJSON(w, ruleset)
}

func handleAPIStorage(w http.ResponseWriter, r *http.Request) {
	devices, err := collect.BlockDevices()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	writeJSON(w, devices)
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(v); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}
