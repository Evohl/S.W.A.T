package main

import (
	"encoding/xml"
	"fmt"
	"html"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"

	"swat/internal/collect"
)

var vmNamePattern = regexp.MustCompile(`^[A-Za-z0-9._-]+$`)
var vmDiskTargetPattern = regexp.MustCompile(`^[A-Za-z0-9._-]+$`)

type vmCreateView struct {
	Libvirt         collect.LibvirtRuntime
	HostDevices     collect.HostDeviceInventory
	VMCreateError   string
	VMCreateSuccess string
}

func handleVMCreate(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		http.Redirect(w, r, "/vms", http.StatusSeeOther)
		return
	}
	if r.Method != http.MethodPost {
		http.Error(w, "Methode nicht erlaubt", http.StatusMethodNotAllowed)
		return
	}
	session, err := accountActionSession(r)
	if err != nil {
		renderVMCreateError(w, r, err.Error())
		return
	}
	if !session.RootAccess && !session.AdminAccess {
		renderVMCreateError(w, r, "Root-Zugriff erforderlich")
		return
	}
	name := strings.TrimSpace(r.FormValue("name"))
	if !vmNamePattern.MatchString(name) {
		renderVMCreateError(w, r, "Ungültiger VM-Name.")
		return
	}
	memory, err := parsePositiveInt(r.FormValue("memory"), 256)
	if err != nil {
		renderVMCreateError(w, r, "Ungültige Größe für Arbeitsspeicher.")
		return
	}
	vcpus, err := parsePositiveInt(r.FormValue("vcpus"), 1)
	if err != nil {
		renderVMCreateError(w, r, "Ungültige Anzahl virtueller CPUs.")
		return
	}
	diskGiB, err := parsePositiveInt(r.FormValue("disk_gib"), 20)
	if err != nil {
		renderVMCreateError(w, r, "Ungültige Größe für Festplatte.")
		return
	}
	iso := strings.TrimSpace(r.FormValue("iso"))
	if iso == "" {
		renderVMCreateError(w, r, "ISO-Image ist erforderlich.")
		return
	}
	network := strings.TrimSpace(r.FormValue("network"))
	if !validLibvirtNetwork(network) {
		renderVMCreateError(w, r, "Ungültige Netzwerk-Auswahl.")
		return
	}
	pool := strings.TrimSpace(r.FormValue("pool"))
	if pool == "" {
		renderVMCreateError(w, r, "Speicherpool ist erforderlich.")
		return
	}
	poolPath, err := libvirtPoolTargetPath(session.SudoPassword, pool)
	if err != nil {
		renderVMCreateError(w, r, "Speicherpool konnte nicht gelesen werden: "+err.Error())
		return
	}
	if poolPath == "" {
		poolPath = "/var/lib/libvirt/images"
	}
	if !filepath.IsAbs(poolPath) {
		renderVMCreateError(w, r, "Der Speicherpool muss einen absoluten Pfad liefern.")
		return
	}
	diskPath := filepath.Join(poolPath, name+".qcow2")
	if err := runAsRoot(session.SudoPassword, "mkdir", "-p", poolPath); err != nil {
		renderVMCreateError(w, r, "Speicherpool konnte nicht vorbereitet werden: "+err.Error())
		return
	}
	isoPath, err := stageVMISO(session.SudoPassword, iso, poolPath, name)
	if err != nil {
		renderVMCreateError(w, r, "ISO-Image konnte nicht in den Libvirt-Speicherpool kopiert werden: "+err.Error())
		return
	}
	if err := runAsRoot(session.SudoPassword, "qemu-img", "create", "-f", "qcow2", diskPath, fmt.Sprintf("%dG", diskGiB)); err != nil {
		renderVMCreateError(w, r, "Festplatte konnte nicht erstellt werden: "+err.Error())
		return
	}
	xmlPath, err := writeVMXML(name, memory, vcpus, isoPath, diskPath, network)
	if err != nil {
		renderVMCreateError(w, r, "VM-Definition konnte nicht erstellt werden: "+err.Error())
		return
	}
	defer os.Remove(xmlPath)
	if err := runAsRoot(session.SudoPassword, "virsh", "--connect", "qemu:///system", "define", xmlPath); err != nil {
		renderVMCreateError(w, r, "VM konnte nicht definiert werden: "+err.Error())
		return
	}
	if r.FormValue("start_after_create") != "" {
		if err := runAsRoot(session.SudoPassword, "virsh", "--connect", "qemu:///system", "start", name); err != nil {
			renderVMCreateError(w, r, "VM konnte nicht gestartet werden: "+err.Error())
			return
		}
	}
	http.Redirect(w, r, "/vm?name="+url.QueryEscape(name)+"&created=1", http.StatusSeeOther)
}

func renderVMCreateError(w http.ResponseWriter, r *http.Request, message string) {
	inventory, err := collect.VMs()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	render(w, r, "vms", "vms.html", vmPageData(r, inventory, map[string]any{"VMCreateError": message}))
}

func validLibvirtNetwork(name string) bool {
	if name == "none" {
		return true
	}
	if strings.HasPrefix(name, "bridge:") || strings.HasPrefix(name, "direct:") {
		parts := strings.SplitN(name, ":", 2)
		if len(parts) != 2 || parts[1] == "" {
			return false
		}
		for _, iface := range hostInterfaces() {
			if iface.Name == parts[1] && ((parts[0] == "bridge" && iface.IsBridge) || (parts[0] == "direct" && !iface.IsBridge && iface.Name != "lo")) {
				return true
			}
		}
		return false
	}
	for _, row := range collect.LibvirtRuntimeStatus().Networks {
		if len(row) > 0 && row[0] == name {
			return true
		}
	}
	return false
}

func handleLibvirtResourceAction(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Methode nicht erlaubt", http.StatusMethodNotAllowed)
		return
	}
	session, err := accountActionSession(r)
	if err != nil {
		renderLibvirtResourceAction(w, r, err.Error(), "")
		return
	}
	resource := r.FormValue("resource")
	name := strings.TrimSpace(r.FormValue("name"))
	action := r.FormValue("action")
	if resource == "pool-create" {
		handleLibvirtPoolCreate(w, r, session)
		return
	}
	if resource == "iso-delete" {
		if !vmNamePattern.MatchString(name) {
			renderLibvirtResourceAction(w, r, "Ungültiger Speicherpool.", "")
			return
		}
		isoName := filepath.Base(strings.TrimSpace(r.FormValue("iso")))
		if isoName == "." || isoName == ".." || filepath.Ext(isoName) == "" || !strings.EqualFold(filepath.Ext(isoName), ".iso") {
			renderLibvirtResourceAction(w, r, "Ungültiges ISO-Image.", "")
			return
		}
		poolPath, pathErr := libvirtPoolTargetPath(session.SudoPassword, name)
		if pathErr != nil || poolPath == "" {
			renderLibvirtResourceAction(w, r, "Speicherpool konnte nicht gelesen werden.", "")
			return
		}
		isoPath := filepath.Join(poolPath, isoName)
		if err := runAsRoot(session.SudoPassword, "rm", "-f", "--", isoPath); err != nil {
			renderLibvirtResourceAction(w, r, "ISO-Image konnte nicht gelöscht werden: "+err.Error(), "")
			return
		}
		renderLibvirtResourceAction(w, r, "", "ISO-Image gelöscht.")
		return
	}
	if !vmNamePattern.MatchString(name) {
		renderLibvirtResourceAction(w, r, "Ungültiger Libvirt-Name.", "")
		return
	}
	var command []string
	var success string
	switch resource {
	case "pool":
		switch action {
		case "start":
			command = []string{"virsh", "--connect", "qemu:///system", "pool-start", name}
			success = "Speicherpool gestartet."
		case "stop":
			command = []string{"virsh", "--connect", "qemu:///system", "pool-destroy", name}
			success = "Speicherpool gestoppt."
		default:
			renderLibvirtResourceAction(w, r, "Ungültige Speicherpool-Aktion.", "")
			return
		}
	case "network":
		switch action {
		case "start":
			command = []string{"virsh", "--connect", "qemu:///system", "net-start", name}
			success = "Virtuelles Netzwerk gestartet."
		case "stop":
			command = []string{"virsh", "--connect", "qemu:///system", "net-destroy", name}
			success = "Virtuelles Netzwerk gestoppt."
		default:
			renderLibvirtResourceAction(w, r, "Ungültige Netzwerk-Aktion.", "")
			return
		}
	default:
		renderLibvirtResourceAction(w, r, "Ungültiger Libvirt-Bereich.", "")
		return
	}
	if err := runAsRoot(session.SudoPassword, command...); err != nil {
		renderLibvirtResourceAction(w, r, "Libvirt-Aktion fehlgeschlagen: "+err.Error(), "")
		return
	}
	renderLibvirtResourceAction(w, r, "", success)
}

func renderVMResourceAction(w http.ResponseWriter, r *http.Request, actionError, actionSuccess string) {
	inventory, err := collect.VMs()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	render(w, r, "vms", "vms.html", vmPageData(r, inventory, map[string]any{
		"VMActionError":   actionError,
		"VMActionSuccess": actionSuccess,
	}))
}

func handleLibvirtPoolCreate(w http.ResponseWriter, r *http.Request, session authSession) {
	name := strings.TrimSpace(r.FormValue("pool_name"))
	path := strings.TrimSpace(r.FormValue("pool_path"))
	if !vmNamePattern.MatchString(name) {
		renderLibvirtResourceAction(w, r, "Ungültiger Speicherpool-Name.", "")
		return
	}
	if !filepath.IsAbs(path) || strings.Contains(path, "..") {
		renderLibvirtResourceAction(w, r, "Der Speicherpfad muss absolut sein und darf kein '..' enthalten.", "")
		return
	}
	if err := runAsRoot(session.SudoPassword, "virsh", "--connect", "qemu:///system", "pool-define-as", name, "dir", "--target", path); err != nil {
		renderLibvirtResourceAction(w, r, "Speicherpool konnte nicht definiert werden: "+err.Error(), "")
		return
	}
	if err := runAsRoot(session.SudoPassword, "virsh", "--connect", "qemu:///system", "pool-build", name); err != nil {
		renderLibvirtResourceAction(w, r, "Speicherpool konnte nicht vorbereitet werden: "+err.Error(), "")
		return
	}
	if err := runAsRoot(session.SudoPassword, "virsh", "--connect", "qemu:///system", "pool-start", name); err != nil {
		renderLibvirtResourceAction(w, r, "Speicherpool konnte nicht gestartet werden: "+err.Error(), "")
		return
	}
	renderLibvirtResourceAction(w, r, "", "Speicherpool "+name+" wurde angelegt.")
}

func renderLibvirtResourceAction(w http.ResponseWriter, r *http.Request, actionError, actionSuccess string) {
	inventory, err := collect.VMs()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	render(w, r, "vms", "vms.html", vmPageData(r, inventory, map[string]any{
		"VMActionError":   actionError,
		"VMActionSuccess": actionSuccess,
	}))
}
func handleVMAction(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Methode nicht erlaubt", http.StatusMethodNotAllowed)
		return
	}
	name := strings.TrimSpace(r.FormValue("name"))
	returnTo := r.FormValue("return_to")
	redirectWithFlash := func(actionError, actionSuccess string) {
		token := setFlash(actionError, actionSuccess)
		if returnTo == "detail" && vmNamePattern.MatchString(name) {
			http.Redirect(w, r, "/vm?name="+url.QueryEscape(name)+"&flash="+token, http.StatusSeeOther)
			return
		}
		http.Redirect(w, r, "/vms?flash="+token, http.StatusSeeOther)
	}
	session, err := accountActionSession(r)
	if err != nil {
		redirectWithFlash(err.Error(), "")
		return
	}
	if !vmNamePattern.MatchString(name) {
		redirectWithFlash("Ungültiger VM-Name.", "")
		return
	}
	renderAction := redirectWithFlash
	action := r.FormValue("action")
	var command []string
	var success string
	switch action {
	case "start":
		if err := repairVMGraphics(session.SudoPassword, name); err != nil {
			renderAction("VM-Definition konnte nicht repariert werden: "+err.Error(), "")
			return
		}
		if err := repairVMConsole(session.SudoPassword, name); err != nil {
			renderAction("Serielle VM-Konsole konnte nicht eingerichtet werden: "+err.Error(), "")
			return
		}
		if err := repairVMISO(session.SudoPassword, name); err != nil {
			renderAction("ISO-Referenz konnte nicht repariert werden: "+err.Error(), "")
			return
		}
		command = []string{"virsh", "--connect", "qemu:///system", "start", name}
		success = "VM gestartet."
	case "stop":
		command = []string{"virsh", "--connect", "qemu:///system", "shutdown", name}
		success = "Herunterfahren angefordert. Das Gastbetriebssystem muss das Signal noch verarbeiten, bis der Status auf gestoppt wechselt."
	case "force-stop":
		command = []string{"virsh", "--connect", "qemu:///system", "destroy", name}
		success = "VM wurde zwangsweise gestoppt."
	case "restart":
		command = []string{"virsh", "--connect", "qemu:///system", "reboot", name}
		success = "VM neu gestartet."
	case "eject-media":
		detail, detailErr := collect.VMByName(name)
		if detailErr != nil {
			renderAction(detailErr.Error(), "")
			return
		}
		if detail.State != "stopped" {
			renderAction("Das Installationsmedium kann nur bei ausgeschalteter VM ausgehängt werden.", "")
			return
		}
		target := strings.TrimSpace(r.FormValue("target"))
		if !vmDiskTargetPattern.MatchString(target) {
			renderAction("Ungültiges Installationsmedium.", "")
			return
		}
		command = []string{"virsh", "--connect", "qemu:///system", "change-media", name, target, "--eject", "--config"}
		success = "Installationsmedium ausgehängt."
	case "delete":
		detail, detailErr := collect.VMByName(name)
		if detailErr != nil {
			renderAction(detailErr.Error(), "")
			return
		}
		if detail.State != "stopped" {
			renderAction("Eine laufende VM kann nicht gelöscht werden.", "")
			return
		}
		command = []string{"virsh", "--connect", "qemu:///system", "undefine", name, "--nvram"}
		success = "VM gelöscht. Die virtuellen Festplatten wurden nicht entfernt."
	default:
		renderAction("Ungültige VM-Aktion.", "")
		return
	}
	if err := runAsRoot(session.SudoPassword, command...); err != nil {
		renderAction("VM-Aktion fehlgeschlagen: "+err.Error(), "")
		return
	}
	renderAction("", success)
}

func repairVMGraphics(password, name string) error {
	xmlData, err := runAsRootCapture(password, "virsh", "--connect", "qemu:///system", "dumpxml", name)
	if err != nil {
		return err
	}
	fixedXML := strings.ReplaceAll(xmlData, "listen='none'", "listen='127.0.0.1'")
	fixedXML = strings.ReplaceAll(fixedXML, `listen="none"`, `listen="127.0.0.1"`)
	if fixedXML == xmlData {
		return nil
	}
	path, err := writeHostDeviceXML(fixedXML)
	if err != nil {
		return err
	}
	defer os.Remove(path)
	return runAsRoot(password, "virsh", "--connect", "qemu:///system", "define", path)
}

func repairVMConsole(password, name string) error {
	xmlData, err := runAsRootCapture(password, "virsh", "--connect", "qemu:///system", "dumpxml", name)
	if err != nil {
		return err
	}
	fixedXML := xmlData
	if strings.Contains(fixedXML, "<console type='pty'/>") {
		fixedXML = strings.Replace(fixedXML, "<console type='pty'/>", "<console type='pty'>\n      <target type='serial' port='0'/>\n    </console>", 1)
	}
	if !strings.Contains(fixedXML, "<serial ") {
		fixedXML = strings.Replace(fixedXML, "</devices>", "<serial type='pty'>\n      <target type='isa-serial' port='0'/>\n    </serial>\n  </devices>", 1)
	}
	if fixedXML == xmlData {
		return nil
	}
	path, err := writeHostDeviceXML(fixedXML)
	if err != nil {
		return err
	}
	defer os.Remove(path)
	return runAsRoot(password, "virsh", "--connect", "qemu:///system", "define", path)
}

func stageVMISO(password, source, poolPath, name string) (string, error) {
	if !filepath.IsAbs(source) {
		return "", fmt.Errorf("der ISO-Pfad muss absolut sein")
	}
	destination := filepath.Join(poolPath, name+"-installer.iso")
	if filepath.Clean(source) == filepath.Clean(destination) {
		return destination, nil
	}
	if err := runAsRoot(password, "cp", "--", source, destination); err != nil {
		return "", err
	}
	return destination, nil
}

func repairVMISO(password, name string) error {
	xmlData, err := runAsRootCapture(password, "virsh", "--connect", "qemu:///system", "dumpxml", name)
	if err != nil {
		return err
	}
	var definition struct {
		Devices struct {
			Disks []struct {
				Device string `xml:"device,attr"`
				Source struct {
					File string `xml:"file,attr"`
				} `xml:"source"`
			} `xml:"disk"`
		} `xml:"devices"`
	}
	if err := xml.Unmarshal([]byte(xmlData), &definition); err != nil {
		return err
	}
	isoSource := ""
	poolPath := "/var/lib/libvirt/images"
	for _, disk := range definition.Devices.Disks {
		if disk.Device == "cdrom" && disk.Source.File != "" {
			isoSource = disk.Source.File
		}
		if disk.Device == "disk" && disk.Source.File != "" {
			poolPath = filepath.Dir(disk.Source.File)
		}
	}
	if isoSource == "" || !filepath.IsAbs(isoSource) || filepath.Dir(isoSource) == poolPath {
		return nil
	}
	destination, err := stageVMISO(password, isoSource, poolPath, name)
	if err != nil {
		return err
	}
	fixedXML := strings.Replace(xmlData, "file='"+isoSource+"'", "file='"+destination+"'", 1)
	fixedXML = strings.Replace(fixedXML, `file="`+isoSource+`"`, `file="`+destination+`"`, 1)
	if fixedXML == xmlData {
		return nil
	}
	path, err := writeHostDeviceXML(fixedXML)
	if err != nil {
		return err
	}
	defer os.Remove(path)
	return runAsRoot(password, "virsh", "--connect", "qemu:///system", "define", path)
}

func handleVMConfig(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Methode nicht erlaubt", http.StatusMethodNotAllowed)
		return
	}
	session, err := accountActionSession(r)
	name := strings.TrimSpace(r.FormValue("name"))
	if err != nil {
		renderVMConfigAction(w, r, name, err.Error(), "")
		return
	}
	if !vmNamePattern.MatchString(name) {
		renderVMConfigAction(w, r, name, "Ungültiger VM-Name.", "")
		return
	}
	detail, err := collect.VMByName(name)
	if err != nil {
		renderVMConfigAction(w, r, name, err.Error(), "")
		return
	}
	if detail.State != "stopped" {
		renderVMConfigAction(w, r, name, "Die VM-Konfiguration kann nur geändert werden, wenn die VM ausgeschaltet ist.", "")
		return
	}
	vcpus, err := parsePositiveInt(r.FormValue("vcpus"), 0)
	if err != nil || vcpus < 1 || vcpus > 256 {
		renderVMConfigAction(w, r, name, "Die Anzahl der CPU-Kerne muss zwischen 1 und 256 liegen.", "")
		return
	}
	memory, err := parsePositiveInt(r.FormValue("memory"), 0)
	if err != nil || memory < 256 || memory > 1048576 {
		renderVMConfigAction(w, r, name, "Der Arbeitsspeicher muss zwischen 256 und 1048576 MiB liegen.", "")
		return
	}
	network := strings.TrimSpace(r.FormValue("network"))
	if !validLibvirtNetwork(network) {
		renderVMConfigAction(w, r, name, "Ungültige Netzwerk-Auswahl.", "")
		return
	}
	if err := runAsRoot(session.SudoPassword, "virsh", "--connect", "qemu:///system", "setmaxmem", name, fmt.Sprintf("%dMiB", memory), "--config"); err != nil {
		renderVMConfigAction(w, r, name, "Arbeitsspeicher konnte nicht gesetzt werden: "+err.Error(), "")
		return
	}
	if err := runAsRoot(session.SudoPassword, "virsh", "--connect", "qemu:///system", "setmem", name, fmt.Sprintf("%dMiB", memory), "--config"); err != nil {
		renderVMConfigAction(w, r, name, "Arbeitsspeicher konnte nicht gesetzt werden: "+err.Error(), "")
		return
	}
	if err := runAsRoot(session.SudoPassword, "virsh", "--connect", "qemu:///system", "setvcpus", name, strconv.Itoa(vcpus), "--maximum", "--config"); err != nil {
		renderVMConfigAction(w, r, name, "Maximale CPU-Anzahl konnte nicht gesetzt werden: "+err.Error(), "")
		return
	}
	if err := runAsRoot(session.SudoPassword, "virsh", "--connect", "qemu:///system", "setvcpus", name, strconv.Itoa(vcpus), "--config"); err != nil {
		renderVMConfigAction(w, r, name, "CPU-Kerne konnten nicht gesetzt werden: "+err.Error(), "")
		return
	}
	if network != detail.NetworkSelection {
		if len(detail.Networks) > 0 {
			if err := runAsRoot(session.SudoPassword, "virsh", "--connect", "qemu:///system", "detach-interface", name, "network", "--config"); err != nil {
				renderVMConfigAction(w, r, name, "Netzwerkadapter konnte nicht entfernt werden: "+err.Error(), "")
				return
			}
		}
		if network != "none" {
			adapterType, source := vmNetworkArguments(network)
			if err := runAsRoot(session.SudoPassword, "virsh", "--connect", "qemu:///system", "attach-interface", name, adapterType, source, "--model", "virtio", "--config"); err != nil {
				renderVMConfigAction(w, r, name, "Netzwerkadapter konnte nicht eingerichtet werden: "+err.Error(), "")
				return
			}
		}
	}
	selected := make(map[string]bool)
	for _, deviceName := range r.Form["host_devices"] {
		selected[deviceName] = true
	}
	for _, option := range detail.HostDeviceOptions {
		if option.Attached == selected[option.Name] {
			continue
		}
		path, writeErr := writeHostDeviceXML(option.XML)
		if writeErr != nil {
			renderVMConfigAction(w, r, name, "Hostgerät konnte nicht vorbereitet werden: "+writeErr.Error(), "")
			return
		}
		command := "attach-device"
		if option.Attached {
			command = "detach-device"
		}
		deviceErr := runAsRoot(session.SudoPassword, "virsh", "--connect", "qemu:///system", command, name, path, "--config")
		os.Remove(path)
		if deviceErr != nil {
			renderVMConfigAction(w, r, name, "Hostgerät konnte nicht durchgereicht werden: "+deviceErr.Error(), "")
			return
		}
	}
	renderVMConfigAction(w, r, name, "", "VM-Konfiguration gespeichert.")
}

func vmNetworkArguments(network string) (string, string) {
	switch {
	case strings.HasPrefix(network, "bridge:"):
		return "bridge", strings.TrimPrefix(network, "bridge:")
	case strings.HasPrefix(network, "direct:"):
		return "direct", strings.TrimPrefix(network, "direct:")
	default:
		return "network", network
	}
}

func writeHostDeviceXML(content string) (string, error) {
	file, err := os.CreateTemp("", "swat-hostdev-*.xml")
	if err != nil {
		return "", err
	}
	path := file.Name()
	if _, err := file.WriteString(content); err != nil {
		file.Close()
		os.Remove(path)
		return "", err
	}
	if err := file.Close(); err != nil {
		os.Remove(path)
		return "", err
	}
	return path, nil
}

func renderVMConfigAction(w http.ResponseWriter, r *http.Request, name, actionError, actionSuccess string) {
	detail, err := collect.VMByName(name)
	if err != nil {
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}
	render(w, r, "vm", "vm.html", vmDetailData(r, detail, map[string]any{
		"VMActionError":   actionError,
		"VMActionSuccess": actionSuccess,
	}))
}

func vmCreateData(extra *vmCreateView) map[string]any {
	data := map[string]any{
		"Libvirt":     collect.LibvirtRuntimeStatus(),
		"HostDevices": collect.HostDevices(),
	}
	if extra != nil {
		data["VMCreateError"] = extra.VMCreateError
		data["VMCreateSuccess"] = extra.VMCreateSuccess
	}
	return data
}

func parsePositiveInt(value string, fallback int) (int, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return fallback, nil
	}
	parsed, err := strconv.Atoi(value)
	if err != nil || parsed <= 0 {
		return 0, fmt.Errorf("ungültiger Wert")
	}
	return parsed, nil
}

func libvirtPoolTargetPath(password, pool string) (string, error) {
	output, err := runAsRootCapture(password, "virsh", "--connect", "qemu:///system", "pool-dumpxml", pool)
	if err != nil {
		return "", err
	}
	type targetXML struct {
		Target struct {
			Path string `xml:"path"`
		} `xml:"target"`
	}
	var parsed targetXML
	if err := xml.Unmarshal([]byte(output), &parsed); err != nil {
		return "", err
	}
	return strings.TrimSpace(parsed.Target.Path), nil
}

func writeVMXML(name string, memory, vcpus int, isoPath, diskPath, network string) (string, error) {
	networkXML := ""
	if network == "default" {
		networkXML = "\n    <interface type='network'>\n      <source network='default'/>\n      <model type='virtio'/>\n    </interface>"
	} else if strings.HasPrefix(network, "bridge:") {
		iface := html.EscapeString(strings.TrimPrefix(network, "bridge:"))
		networkXML = fmt.Sprintf("\n    <interface type='bridge'>\n      <source bridge='%s'/>\n      <model type='virtio'/>\n    </interface>", iface)
	} else if strings.HasPrefix(network, "direct:") {
		iface := html.EscapeString(strings.TrimPrefix(network, "direct:"))
		networkXML = fmt.Sprintf("\n    <interface type='direct'>\n      <source dev='%s' mode='bridge'/>\n      <model type='virtio'/>\n    </interface>", iface)
	} else if network != "" && network != "none" {
		networkXML = fmt.Sprintf("\n    <interface type='network'>\n      <source network='%s'/>\n      <model type='virtio'/>\n    </interface>", html.EscapeString(network))
	}
	const templateXML = `<?xml version="1.0" encoding="UTF-8"?>
<domain type='qemu'>
  <name>%s</name>
  <memory unit='MiB'>%d</memory>
  <currentMemory unit='MiB'>%d</currentMemory>
  <vcpu placement='static'>%d</vcpu>
  <os>
    <type arch='x86_64' machine='pc'>hvm</type>
    <boot dev='cdrom'/>
    <boot dev='hd'/>
  </os>
  <features>
    <acpi/>
    <apic/>
    <pae/>
  </features>
  <devices>
    <emulator>/usr/bin/qemu-system-x86_64</emulator>
    <disk type='file' device='disk'>
      <driver name='qemu' type='qcow2'/>
      <source file='%s'/>
      <target dev='vda' bus='virtio'/>
    </disk>
    <disk type='file' device='cdrom'>
      <driver name='qemu' type='raw'/>
      <source file='%s'/>
      <target dev='sda' bus='sata'/>
      <readonly/>
    </disk>
	<graphics type='spice' autoport='yes' listen='127.0.0.1'/>
	<serial type='pty'>
			<target type='isa-serial' port='0'/>
		</serial>
		<console type='pty'>
			<target type='serial' port='0'/>
		</console>
%s
	</devices>
</domain>`
	content := fmt.Sprintf(templateXML, html.EscapeString(name), memory, memory, vcpus, html.EscapeString(diskPath), html.EscapeString(isoPath), networkXML)
	file, err := os.CreateTemp("", "swat-vm-*.xml")
	if err != nil {
		return "", err
	}
	if _, err := file.WriteString(content); err != nil {
		file.Close()
		return "", err
	}
	if err := file.Close(); err != nil {
		return "", err
	}
	return file.Name(), nil
}

func runAsRootCapture(password string, args ...string) (string, error) {
	if readOnlyMode() {
		return "", fmt.Errorf("diese Installation läuft ausdrücklich im Read-only-Modus")
	}
	if password == "" {
		return "", fmt.Errorf("kein Sudo-Passwort in der Sitzung vorhanden")
	}
	command := exec.Command("sudo", append([]string{"-S", "-p", "", "--", "env", "LC_ALL=C", "LANG=C"}, args...)...)
	command.Stdin = strings.NewReader(password + "\n")
	output, err := command.CombinedOutput()
	if err != nil {
		message := strings.TrimSpace(string(output))
		if message == "" {
			message = err.Error()
		}
		return "", fmt.Errorf("%s", message)
	}
	return strings.TrimSpace(string(output)), nil
}
