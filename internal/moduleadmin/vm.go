package moduleadmin

import (
	"context"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"

	"swat/internal/collect"
)

var libvirtNamePattern = regexp.MustCompile(`^[A-Za-z0-9._-]+$`)

func (installer *Installer) VMAction(ctx context.Context, action, target, value, value2, value3, value4 string) (Response, error) {
	installer.mu.Lock()
	defer installer.mu.Unlock()
	if installer.Run == nil {
		installer.Run = SystemRunner
	}
	command, args, err := vmActionCommand(action, target, value, value2, value3, value4)
	if err != nil {
		return Response{}, err
	}
	if command == "virsh-define-xml" {
		if !validDomainXML(value, target) {
			return Response{}, errors.New("Ungültige VM-Definition.")
		}
		file, err := os.CreateTemp("/var/lib/swat", "domain-*.xml")
		if err != nil {
			return Response{}, err
		}
		path := file.Name()
		defer os.Remove(path)
		if _, err := file.WriteString(value); err != nil {
			file.Close()
			return Response{}, err
		}
		if err := file.Close(); err != nil {
			return Response{}, err
		}
		output, runErr := installer.Run(ctx, "virsh", "--connect", "qemu:///system", "define", path)
		if runErr != nil {
			return Response{}, fmt.Errorf("VM konnte nicht definiert werden: %s", summarize(output, runErr))
		}
		return Response{OK: true}, nil
	}
	if command == "virsh-dumpxml" || command == "virsh-pool-dumpxml" {
		output, runErr := installer.Run(ctx, "virsh", args...)
		if runErr != nil {
			return Response{}, fmt.Errorf("Libvirt-Abfrage fehlgeschlagen: %s", summarize(output, runErr))
		}
		return Response{OK: true, Output: string(output)}, nil
	}
	if command == "qemu-img-create" {
		poolPath, err := installer.poolPath(ctx, target)
		if err != nil {
			return Response{}, err
		}
		diskPath := filepath.Join(poolPath, value+".qcow2")
		output, runErr := installer.Run(ctx, "qemu-img", "create", "-f", "qcow2", diskPath, value2+"G")
		if runErr != nil {
			return Response{}, fmt.Errorf("Virtuelle Festplatte konnte nicht erstellt werden: %s", summarize(output, runErr))
		}
		return Response{OK: true}, nil
	}
	if command == "copy-iso" {
		poolPath, err := installer.poolPath(ctx, target)
		if err != nil {
			return Response{}, err
		}
		if !safeISOPath(value2) || !libvirtNamePattern.MatchString(value) {
			return Response{}, errors.New("ISO-Quelle muss eine ISO-Datei unter /var/lib/libvirt/images sein.")
		}
		info, err := os.Stat(value2)
		if err != nil || !info.Mode().IsRegular() {
			return Response{}, errors.New("ISO-Quelle ist keine reguläre Datei.")
		}
		destination := filepath.Join(poolPath, value+"-installer.iso")
		if filepath.Clean(value2) == destination {
			return Response{OK: true, Output: destination}, nil
		}
		if output, err := installer.Run(ctx, "cp", "--", value2, destination); err != nil {
			return Response{}, fmt.Errorf("ISO konnte nicht in den Speicherpool kopiert werden: %s", summarize(output, err))
		}
		return Response{OK: true, Output: destination}, nil
	}
	if command == "copy-iso-path" {
		if !safeISOPath(value) || !safeISOPath(value2) {
			return Response{}, errors.New("ISO-Quelle und Ziel müssen im erlaubten Libvirt-Speicherbereich liegen.")
		}
		info, err := os.Stat(value)
		if err != nil || !info.Mode().IsRegular() {
			return Response{}, errors.New("ISO-Quelle ist keine reguläre Datei.")
		}
		if output, err := installer.Run(ctx, "cp", "--", value, value2); err != nil {
			return Response{}, fmt.Errorf("ISO konnte nicht verschoben werden: %s", summarize(output, err))
		}
		return Response{OK: true}, nil
	}
	if command == "copy-iso-path" {
		if !safeISOPath(value) || !safeISOPath(value2) {
			return Response{}, errors.New("ISO-Quelle und Ziel müssen im erlaubten Libvirt-Speicherbereich liegen.")
		}
		info, err := os.Stat(value)
		if err != nil || !info.Mode().IsRegular() {
			return Response{}, errors.New("ISO-Quelle ist keine reguläre Datei.")
		}
		if output, err := installer.Run(ctx, "cp", "--", value, value2); err != nil {
			return Response{}, fmt.Errorf("ISO konnte nicht verschoben werden: %s", summarize(output, err))
		}
		return Response{OK: true}, nil
	}
	if command == "delete-iso" {
		poolPath, err := installer.poolPath(ctx, target)
		if err != nil {
			return Response{}, err
		}
		path := filepath.Join(poolPath, value)
		if !safeISOPath(path) || filepath.Dir(filepath.Clean(path)) != filepath.Clean(poolPath) {
			return Response{}, errors.New("Ungültiges ISO-Ziel.")
		}
		if err := os.Remove(path); err != nil {
			return Response{}, err
		}
		return Response{OK: true}, nil
	}
	if command == "device-xml" {
		if !validHostDeviceXML(value2) || !knownHostDeviceXML(value2) || (value != "attach" && value != "detach") {
			return Response{}, errors.New("Ungültige Hostgeräte-Konfiguration.")
		}
		file, err := os.CreateTemp("/var/lib/swat", "hostdev-*.xml")
		if err != nil {
			return Response{}, err
		}
		path := file.Name()
		defer os.Remove(path)
		if _, err := file.WriteString(value2); err != nil {
			file.Close()
			return Response{}, err
		}
		if err := file.Close(); err != nil {
			return Response{}, err
		}
		verb := value + "-device"
		args := []string{"--connect", "qemu:///system", verb, target, path, "--config"}
		output, err := installer.Run(ctx, "virsh", args...)
		if err != nil {
			return Response{}, fmt.Errorf("Hostgerät konnte nicht geändert werden: %s", summarize(output, err))
		}
		return Response{OK: true}, nil
	}
	if command != "virsh" {
		return Response{}, errors.New("Unbekannte Libvirt-Aktion.")
	}
	output, runErr := installer.Run(ctx, command, args...)
	if runErr != nil {
		return Response{}, fmt.Errorf("Libvirt-Aktion fehlgeschlagen: %s", summarize(output, runErr))
	}
	return Response{OK: true, Output: string(output)}, nil
}

func vmActionCommand(action, target, value, value2, value3, value4 string) (string, []string, error) {
	if target != "" && !libvirtNamePattern.MatchString(target) {
		return "", nil, errors.New("Ungültiger Libvirt-Name.")
	}
	base := []string{"--connect", "qemu:///system"}
	switch action {
	case "vm-start", "vm-stop", "vm-force-stop", "vm-restart", "vm-delete":
		verb := map[string]string{"vm-start": "start", "vm-stop": "shutdown", "vm-force-stop": "destroy", "vm-restart": "reboot", "vm-delete": "undefine"}[action]
		args := append(base, verb, target)
		if action == "vm-delete" {
			args = append(args, "--nvram")
		}
		return "virsh", args, nil
	case "vm-eject-media":
		if !libvirtNamePattern.MatchString(value) {
			return "", nil, errors.New("Ungültiges Medienziel.")
		}
		return "virsh", append(base, "change-media", target, value, "--eject", "--config"), nil
	case "libvirt-pool-start", "libvirt-pool-stop", "libvirt-network-start", "libvirt-network-stop":
		verb := map[string]string{"libvirt-pool-start": "pool-start", "libvirt-pool-stop": "pool-destroy", "libvirt-network-start": "net-start", "libvirt-network-stop": "net-destroy"}[action]
		return "virsh", append(base, verb, target), nil
	case "libvirt-pool-create":
		if !safeLibvirtStoragePath(value) {
			return "", nil, errors.New("Speicherpool-Ziel muss unter /var/lib/libvirt/images liegen.")
		}
		return "virsh", append(base, "pool-define-as", target, "dir", "--target", value), nil
	case "libvirt-pool-build", "libvirt-pool-activate":
		verb := "pool-build"
		if action == "libvirt-pool-activate" {
			verb = "pool-start"
		}
		return "virsh", append(base, verb, target), nil
	case "vm-define":
		return "virsh-define-xml", nil, nil
	case "vm-dumpxml":
		return "virsh-dumpxml", append(base, "dumpxml", target), nil
	case "libvirt-pool-dumpxml":
		return "virsh-pool-dumpxml", append(base, "pool-dumpxml", target), nil
	case "vm-disk-create":
		size, err := strconv.Atoi(value2)
		if !libvirtNamePattern.MatchString(value) || err != nil || size < 10 || size > 1048576 {
			return "", nil, errors.New("Ungültige Festplattenparameter.")
		}
		return "qemu-img-create", nil, nil
	case "vm-iso-stage":
		if !libvirtNamePattern.MatchString(value) || !safeISOPath(value2) {
			return "", nil, errors.New("Ungültige ISO-Quelle oder VM.")
		}
		return "copy-iso", nil, nil
	case "vm-iso-delete":
		if filepath.Base(value) != value || !strings.EqualFold(filepath.Ext(value), ".iso") {
			return "", nil, errors.New("Ungültiger ISO-Dateiname.")
		}
		return "delete-iso", nil, nil
	case "vm-iso-copy":
		if !safeISOPath(value) || !safeISOPath(value2) {
			return "", nil, errors.New("Ungültige ISO-Quelle oder Ziel.")
		}
		return "copy-iso-path", nil, nil
	case "vm-device-attach":
		return "device-xml", nil, nil
	case "vm-config-memory":
		memory, err := strconv.Atoi(value)
		if err != nil || memory < 256 || memory > 1048576 {
			return "", nil, errors.New("Ungültige Speichergröße.")
		}
		return "virsh", append(base, "setmaxmem", target, fmt.Sprintf("%dMiB", memory), "--config"), nil
	case "vm-config-memory-current":
		memory, err := strconv.Atoi(value)
		if err != nil || memory < 256 || memory > 1048576 {
			return "", nil, errors.New("Ungültige Speichergröße.")
		}
		return "virsh", append(base, "setmem", target, fmt.Sprintf("%dMiB", memory), "--config"), nil
	case "vm-config-cpus-max", "vm-config-cpus":
		cpus, err := strconv.Atoi(value)
		if err != nil || cpus < 1 || cpus > 256 {
			return "", nil, errors.New("Ungültige CPU-Anzahl.")
		}
		args := append(base, "setvcpus", target, strconv.Itoa(cpus))
		if action == "vm-config-cpus-max" {
			args = append(args, "--maximum")
		}
		return "virsh", append(args, "--config"), nil
	case "vm-interface-detach":
		return "virsh", append(base, "detach-interface", target, "network", "--config"), nil
	case "vm-interface-attach":
		adapterType, source, err := vmNetworkSource(value, value2)
		if err != nil {
			return "", nil, err
		}
		return "virsh", append(base, "attach-interface", target, adapterType, source, "--model", "virtio", "--config"), nil
	default:
		return "", nil, errors.New("Unbekannte Libvirt-Aktion.")
	}
}

func vmNetworkSource(adapterType, source string) (string, string, error) {
	if adapterType != "network" && adapterType != "bridge" && adapterType != "direct" {
		return "", "", errors.New("Ungültiger Netzwerkadapter-Typ.")
	}
	if !libvirtNamePattern.MatchString(source) {
		return "", "", errors.New("Ungültige Netzwerkquelle.")
	}
	return adapterType, source, nil
}

func (installer *Installer) poolPath(ctx context.Context, pool string) (string, error) {
	if !libvirtNamePattern.MatchString(pool) {
		return "", errors.New("Ungültiger Speicherpool.")
	}
	output, err := installer.Run(ctx, "virsh", "--connect", "qemu:///system", "pool-dumpxml", pool)
	if err != nil {
		return "", fmt.Errorf("Speicherpool konnte nicht gelesen werden: %s", summarize(output, err))
	}
	var parsed struct {
		Target struct {
			Path string `xml:"path"`
		} `xml:"target"`
	}
	if err := xml.Unmarshal(output, &parsed); err != nil || !safeLibvirtStoragePath(parsed.Target.Path) {
		return "", errors.New("Speicherpool-Ziel liegt nicht im erlaubten Libvirt-Speicherbereich.")
	}
	return filepath.Clean(parsed.Target.Path), nil
}

func safeLibvirtStoragePath(path string) bool {
	clean := filepath.Clean(path)
	return filepath.IsAbs(path) && !strings.Contains(path, "..") && (clean == "/var/lib/libvirt/images" || strings.HasPrefix(clean, "/var/lib/libvirt/images/"))
}

func safeISOPath(path string) bool {
	clean := filepath.Clean(path)
	return filepath.IsAbs(path) && !strings.Contains(path, "..") && strings.EqualFold(filepath.Ext(clean), ".iso") && (clean == "/var/lib/libvirt/images" || strings.HasPrefix(clean, "/var/lib/libvirt/images/"))
}

func validHostDeviceXML(content string) bool {
	upper := strings.ToUpper(content)
	if strings.Contains(upper, "<!DOCTYPE") || strings.Contains(upper, "<!ENTITY") {
		return false
	}
	var device struct {
		XMLName xml.Name `xml:"hostdev"`
	}
	return xml.Unmarshal([]byte(content), &device) == nil && device.XMLName.Local == "hostdev"
}

func validDomainXML(content, expectedName string) bool {
	upper := strings.ToUpper(content)
	if strings.Contains(upper, "<!DOCTYPE") || strings.Contains(upper, "<!ENTITY") {
		return false
	}
	decoder := xml.NewDecoder(strings.NewReader(content))
	allowedElements := map[string]bool{
		"domain": true, "name": true, "memory": true, "currentMemory": true, "vcpu": true,
		"os": true, "type": true, "boot": true, "features": true, "acpi": true, "apic": true,
		"pae": true, "devices": true, "emulator": true, "disk": true, "driver": true,
		"source": true, "target": true, "readonly": true, "graphics": true, "serial": true,
		"console": true, "interface": true, "model": true,
	}
	allowedAttributes := map[string]bool{
		"type": true, "unit": true, "placement": true, "arch": true, "machine": true, "dev": true, "file": true,
		"device": true, "name": true, "bus": true, "autoport": true, "listen": true,
		"network": true, "bridge": true, "mode": true, "port": true,
	}
	rootName := ""
	insideEmulator := false
	for {
		token, err := decoder.Token()
		if err != nil {
			if errors.Is(err, io.EOF) {
				break
			}
			return false
		}
		switch element := token.(type) {
		case xml.StartElement:
			if !allowedElements[element.Name.Local] {
				return false
			}
			if rootName == "" {
				rootName = element.Name.Local
			}
			if element.Name.Local == "emulator" {
				insideEmulator = true
			}
			for _, attribute := range element.Attr {
				if !allowedAttributes[attribute.Name.Local] {
					return false
				}
				switch attribute.Name.Local {
				case "type":
					allowed := map[string]map[string]bool{
						"domain": {"qemu": true}, "disk": {"file": true}, "interface": {"network": true, "bridge": true, "direct": true},
						"driver": {"raw": true, "qcow2": true}, "graphics": {"spice": true}, "serial": {"pty": true},
						"console": {"pty": true}, "target": {"serial": true, "isa-serial": true},
						"source": {}, "model": {"virtio": true}, "os": {}, "": {},
					}
					if choices, ok := allowed[element.Name.Local]; ok && !choices[attribute.Value] {
						return false
					}
				case "file":
					if !safeLibvirtStoragePath(attribute.Value) || !strings.EqualFold(filepath.Ext(attribute.Value), ".iso") && !strings.EqualFold(filepath.Ext(attribute.Value), ".qcow2") {
						return false
					}
				case "listen":
					if attribute.Value != "127.0.0.1" {
						return false
					}
				case "network", "bridge", "dev", "name":
					if element.Name.Local == "source" && !libvirtNamePattern.MatchString(attribute.Value) {
						return false
					}
				}
				if element.Name.Local == "disk" && attribute.Name.Local == "device" && attribute.Value != "disk" && attribute.Value != "cdrom" {
					return false
				}
			}
		case xml.EndElement:
			if element.Name.Local == "emulator" {
				insideEmulator = false
			}
		case xml.CharData:
			if len(strings.TrimSpace(string(element))) > 4096 {
				return false
			}
			if insideEmulator && strings.TrimSpace(string(element)) != "/usr/bin/qemu-system-x86_64" {
				return false
			}
		}
	}
	var domain struct {
		XMLName xml.Name `xml:"domain"`
		Name    string   `xml:"name"`
	}
	return rootName == "domain" && xml.Unmarshal([]byte(content), &domain) == nil && domain.XMLName.Local == "domain" && domain.Name == expectedName
}

func knownHostDeviceXML(content string) bool {
	inventory := collect.HostDevices()
	for _, device := range inventory.Devices {
		if device.XML == content {
			return true
		}
	}
	return false
}
