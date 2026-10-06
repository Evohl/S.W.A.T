package collect

import (
	"encoding/xml"
	"fmt"
	"os/exec"
	"strconv"
	"strings"
)

type HostDevice struct {
	Name   string
	Kind   string
	Label  string
	Source string
	XML    string
}

type HostDeviceInventory struct {
	Devices   []HostDevice
	Available bool
	Hint      string
}

func HostDevices() HostDeviceInventory {
	virshPath, err := exec.LookPath("virsh")
	if err != nil {
		return HostDeviceInventory{Available: false, Hint: "virsh ist nicht installiert."}
	}
	var devices []HostDevice
	for _, capability := range []string{"pci", "usb_device"} {
		output := virshOutput(virshPath, "nodedev-list", "--cap", capability)
		if output == "" {
			continue
		}
		for _, name := range strings.Split(output, "\n") {
			name = strings.TrimSpace(name)
			if name == "" {
				continue
			}
			xmlOutput := virshOutput(virshPath, "nodedev-dumpxml", name)
			device, ok := parseHostDevice(name, xmlOutput)
			if !ok {
				continue
			}
			devices = append(devices, device)
		}
	}
	if len(devices) == 0 {
		return HostDeviceInventory{Available: false, Hint: "Keine Host-Geräte für Passthrough gefunden oder Libvirt kann sie nicht lesen."}
	}
	return HostDeviceInventory{Devices: devices, Available: true}
}

func parseHostDevice(name, raw string) (HostDevice, bool) {
	type deviceXML struct {
		Capability struct {
			Type     string `xml:"type,attr"`
			Domain   uint64 `xml:"domain"`
			Bus      uint64 `xml:"bus"`
			Slot     uint64 `xml:"slot"`
			Function uint64 `xml:"function"`
			Device   uint64 `xml:"device"`
			Class    string `xml:"class"`
			Product  struct {
				ID   string `xml:"id,attr"`
				Text string `xml:",chardata"`
			} `xml:"product"`
			Vendor struct {
				ID   string `xml:"id,attr"`
				Text string `xml:",chardata"`
			} `xml:"vendor"`
		} `xml:"capability"`
	}
	var parsed deviceXML
	if err := xml.Unmarshal([]byte(raw), &parsed); err != nil {
		return HostDevice{}, false
	}
	switch parsed.Capability.Type {
	case "pci":
		if !usefulPCIClass(parsed.Capability.Class) {
			return HostDevice{}, false
		}
		address := fmt.Sprintf("%04x:%02x:%02x.%x", parsed.Capability.Domain, parsed.Capability.Bus, parsed.Capability.Slot, parsed.Capability.Function)
		label := strings.TrimSpace(parsed.Capability.Vendor.Text + " " + parsed.Capability.Product.Text)
		if label == "" {
			label = "Unbekanntes PCI-Gerät"
		}
		return HostDevice{
			Name:   name,
			Kind:   "pci",
			Label:  label,
			Source: address,
			XML:    fmt.Sprintf("<hostdev mode='subsystem' type='pci' managed='yes'><source><address domain='0x%04x' bus='0x%02x' slot='0x%02x' function='0x%x'/></source></hostdev>", parsed.Capability.Domain, parsed.Capability.Bus, parsed.Capability.Slot, parsed.Capability.Function),
		}, true
	case "usb_device":
		address := fmt.Sprintf("Bus %d / Gerät %d", parsed.Capability.Bus, parsed.Capability.Device)
		label := strings.TrimSpace(parsed.Capability.Vendor.Text + " " + parsed.Capability.Product.Text)
		if label == "" {
			label = "Unbekanntes USB-Gerät"
		}
		return HostDevice{
			Name:   name,
			Kind:   "usb",
			Label:  label,
			Source: address,
			XML:    fmt.Sprintf("<hostdev mode='subsystem' type='usb' managed='yes'><source><vendor id='0x%s'/><product id='0x%s'/></source></hostdev>", strings.TrimPrefix(strings.TrimSpace(parsed.Capability.Vendor.ID), "0x"), strings.TrimPrefix(strings.TrimSpace(parsed.Capability.Product.ID), "0x")),
		}, true
	default:
		return HostDevice{}, false
	}
}

func usefulPCIClass(raw string) bool {
	value, err := strconv.ParseUint(strings.TrimPrefix(strings.TrimSpace(raw), "0x"), 16, 32)
	if err != nil {
		return true
	}
	switch value >> 16 {
	case 0x05, 0x06:
		return false
	default:
		return true
	}
}
