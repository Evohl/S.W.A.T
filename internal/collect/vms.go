package collect

import (
	"bytes"
	"encoding/xml"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"time"
)

type cpuSample struct {
	nanoseconds uint64
	at          time.Time
}

var vmCPUSamples = struct {
	sync.Mutex
	values map[string]cpuSample
}{values: make(map[string]cpuSample)}

func normalizeVMState(raw string) string {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "", "unknown", "unbekannt", "unknown state":
		return "unknown"
	case "running", "active", "online", "started", "start":
		return "running"
	case "shut off", "shutoff", "stopped", "stopping", "off", "poweroff", "shutdown", "halted", "ausgeschaltet", "beendet":
		return "stopped"
	case "paused", "suspended", "suspend":
		return "paused"
	case "error", "crashed", "failed", "failure":
		return "error"
	default:
		return strings.ToLower(strings.TrimSpace(raw))
	}
}

type VM struct {
	Name  string
	State string
}

type VMDetail struct {
	VM
	Info               string
	MemoryConfig       string
	MemoryMiB          uint64
	VCPUs              string
	DiskPaths          []string
	Networks           []string
	HostDevices        []string
	HostDeviceOptions  []VMHostDevice
	NetworkSelection   string
	NetworkWarning     string
	ConsoleCommand     string
	SpiceAvailable     bool
	SpicePort          int
	SpiceCommand       string
	CPUUsage           string
	MemoryUsage        string
	MemoryPercent      string
	DiskUsage          string
	InstallMedia       string
	InstallMediaTarget string
}

type VMHostDevice struct {
	HostDevice
	Attached bool
}

type VMInventory struct {
	VMs       []VM
	Available bool
	Hint      string
}

func VMs() (VMInventory, error) {
	virshPath, err := exec.LookPath("virsh")
	if err != nil {
		return VMInventory{
			Available: false,
			Hint:      "Libvirt ist nicht installiert. Installiere libvirt und qemu-desktop, aktiviere danach libvirtd.service.",
		}, nil
	}

	listCmd := virshCommand(virshPath, "list", "--all", "--name")
	var listOut, listErr bytes.Buffer
	listCmd.Stdout = &listOut
	listCmd.Stderr = &listErr
	if err := listCmd.Run(); err != nil {
		return VMInventory{
			Available: false,
			Hint:      "Libvirt ist installiert, aber nicht erreichbar. Prüfe libvirtd.service und die Benutzerrechte.",
		}, nil
	}

	var names []string
	for _, name := range strings.Split(strings.TrimSpace(listOut.String()), "\n") {
		name = strings.TrimSpace(name)
		if name != "" {
			names = append(names, name)
		}
	}
	vms := make([]VM, len(names))
	var wg sync.WaitGroup
	for i, name := range names {
		wg.Add(1)
		go func(index int, name string) {
			defer wg.Done()
			stateCmd := virshCommand(virshPath, "domstate", name)
			var stateOut, stateErr bytes.Buffer
			stateCmd.Stdout = &stateOut
			stateCmd.Stderr = &stateErr
			if err := stateCmd.Run(); err != nil {
				vms[index] = VM{Name: name, State: "unknown"}
				return
			}
			vms[index] = VM{Name: name, State: normalizeVMState(strings.TrimSpace(stateOut.String()))}
		}(i, name)
	}
	wg.Wait()
	return VMInventory{VMs: vms, Available: true}, nil
}

func VMByName(name string) (VMDetail, error) {
	name = strings.TrimSpace(name)
	if name == "" {
		return VMDetail{}, fmt.Errorf("kein VM-Name angegeben")
	}
	inventory, err := VMs()
	if err != nil {
		return VMDetail{}, err
	}
	virshPath, err := exec.LookPath("virsh")
	if err != nil {
		return VMDetail{}, fmt.Errorf("libvirt ist nicht verfügbar")
	}
	for _, vm := range inventory.VMs {
		if vm.Name != name {
			continue
		}
		return vmDetail(virshPath, vm, true)
	}
	return VMDetail{}, fmt.Errorf("VM %q nicht gefunden", name)
}

// VMDetailsForList builds one VMDetail per VM without the expensive host-device
// enrichment, fetching each VM concurrently since it is only used for overview lists.
func VMDetailsForList(inventory VMInventory) []VMDetail {
	virshPath, err := exec.LookPath("virsh")
	if err != nil {
		details := make([]VMDetail, len(inventory.VMs))
		for i, vm := range inventory.VMs {
			details[i] = VMDetail{VM: vm}
		}
		return details
	}
	details := make([]VMDetail, len(inventory.VMs))
	var wg sync.WaitGroup
	for i, vm := range inventory.VMs {
		wg.Add(1)
		go func(index int, vm VM) {
			defer wg.Done()
			detail, err := vmDetail(virshPath, vm, false)
			if err != nil {
				detail = VMDetail{VM: vm}
			}
			details[index] = detail
		}(i, vm)
	}
	wg.Wait()
	return details
}

func vmDetail(virshPath string, vm VM, includeHostDevices bool) (VMDetail, error) {
	name := vm.Name
	output, err := virshCommand(virshPath, "dominfo", name).Output()
	if err != nil {
		return VMDetail{}, fmt.Errorf("VM-Details konnten nicht gelesen werden: %w", err)
	}
	detail := VMDetail{VM: vm, Info: strings.TrimSpace(string(output)), ConsoleCommand: "virsh --connect qemu:///system console " + name}
	if config, configErr := virshCommand(virshPath, "dumpxml", name).Output(); configErr == nil {
		detail.Info = strings.TrimSpace(string(config))
		applyVMConfig(&detail, config, includeHostDevices)
	}
	stats := vmStats(virshPath, name)
	if currentVCPUs := stats["vcpu.current"]; currentVCPUs != "" {
		detail.VCPUs = currentVCPUs
	}
	detail.MemoryUsage, detail.MemoryPercent = memoryMetric(stats)
	detail.DiskUsage = diskMetric(stats)
	detail.CPUUsage = cpuMetric(name, stats["cpu.time"], stats["vcpu.current"])
	if vm.State == "stopped" {
		detail.CPUUsage = "-"
		detail.MemoryPercent = "-"
	}
	return detail, nil
}

type vmDomainXML struct {
	Memory struct {
		Value uint64 `xml:",chardata"`
		Unit  string `xml:"unit,attr"`
	} `xml:"memory"`
	VCPU struct {
		Value uint64 `xml:",chardata"`
	} `xml:"vcpu"`
	Devices struct {
		Graphics []struct {
			Type string `xml:"type,attr"`
			Port int    `xml:"port,attr"`
		} `xml:"graphics"`
		Disks []struct {
			Device string `xml:"device,attr"`
			Target struct {
				Dev string `xml:"dev,attr"`
			} `xml:"target"`
			Source struct {
				File string `xml:"file,attr"`
			} `xml:"source"`
		} `xml:"disk"`
		Interfaces []struct {
			Type   string `xml:"type,attr"`
			Source struct {
				Network string `xml:"network,attr"`
				Bridge  string `xml:"bridge,attr"`
				Device  string `xml:"dev,attr"`
			} `xml:"source"`
		} `xml:"interface"`
		Hostdevs []vmHostdevXML `xml:"hostdev"`
	} `xml:"devices"`
}

type vmHostdevXML struct {
	Type   string `xml:"type,attr"`
	Source struct {
		Address struct {
			Domain   string `xml:"domain,attr"`
			Bus      string `xml:"bus,attr"`
			Slot     string `xml:"slot,attr"`
			Function string `xml:"function,attr"`
		} `xml:"address"`
		Vendor struct {
			ID string `xml:"id,attr"`
		} `xml:"vendor"`
		Product struct {
			ID string `xml:"id,attr"`
		} `xml:"product"`
	} `xml:"source"`
}

func applyVMConfig(detail *VMDetail, raw []byte, includeHostDevices bool) {
	var config vmDomainXML
	if err := xml.Unmarshal(raw, &config); err != nil {
		return
	}
	if config.Memory.Value > 0 {
		unit := config.Memory.Unit
		if unit == "" {
			unit = "KiB"
		}
		detail.MemoryConfig = formatConfiguredMemory(config.Memory.Value, unit)
		detail.MemoryMiB = config.Memory.Value
		switch strings.ToLower(unit) {
		case "b":
			detail.MemoryMiB /= 1024 * 1024
		case "kib":
			detail.MemoryMiB /= 1024
		case "gib":
			detail.MemoryMiB *= 1024
		case "tib":
			detail.MemoryMiB *= 1024 * 1024
		}
	}
	if config.VCPU.Value > 0 {
		detail.VCPUs = strconv.FormatUint(config.VCPU.Value, 10)
	}
	for _, graphics := range config.Devices.Graphics {
		if strings.EqualFold(graphics.Type, "spice") {
			detail.SpiceAvailable = true
			if graphics.Port > 0 {
				detail.SpicePort = graphics.Port
				detail.SpiceCommand = fmt.Sprintf("remote-viewer spice://127.0.0.1:%d", graphics.Port)
			}
			break
		}
	}
	for _, disk := range config.Devices.Disks {
		if disk.Device == "cdrom" {
			detail.InstallMediaTarget = disk.Target.Dev
			if disk.Source.File != "" {
				detail.InstallMedia = disk.Source.File
			}
			continue
		}
		if disk.Source.File != "" {
			detail.DiskPaths = append(detail.DiskPaths, disk.Device+": "+disk.Source.File)
		}
	}
	for _, network := range config.Devices.Interfaces {
		switch {
		case network.Source.Network != "":
			detail.Networks = append(detail.Networks, "NAT: "+network.Source.Network)
			detail.NetworkSelection = network.Source.Network
		case network.Source.Bridge != "":
			detail.Networks = append(detail.Networks, "Bridge: "+network.Source.Bridge)
			detail.NetworkSelection = "bridge:" + network.Source.Bridge
			if !bridgeInterfaceNames()[network.Source.Bridge] {
				detail.NetworkSelection = "direct:" + network.Source.Bridge
				detail.NetworkWarning = "Die bisherige Bridge-Konfiguration verwendet ein normales Host-Interface. Bitte als Direktverbindung speichern."
			}
		case network.Source.Device != "":
			detail.Networks = append(detail.Networks, "Direct: "+network.Source.Device)
			detail.NetworkSelection = "direct:" + network.Source.Device
		default:
			detail.Networks = append(detail.Networks, network.Type)
		}
	}
	for _, hostdev := range config.Devices.Hostdevs {
		if hostdev.Type == "pci" && hostdev.Source.Address.Bus != "" {
			detail.HostDevices = append(detail.HostDevices, fmt.Sprintf("PCI %s:%s:%s.%s", hostdev.Source.Address.Domain, hostdev.Source.Address.Bus, hostdev.Source.Address.Slot, hostdev.Source.Address.Function))
			continue
		}
		if hostdev.Type == "usb" && (hostdev.Source.Vendor.ID != "" || hostdev.Source.Product.ID != "") {
			detail.HostDevices = append(detail.HostDevices, fmt.Sprintf("USB %s:%s", hostdev.Source.Vendor.ID, hostdev.Source.Product.ID))
		}
	}
	if !includeHostDevices {
		return
	}
	for _, device := range HostDevices().Devices {
		option := VMHostDevice{HostDevice: device}
		for _, hostdev := range config.Devices.Hostdevs {
			if hostDeviceMatches(hostdev, device.XML) {
				option.Attached = true
				break
			}
		}
		detail.HostDeviceOptions = append(detail.HostDeviceOptions, option)
	}
}

func formatConfiguredMemory(value uint64, unit string) string {
	multiplier := uint64(1024)
	switch strings.ToLower(unit) {
	case "b":
		multiplier = 1
	case "mib":
		multiplier = 1024 * 1024
	case "gib":
		multiplier = 1024 * 1024 * 1024
	case "tib":
		multiplier = 1024 * 1024 * 1024 * 1024
	}
	return formatMetricBytes(value * multiplier)
}

func hostDeviceMatches(hostdev vmHostdevXML, raw string) bool {
	var source struct {
		Type   string `xml:"type,attr"`
		Source struct {
			Address struct {
				Domain   string `xml:"domain,attr"`
				Bus      string `xml:"bus,attr"`
				Slot     string `xml:"slot,attr"`
				Function string `xml:"function,attr"`
			} `xml:"address"`
			Vendor struct {
				ID string `xml:"id,attr"`
			} `xml:"vendor"`
			Product struct {
				ID string `xml:"id,attr"`
			} `xml:"product"`
		} `xml:"source"`
	}
	if xml.Unmarshal([]byte(raw), &source) != nil || source.Type != hostdev.Type {
		return false
	}
	if source.Type == "pci" {
		return source.Source.Address.Domain == hostdev.Source.Address.Domain && source.Source.Address.Bus == hostdev.Source.Address.Bus && source.Source.Address.Slot == hostdev.Source.Address.Slot && source.Source.Address.Function == hostdev.Source.Address.Function
	}
	return source.Source.Vendor.ID == hostdev.Source.Vendor.ID && source.Source.Product.ID == hostdev.Source.Product.ID
}

func vmStats(path, name string) map[string]string {
	output, err := virshCommand(path, "domstats", "--vcpu", "--balloon", "--block", "--state", "--cpu-total", name).Output()
	if err != nil {
		return map[string]string{}
	}
	stats := make(map[string]string)
	for _, line := range strings.Split(string(output), "\n") {
		parts := strings.SplitN(strings.TrimSpace(line), "=", 2)
		if len(parts) == 2 {
			stats[parts[0]] = strings.TrimSpace(parts[1])
		}
	}
	return stats
}

func memoryMetric(stats map[string]string) (string, string) {
	currentBytes, currentOK := parseUint(stats["balloon.current"])
	maximumBytes, maximumOK := parseUint(stats["balloon.maximum"])
	if !currentOK || !maximumOK || maximumBytes == 0 {
		return "k.A.", "k.A."
	}
	usedBytes := currentBytes
	availableBytes, availableOK := parseUint(stats["balloon.available"])
	unusedBytes, unusedOK := parseUint(stats["balloon.unused"])
	if availableOK && unusedOK && availableBytes > 0 && unusedBytes <= availableBytes {
		usedBytes = availableBytes - unusedBytes
	}
	percent := float64(usedBytes) / float64(maximumBytes) * 100
	if percent > 100 {
		percent = 100
	}
	return formatMetricBytes(currentBytes) + " / " + formatMetricBytes(maximumBytes), fmt.Sprintf("%.0f%%", percent)
}

func diskMetric(stats map[string]string) string {
	var allocation, capacity uint64
	for index := 0; ; index++ {
		allocationValue, allocationOK := parseUint(stats[fmt.Sprintf("block.%d.allocation", index)])
		capacityValue, capacityOK := parseUint(stats[fmt.Sprintf("block.%d.capacity", index)])
		if !allocationOK && !capacityOK {
			break
		}
		allocation += allocationValue
		capacity += capacityValue
	}
	if capacity == 0 {
		return "k.A."
	}
	return formatMetricBytes(allocation) + " / " + formatMetricBytes(capacity)
}

func cpuMetric(name, rawTime, rawVCPUs string) string {
	cpuTime, ok := parseUint(rawTime)
	vcpus, vcpusOK := parseUint(rawVCPUs)
	if !ok || !vcpusOK || vcpus == 0 {
		return "k.A."
	}
	now := time.Now()
	vmCPUSamples.Lock()
	previous, exists := vmCPUSamples.values[name]
	vmCPUSamples.values[name] = cpuSample{nanoseconds: cpuTime, at: now}
	vmCPUSamples.Unlock()
	if !exists || now.Sub(previous.at) <= 0 || cpuTime < previous.nanoseconds {
		return "k.A."
	}
	percent := float64(cpuTime-previous.nanoseconds) / float64(now.Sub(previous.at).Nanoseconds()) / float64(vcpus) * 100
	if percent < 0 {
		percent = 0
	}
	if percent > 100 {
		percent = 100
	}
	return fmt.Sprintf("%.0f%%", percent)
}

func parseUint(value string) (uint64, bool) {
	parsed, err := strconv.ParseUint(strings.TrimSpace(value), 10, 64)
	return parsed, err == nil
}

func formatMetricBytes(value uint64) string {
	units := []string{"B", "KiB", "MiB", "GiB", "TiB"}
	amount := float64(value)
	unit := 0
	for amount >= 1024 && unit < len(units)-1 {
		amount /= 1024
		unit++
	}
	if unit == 0 {
		return fmt.Sprintf("%.0f %s", amount, units[unit])
	}
	return fmt.Sprintf("%.1f %s", amount, units[unit])
}

type LibvirtRuntime struct {
	Available string
	URI       string
	Version   string
	NodeInfo  string
	Networks  [][]string
	Pools     [][]string
	Hint      string
}

func LibvirtRuntimeStatus() LibvirtRuntime {
	virshPath, err := exec.LookPath("virsh")
	if err != nil {
		return LibvirtRuntime{Available: "nicht verfügbar", Hint: "virsh ist nicht installiert."}
	}
	runtime := LibvirtRuntime{Available: "verfügbar"}
	runtime.URI = virshOutput(virshPath, "uri")
	runtime.Version = virshOutput(virshPath, "version")
	runtime.NodeInfo = virshOutput(virshPath, "nodeinfo")
	if runtime.URI == "" || runtime.NodeInfo == "" {
		runtime.Available = "nicht erreichbar"
		runtime.Hint = "Libvirt ist installiert, aber die Systemverbindung konnte nicht gelesen werden."
		return runtime
	}
	runtime.Networks = virshList(virshPath, "net-list", "--all")
	runtime.Pools = virshList(virshPath, "pool-list", "--all")
	return runtime
}

func virshOutput(path string, args ...string) string {
	output, err := virshCommand(path, args...).Output()
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(output))
}

// virshCommand runs virsh with a forced C locale so status text (e.g. domstate)
// is always in English regardless of the host's configured system locale.
func virshCommand(path string, args ...string) *exec.Cmd {
	commandArgs := append([]string{"--connect", "qemu:///system"}, args...)
	command := exec.Command(path, commandArgs...)
	command.Env = append(os.Environ(), "LC_ALL=C", "LANG=C")
	return command
}

func virshList(path string, args ...string) [][]string {
	raw := virshOutput(path, args...)
	lines := strings.Split(raw, "\n")
	rows := make([][]string, 0, len(lines))
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "---") || strings.HasPrefix(line, "Name ") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) > 0 {
			rows = append(rows, fields)
		}
	}
	return rows
}
