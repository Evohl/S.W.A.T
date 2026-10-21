package moduleadmin

import (
	"strings"
	"testing"
)

func TestValidDomainXMLAllowsOnlySWATVMProfile(t *testing.T) {
	valid := `<?xml version="1.0" encoding="UTF-8"?>
<domain type='qemu'>
  <name>test-vm</name>
  <memory unit='MiB'>2048</memory>
  <currentMemory unit='MiB'>2048</currentMemory>
  <vcpu placement='static'>2</vcpu>
  <os><type arch='x86_64' machine='pc'>hvm</type><boot dev='cdrom'/><boot dev='hd'/></os>
  <features><acpi/><apic/><pae/></features>
  <devices>
    <emulator>/usr/bin/qemu-system-x86_64</emulator>
    <disk type='file' device='disk'><driver name='qemu' type='qcow2'/><source file='/var/lib/libvirt/images/test-vm.qcow2'/><target dev='vda' bus='virtio'/></disk>
    <disk type='file' device='cdrom'><driver name='qemu' type='raw'/><source file='/var/lib/libvirt/images/test-vm-installer.iso'/><target dev='sda' bus='sata'/><readonly/></disk>
    <graphics type='spice' autoport='yes' listen='127.0.0.1'/>
    <serial type='pty'><target type='isa-serial' port='0'/></serial>
    <console type='pty'><target type='serial' port='0'/></console>
    <interface type='network'><source network='default'/><model type='virtio'/></interface>
  </devices>
</domain>`
	if !validDomainXML(valid, "test-vm") {
		t.Fatal("valid SWAT VM definition rejected")
	}
	for _, invalid := range []string{
		strings.Replace(valid, "listen='127.0.0.1'", "listen='0.0.0.0'", 1),
		strings.Replace(valid, "/var/lib/libvirt/images/test-vm.qcow2", "/etc/passwd", 1),
		strings.Replace(valid, "<devices>", "<devices><hostdev mode='subsystem' type='pci'/>", 1),
		strings.Replace(valid, "/usr/bin/qemu-system-x86_64", "/bin/sh", 1),
		strings.Replace(valid, "<name>test-vm</name>", "<name>other-vm</name>", 1),
		"<!DOCTYPE domain><domain><name>test-vm</name></domain>",
	} {
		if validDomainXML(invalid, "test-vm") {
			t.Errorf("unsafe VM definition accepted: %s", invalid[:min(len(invalid), 80)])
		}
	}
}

func TestVMActionCommandConvertsActionsToFixedVirshArguments(t *testing.T) {
	command, args, err := vmActionCommand("vm-start", "test-vm", "", "", "", "")
	if err != nil {
		t.Fatal(err)
	}
	if command != "virsh" || strings.Join(args, " ") != "--connect qemu:///system start test-vm" {
		t.Fatalf("command = %q %v", command, args)
	}
	if _, _, err := vmActionCommand("vm-start", "../../etc", "", "", "", ""); err == nil {
		t.Fatal("unsafe VM name accepted")
	}
	if _, _, err := vmActionCommand("libvirt-pool-create", "images", "/etc", "", "", ""); err == nil {
		t.Fatal("arbitrary pool path accepted")
	}
}
