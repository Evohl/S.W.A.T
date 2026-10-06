package collect

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os/exec"
	"strings"
	"syscall"
)

type BlockDevice struct {
	Name         string        `json:"name"`
	Path         string        `json:"path"`
	Type         string        `json:"type"`
	Size         string        `json:"size"`
	FSType       string        `json:"fstype"`
	Mountpoint   string        `json:"mountpoint"`
	Used         string        `json:"used,omitempty"`
	Available    string        `json:"available,omitempty"`
	Usage        string        `json:"usage,omitempty"`
	UsagePercent int           `json:"usage_percent,omitempty"`
	Parent       string        `json:"parent,omitempty"`
	Level        int           `json:"level"`
	Children     []BlockDevice `json:"children"`
}

type StorageSummary struct {
	Used      string
	Available string
	Usage     string
	Percent   int
}

func (device BlockDevice) IsRAID() bool {
	typeName := strings.ToLower(device.Type)
	switch typeName {
	case "raid0", "raid1", "raid4", "raid5", "raid6", "raid10", "md":
		return true
	default:
		return false
	}
}

type blockDevicesOutput struct {
	BlockDevices []BlockDevice `json:"blockdevices"`
}

func BlockDevices() ([]BlockDevice, error) {
	cmd := exec.Command("lsblk", "--json", "--output", "NAME,PATH,TYPE,SIZE,FSTYPE,MOUNTPOINT")
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("lsblk: %w: %s", err, stderr.String())
	}

	var output blockDevicesOutput
	if err := json.Unmarshal(stdout.Bytes(), &output); err != nil {
		return nil, fmt.Errorf("parsing lsblk output: %w", err)
	}
	for index := range output.BlockDevices {
		setBlockDeviceHierarchy(&output.BlockDevices[index], "", 0)
	}
	return output.BlockDevices, nil
}

func SummarizeStorage(devices []BlockDevice) StorageSummary {
	mountpoints := make(map[string]struct{})
	var total, used, available uint64
	var collect func([]BlockDevice)
	collect = func(items []BlockDevice) {
		for _, device := range items {
			if device.Mountpoint != "" {
				if _, seen := mountpoints[device.Mountpoint]; !seen {
					mountpoints[device.Mountpoint] = struct{}{}
					deviceTotal, deviceUsed, deviceAvailable, ok := filesystemUsageBytes(device.Mountpoint)
					if ok {
						total += deviceTotal
						used += deviceUsed
						available += deviceAvailable
					}
				}
			}
			collect(device.Children)
		}
	}
	collect(devices)
	if total == 0 {
		return StorageSummary{}
	}
	percent := int(float64(used) / float64(total) * 100)
	return StorageSummary{
		Used:      formatStorageBytes(used),
		Available: formatStorageBytes(available),
		Usage:     fmt.Sprintf("%.0f%%", float64(used)/float64(total)*100),
		Percent:   percent,
	}
}

func DisplayStorageDevices(devices []BlockDevice) []BlockDevice {
	raids := make(map[string]BlockDevice)
	var collectRAIDs func(BlockDevice, string)
	collectRAIDs = func(device BlockDevice, parent string) {
		if device.IsRAID() {
			if _, exists := raids[device.Path]; !exists {
				array := device
				array.Parent = ""
				array.Level = 0
				array.Children = nil
				raids[device.Path] = array
			}
			if parent != "" {
				array := raids[device.Path]
				member := BlockDevice{Name: strings.TrimPrefix(parent, "/dev/"), Path: parent, Type: "raid member", FSType: "linux_raid_member", Level: 1, Parent: array.Path}
				for _, existing := range array.Children {
					if existing.Path == member.Path {
						return
					}
				}
				array.Children = append(array.Children, member)
				raids[device.Path] = array
			}
			return
		}
		for _, child := range device.Children {
			collectRAIDs(child, device.Path)
		}
	}
	for _, device := range devices {
		collectRAIDs(device, "")
	}

	result := make([]BlockDevice, 0, len(raids)+len(devices))
	for _, array := range raids {
		result = append(result, array)
	}
	for _, device := range devices {
		if !containsRAID(device) {
			result = append(result, collapseRAIDChildren(device))
		}
	}
	return result
}

func collapseRAIDChildren(device BlockDevice) BlockDevice {
	if device.IsRAID() {
		device.Children = nil
		return device
	}
	filteredChildren := make([]BlockDevice, 0, len(device.Children))
	for _, child := range device.Children {
		filteredChildren = append(filteredChildren, collapseRAIDChildren(child))
	}
	device.Children = filteredChildren
	return device
}

func containsRAID(device BlockDevice) bool {
	if device.IsRAID() {
		return true
	}
	for _, child := range device.Children {
		if containsRAID(child) {
			return true
		}
	}
	return false
}

func setBlockDeviceHierarchy(device *BlockDevice, parent string, level int) {
	device.Parent = parent
	device.Level = level
	if device.Mountpoint != "" {
		device.Used, device.Available, device.Usage, device.UsagePercent = filesystemUsage(device.Mountpoint)
	}
	for index := range device.Children {
		setBlockDeviceHierarchy(&device.Children[index], device.Path, level+1)
	}
}

func filesystemUsage(path string) (string, string, string, int) {
	total, used, available, ok := filesystemUsageBytes(path)
	if !ok {
		return "", "", "", 0
	}
	if total == 0 {
		return "", "", "", 0
	}
	usage := float64(used) / float64(total) * 100
	return formatStorageBytes(used), formatStorageBytes(available), fmt.Sprintf("%.0f%%", usage), int(usage)
}

func filesystemUsageBytes(path string) (uint64, uint64, uint64, bool) {
	var stats syscall.Statfs_t
	if err := syscall.Statfs(path, &stats); err != nil || stats.Blocks == 0 {
		return 0, 0, 0, false
	}
	blockSize := uint64(stats.Bsize)
	total := stats.Blocks * blockSize
	available := stats.Bavail * blockSize
	used := total - stats.Bfree*blockSize
	return total, used, available, true
}

func formatStorageBytes(value uint64) string {
	units := []string{"B", "KB", "MB", "GB", "TB"}
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
