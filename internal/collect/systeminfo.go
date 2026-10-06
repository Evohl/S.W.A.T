package collect

import (
	"fmt"
	"os"
	"runtime"
	"strconv"
	"strings"
)

// SystemInfo contains read-only host information available without root.
type SystemInfo struct {
	Hostname      string
	Hardware      string
	OS            string
	Architecture  string
	CPUModel      string
	CPUCores      int
	Uptime        string
	Load          string
	LoadPercent   string
	MemoryUsed    string
	MemoryPercent string
}

// ReadSystemInfo collects the generic host information shown on the overview.
func ReadSystemInfo() SystemInfo {
	total, available := memoryBytes()
	load := loadAverage()
	loadPercent := "nicht verfügbar"
	if total > 0 && load >= 0 {
		loadPercent = fmt.Sprintf("%.0f%%", load/float64(runtime.NumCPU())*100)
	}

	return SystemInfo{
		Hostname:      firstLine("/etc/hostname", "unbekannt"),
		Hardware:      firstLine("/sys/class/dmi/id/product_name", "unbekannt"),
		OS:            osName(),
		Architecture:  runtime.GOARCH,
		CPUModel:      cpuModel(),
		CPUCores:      runtime.NumCPU(),
		Uptime:        uptime(),
		Load:          formatLoad(load),
		LoadPercent:   loadPercent,
		MemoryUsed:    formatMemory(total - available),
		MemoryPercent: memoryPercent(total, available),
	}
}

func firstLine(path, fallback string) string {
	data, err := os.ReadFile(path)
	if err != nil || strings.TrimSpace(string(data)) == "" {
		return fallback
	}
	return strings.TrimSpace(strings.SplitN(string(data), "\n", 2)[0])
}

func osName() string {
	data, err := os.ReadFile("/etc/os-release")
	if err != nil {
		return "Linux"
	}
	for _, line := range strings.Split(string(data), "\n") {
		if strings.HasPrefix(line, "PRETTY_NAME=") {
			return strings.Trim(strings.TrimPrefix(line, "PRETTY_NAME="), "\"")
		}
	}
	return "Linux"
}

func cpuModel() string {
	data, err := os.ReadFile("/proc/cpuinfo")
	if err != nil {
		return "unbekannt"
	}
	for _, line := range strings.Split(string(data), "\n") {
		if strings.HasPrefix(line, "model name") {
			parts := strings.SplitN(line, ":", 2)
			if len(parts) == 2 {
				return strings.TrimSpace(parts[1])
			}
		}
	}
	return "unbekannt"
}

func uptime() string {
	data, err := os.ReadFile("/proc/uptime")
	if err != nil {
		return "unbekannt"
	}
	parts := strings.Fields(string(data))
	if len(parts) == 0 {
		return "unbekannt"
	}
	seconds, err := strconv.ParseFloat(parts[0], 64)
	if err != nil {
		return "unbekannt"
	}
	totalMinutes := int64(seconds / 60)
	days := totalMinutes / (24 * 60)
	hours := (totalMinutes % (24 * 60)) / 60
	minutes := totalMinutes % 60
	return fmt.Sprintf("%d T, %d h, %d min", days, hours, minutes)
}

func loadAverage() float64 {
	data, err := os.ReadFile("/proc/loadavg")
	if err != nil {
		return -1
	}
	parts := strings.Fields(string(data))
	if len(parts) == 0 {
		return -1
	}
	load, err := strconv.ParseFloat(parts[0], 64)
	if err != nil {
		return -1
	}
	return load
}

func memoryBytes() (uint64, uint64) {
	data, err := os.ReadFile("/proc/meminfo")
	if err != nil {
		return 0, 0
	}
	var total, available uint64
	for _, line := range strings.Split(string(data), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		value, err := strconv.ParseUint(fields[1], 10, 64)
		if err != nil {
			continue
		}
		switch fields[0] {
		case "MemTotal:":
			total = value * 1024
		case "MemAvailable:":
			available = value * 1024
		}
	}
	return total, available
}

func formatLoad(load float64) string {
	if load < 0 {
		return "nicht verfügbar"
	}
	return fmt.Sprintf("%.2f (1 min)", load)
}

func formatMemory(bytes uint64) string {
	if bytes == 0 {
		return "nicht verfügbar"
	}
	return fmt.Sprintf("%.1f GiB", float64(bytes)/(1024*1024*1024))
}

func memoryPercent(total, available uint64) string {
	if total == 0 || available > total {
		return "nicht verfügbar"
	}
	return fmt.Sprintf("%.0f%%", float64(total-available)/float64(total)*100)
}
