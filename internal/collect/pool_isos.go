package collect

import (
	"encoding/xml"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

type ISOFile struct {
	Name string
	Size string
}

func PoolISOs(pool string) []ISOFile {
	virshPath, err := exec.LookPath("virsh")
	if err != nil {
		return nil
	}
	output := virshOutput(virshPath, "pool-dumpxml", pool)
	var definition struct {
		Target struct {
			Path string `xml:"path"`
		} `xml:"target"`
	}
	if xml.Unmarshal([]byte(output), &definition) != nil || definition.Target.Path == "" {
		return nil
	}
	entries, err := os.ReadDir(definition.Target.Path)
	if err != nil {
		return nil
	}
	isos := make([]ISOFile, 0)
	for _, entry := range entries {
		if entry.IsDir() || !strings.EqualFold(filepath.Ext(entry.Name()), ".iso") {
			continue
		}
		info, err := entry.Info()
		if err != nil {
			continue
		}
		isos = append(isos, ISOFile{Name: entry.Name(), Size: formatMetricBytes(uint64(info.Size()))})
	}
	return isos
}
