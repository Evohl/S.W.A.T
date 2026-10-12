package main

import (
	"log"
	"net"
	"os"
	"os/user"
	"path/filepath"
	"strconv"

	"swat/internal/audit"
	"swat/internal/moduleadmin"
)

func main() {
	account, err := user.Lookup("swat")
	if err != nil {
		log.Fatalf("lookup swat service account: %v", err)
	}
	uid, err := strconv.ParseUint(account.Uid, 10, 32)
	if err != nil {
		log.Fatalf("parse swat uid: %v", err)
	}
	group, err := user.LookupGroup("swat")
	if err != nil {
		log.Fatalf("lookup swat service group: %v", err)
	}
	groupID, err := strconv.Atoi(group.Gid)
	if err != nil {
		log.Fatalf("parse swat gid: %v", err)
	}
	if err := os.MkdirAll(filepath.Dir(moduleadmin.SocketPath), 0o750); err != nil {
		log.Fatalf("create helper runtime directory: %v", err)
	}
	if err := os.Chown(filepath.Dir(moduleadmin.SocketPath), 0, groupID); err != nil {
		log.Fatalf("set helper runtime directory ownership: %v", err)
	}
	if err := os.Chmod(filepath.Dir(moduleadmin.SocketPath), 0o750); err != nil {
		log.Fatalf("set helper runtime directory permissions: %v", err)
	}
	if info, err := os.Lstat(moduleadmin.SocketPath); err == nil {
		if info.Mode()&os.ModeSocket == 0 {
			log.Fatalf("refusing to replace non-socket helper path %s", moduleadmin.SocketPath)
		}
		if err := os.Remove(moduleadmin.SocketPath); err != nil {
			log.Fatalf("remove stale helper socket: %v", err)
		}
	} else if !os.IsNotExist(err) {
		log.Fatalf("inspect helper socket path: %v", err)
	}
	listener, err := net.Listen("unix", moduleadmin.SocketPath)
	if err != nil {
		log.Fatalf("listen on module helper socket: %v", err)
	}
	defer func() {
		listener.Close()
		os.Remove(moduleadmin.SocketPath)
	}()
	if err := os.Chown(moduleadmin.SocketPath, 0, groupID); err != nil {
		log.Fatalf("set helper socket ownership: %v", err)
	}
	if err := os.Chmod(moduleadmin.SocketPath, 0o660); err != nil {
		log.Fatalf("set helper socket permissions: %v", err)
	}
	log.Printf("module installer helper listening on %s", moduleadmin.SocketPath)
	installer := &moduleadmin.Installer{
		Authorize: moduleadmin.PAMAuthorizer(os.Getenv("SWAT_SUDO_PAM_SERVICE")),
		Login:     moduleadmin.PAMLoginAuthorizer(os.Getenv("SWAT_PAM_SERVICE")),
		Audit: func(entry audit.Entry) error {
			return audit.Log("/var/lib/swat", entry)
		},
	}
	if err := installer.Serve(listener, uint32(uid)); err != nil {
		log.Fatalf("module helper stopped: %v", err)
	}
}
