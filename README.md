# S.W.A.T

**System Web Administration Tool**

S.W.A.T is a small Arch-native server dashboard written in Go. It reads Linux-native interfaces such as systemd, `ip`, `lsblk`, `journalctl`, `virsh`, and nftables instead of hiding the host behind a large abstraction layer.

Repository: [github.com/Evohl/S.W.A.T](https://github.com/Evohl/S.W.A.T)

## Current navigation

### Info

Read-only system information:

- Overview
- Services
- Storage
- VMs
- VM management and creation workflow
- Logs

### Config

Configuration is read-only by default. Root mode currently enables network forwarding and bridge actions, firewall zone management, and system hostname, installed locale, and timezone changes. Other system and account settings remain read-only:

- Network
- Firewall
- Libvirt (global host, network, and storage-pool status)

### Administration

Reserved for authenticated, short-lived administrative actions. User, group, and the remaining system settings are not currently writable.

- System and users
- Global settings
- Firewall (zones, inter-zone policies, NAT, active nftables ruleset; applied with confirm-or-rollback, see [docs/network-configuration.md](docs/network-configuration.md))
- Network (root mode: IPv4/IPv6 forwarding via sysctl)

The admin login validates the selected system account through PAM. The PAM
service defaults to `login` and can be changed with `SWAT_PAM_SERVICE`. After
login, the user can explicitly provide the sudo password for a second PAM
check (`SWAT_SUDO_PAM_SERVICE`, default `sudo`). A successful check creates a
short-lived administrative session; it does not grant arbitrary root commands.
Privileged operations use explicit allowlisted commands and are audited.
All application pages and APIs require an active login session; only the login
page, logout endpoint, and static assets are public.

The permission boundary is documented in [docs/permissions.md](docs/permissions.md).

## Local development

```bash
go build -o swat ./cmd/swat
./swat
```

Open `http://localhost:8443/`.

## Homeserver test deployment

Build, upload, and start the current binary on the homeserver with:

```bash
./scripts/deploy-test.sh
```

The script opens a TTY for `sudo`, so the homeserver password can be entered
normally. The defaults are `evohl@homeserver`, `/tmp/swat-server`, and
`10.10.0.1:18443`. Override them with `SWAT_REMOTE_HOST`,
`SWAT_REMOTE_BINARY`, or `SWAT_REMOTE_ADDR` when needed.

SWAT should run on the server as a dedicated unprivileged system user. Privileged changes are limited to validated, allowlisted commands and are never passed through arbitrary shell input.
