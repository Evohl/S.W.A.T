# S.W.A.T

**System Web Administration Tool**

S.W.A.T is a small Arch-native server dashboard written in Go. It reads Linux-native interfaces such as systemd, `ip`, `lsblk`, `journalctl`, `virsh`, and nftables instead of hiding the host behind a large abstraction layer.

Repository: [github.com/Evohl/S.W.A.T](https://github.com/Evohl/S.W.A.T)

> [!WARNING]
> **Under construction / unfertig:** S.W.A.T is an early, incomplete project. Do not expose it directly to untrusted networks or rely on it as the only way to administer a host. The packaged systemd service is deliberately loopback-only and read-only.

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

## Build and install an Arch package

The repository includes a local `PKGBUILD`, the systemd unit
`packaging/swat.service`, and the system user definition
`packaging/swat.sysusers.conf`. The packaged service runs as the unprivileged
`swat` account, listens only on `127.0.0.1:8443`, stores state in
`/var/lib/swat`, and sets `SWAT_READ_ONLY=1`. Root-mode changes are disabled;
the package does not install sudoers permissions. A reviewed Polkit/helper
boundary is required before enabling system writes.

Install build dependencies and build the package from the repository root:

```bash
sudo pacman -S --needed base-devel go gcc pam
makepkg -s
```

Install the generated package, create the system account, and start the service:

```bash
sudo pacman -U "./swat-0.1.0-1-$(uname -m).pkg.tar.zst"
sudo systemd-sysusers /usr/lib/sysusers.d/swat.conf
sudo systemctl enable --now swat.service
```

Open `http://127.0.0.1:8443/` on the host. To reach the dashboard remotely,
use an SSH tunnel instead of exposing the service port:

```bash
ssh -L 8443:127.0.0.1:8443 user@server
```

Then browse to `http://127.0.0.1:8443/` on the client. Remove the package with
`sudo pacman -R swat`; `/var/lib/swat` is retained. The project license has not
yet been specified (`license=('unknown')` in `PKGBUILD`); select and add a
license before redistributing binary packages.
