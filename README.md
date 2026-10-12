# S.W.A.T

**System Web Administration Tool**

S.W.A.T is a small Arch-native server dashboard written in Go. It reads Linux-native interfaces such as systemd, `ip`, `lsblk`, `journalctl`, `virsh`, and nftables instead of hiding the host behind a large abstraction layer.

Repository: [github.com/Evohl/S.W.A.T](https://github.com/Evohl/S.W.A.T)

> [!WARNING]
> **Under construction / unfertig:** S.W.A.T is an early, incomplete project. Do not rely on it as the only way to administer a host. The packaged service defaults to loopback and read-only; public access requires explicit native HTTPS configuration and should be restricted to trusted source addresses.

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

The permission boundary is documented in [docs/permissions.md](docs/permissions.md). Planned homeserver integration requirements are in [docs/homeserver-requirements.md](docs/homeserver-requirements.md).

## Local development

```bash
go build -o swat ./cmd/swat
./swat
```

Open `http://localhost:8443/`.

## Arch VM test deployment

Build, upload, and start the current binary on an explicitly selected Arch test
VM with:

```bash
./scripts/deploy-test.sh user@arch-test-vm
```

The destination is required; the script has no default host. It opens a TTY
for `sudo`. The remote binary defaults to `/tmp/swat-server` and the listen
address to `10.10.0.1:18443`; override those with `SWAT_REMOTE_BINARY` and
`SWAT_REMOTE_ADDR` when appropriate for the VM. Do not use the physical host
as the test destination.

SWAT should run on the server as a dedicated unprivileged system user. Privileged changes are limited to validated, allowlisted commands and are never passed through arbitrary shell input.

The Nginx administration page currently stores and previews structured virtual
hosts only. It does not write `/etc/nginx` or reload Nginx; see
[`docs/nginx-configuration.md`](docs/nginx-configuration.md).

Optional service profiles and their package dependencies are centralized under
`/modules`; package installation is handled by the narrow Arch-only helper.
See [`docs/modules.md`](docs/modules.md) for its permissions and service-start
rules.

## Build and install an Arch package

The repository includes a local `PKGBUILD`, the systemd unit
`packaging/swat.service`, and the system user definition
`packaging/swat.sysusers.conf`. The packaged service runs as the unprivileged
`swat` account, defaults to `127.0.0.1:8443`, stores state in `/var/lib/swat`,
and sets `SWAT_READ_ONLY=1`. Root-mode changes are disabled; the package does
not install sudoers permissions. Cleartext listeners on non-loopback addresses
are rejected. Native HTTPS can be explicitly enabled with a certificate and
private key supplied through systemd credentials; see
[`docs/https-deployment.md`](docs/https-deployment.md). A reviewed
Polkit/helper boundary is required before enabling system writes.

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

Open `http://127.0.0.1:8443/` on the host for local-only use. For temporary
remote access, use an SSH tunnel:

```bash
ssh -L 8443:127.0.0.1:8443 user@server
```

Then browse to `http://127.0.0.1:8443/` on the client. For internet access,
configure native HTTPS and restrict the firewall to trusted sources as
described in [`docs/https-deployment.md`](docs/https-deployment.md). Remove the
package with `sudo pacman -R swat`; `/var/lib/swat` is retained. The project
license has not yet been specified (`license=('unknown')` in `PKGBUILD`);
select and add a license before redistributing binary packages.
