# S.W.A.T (System Web Administration Tool)

## Purpose

- Go web dashboard and guided setup tool for fresh Arch Linux systems; reads systemd, `ip`, `lsblk`, `journalctl`, `virsh`, nftables directly

## Ownership

- `cmd/swat/`: HTTP server, handlers, templates, static assets (`web/`, vendored `spice-html5` and `xterm`)
- `cmd/servman/`: separate static assets
- `internal/collect/`: read-only data collectors for host state
- `internal/configwrite/`: ownership-aware atomic writer for SWAT-managed native configuration files
- `internal/modules/`: central Arch service-profile registry, package/service status, and persisted selection
- `internal/moduleadmin/`: typed Unix-socket operations for privileged server actions, helper-side PAM authorization, audit, and confirm/rollback transactions
- `cmd/swat-privileged/`: root-owned allowlisted administration helper; no generic command or arbitrary path operations
- `internal/zones/`: firewall zone/policy model, validation, nftables generator, desired-state store (`zones.json` in `SWAT_STATE_DIR`)
- `internal/audit/`: append-only JSON audit log (`audit.log` in the state dir)
- `PKGBUILD` and `packaging/`: local Arch package build, systemd unit, and sysusers account
- `packaging/` and `PKGBUILD`: Arch package systemd unit, sysusers account, and local package build
- `docs/`: permission, ownership, service configuration contracts, fresh-Arch onboarding, and host-specific integration requirements
- `scripts/`: `deploy-test.sh` (build, upload, start on an explicitly selected Arch test VM) and `restart.sh`

## Local Contracts

- All pages and APIs require a login session; only login page, logout endpoint, and static assets are public
- Config pages are read-only by default; explicit root-mode actions use allowlisted fixed command arguments, never arbitrary shell input (see `docs/permissions.md`)
- System configuration may set hostname, installed `LANG` locale, and listed timezone through `hostnamectl`, `localectl`, and `timedatectl`; `/etc/hosts`, other `LC_*` values, and keyboard settings remain untouched
- Admin login validates via the root helper's PAM check (`SWAT_PAM_SERVICE` on `swat-privileged`, default `login`); the helper rechecks admin credentials through `SWAT_SUDO_PAM_SERVICE` (default PAM stack `sudo`) for each action; no `sudo` executable or sudoers policy is used by the web process
- Firewall zones: SWAT owns only the `inet swat` nftables table; unlisted traffic between zones is blocked, interfaces outside every zone are untouched; apply = `nft -c` check, load, then confirm within 60 s or automatic rollback; every zone action is audit-logged
- Stable adapter names use early-ordered, SWAT-owned `systemd.link` files matching permanent MAC addresses; changing a name must coordinate SWAT networkd and nftables references and must not rename a live management interface without reboot-safe recovery
- Network adapter name edits are stored as versioned SWAT desired state and previewed; do not write `/etc/systemd/network` until reboot-safe recovery and networkd/nftables reference migration are implemented
- Native configuration writers may modify only fixed service-owned directories and files carrying the matching SWAT marker and Config-ID; target paths must never come from request data, and writers do not activate network changes or replace reboot-safe recovery
- State dir defaults to `~/.local/state/swat` (`SWAT_STATE_DIR`); confirmed rules are installed to `/etc/swat/swat.nft`
- The packaged `swat.service` listens on IPv4 interfaces at TLS port 8443, runs as the unprivileged `swat` account; it creates a persistent self-signed certificate on first start and does not alter firewall rules
- The packaged service permits `AF_NETLINK` for unprivileged network-interface inventory; do not add Linux capabilities for this read-only access
- The generated TLS key stays in the protected SWAT state directory with mode 0600; custom certificates and keys use systemd credentials, and source key permissions must not be broadened
- All privileged mutations go through `swat-privileged` as typed allowlisted operations. The helper requires peer UID `swat`, independently authenticates the requesting administrator through PAM, and writes helper-side audit start/result records. It never accepts generic commands or arbitrary paths; the web application uses no sudoers policy.
- Test deployments require an explicit destination; use the designated fresh Arch VM and never assume the physical host is a deployment target

## Work Guidance

- Prefer system commands, the standard library, and existing dependencies; add new dependencies only when necessary
- Account tables show actions only for real interactive users; technical accounts such as `nobody` stay read-only
- Table action columns are right-aligned consistently
- In equal-height form cards, dock action buttons to the bottom
- Update `README.md` and the matching `docs/` page when navigation or permission behavior changes
- Pages in `cmd/swat/web/templates/` use the global `layout.html`: define `title`, `subtitle`, `content` (optional `head`, `toolbar`, `header-actions`, `scripts`) and end the file with `{{template "layout" .}}`; `login.html` uses `auth-layout`; shared fragments live in `partials.html`; never repeat `<html>`, nav, or script tags in a page

## Verification

- `go build ./...` and `go test ./...` from `swat/`

## Child DOX Index

- `internal/modules/AGENTS.md`: module registry, profile selection, dependency and readiness contracts
- `internal/moduleadmin/AGENTS.md`: privileged module installer protocol and peer authorization
- `cmd/swat-privileged/AGENTS.md`: root-owned systemd service lifecycle and socket setup
