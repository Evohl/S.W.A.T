# S.W.A.T (System Web Administration Tool)

## Purpose

- Go web dashboard and guided setup tool for fresh Arch Linux systems; reads systemd, `ip`, `lsblk`, `journalctl`, `virsh`, nftables directly

## Ownership

- `cmd/swat/`: HTTP server, handlers, templates, static assets (`web/`, vendored `spice-html5` and `xterm`)
- `cmd/servman/`: separate static assets
- `internal/collect/`: read-only data collectors for host state
- `internal/configwrite/`: ownership-aware atomic writer for SWAT-managed native configuration files
- `internal/modules/`: central Arch service-profile registry, package/service status, and persisted selection
- `internal/moduleadmin/`: fixed-ID Unix-socket protocol and allowlisted package installer with independent PAM authorization
- `cmd/swat-privileged/`: root-owned module installer daemon; no generic commands, paths, service activation, or systemd operations
- `internal/zones/`: firewall zone/policy model, validation, nftables generator, desired-state store (`zones.json` in `SWAT_STATE_DIR`)
- `internal/audit/`: append-only JSON audit log (`audit.log` in the state dir)
- `PKGBUILD` and `packaging/`: local Arch package build, read-only systemd unit, and sysusers account
- `packaging/` and `PKGBUILD`: Arch package systemd unit, sysusers account, and local package build
- `docs/`: permission, ownership, service configuration contracts, fresh-Arch onboarding, and host-specific integration requirements
- `scripts/`: `deploy-test.sh` (build, upload, start on an explicitly selected Arch test VM) and `restart.sh`

## Local Contracts

- All pages and APIs require a login session; only login page, logout endpoint, and static assets are public
- Config pages are read-only by default; explicit root-mode actions use allowlisted fixed command arguments, never arbitrary shell input (see `docs/permissions.md`)
- System configuration may set hostname, installed `LANG` locale, and listed timezone through `hostnamectl`, `localectl`, and `timedatectl`; `/etc/hosts`, other `LC_*` values, and keyboard settings remain untouched
- Admin login validates via PAM (`SWAT_PAM_SERVICE`, `SWAT_SUDO_PAM_SERVICE`) and creates short-lived sessions only
- Firewall zones: SWAT owns only the `inet swat` nftables table; unlisted traffic between zones is blocked, interfaces outside every zone are untouched; apply = `nft -c` check, load, then confirm within 60 s or automatic rollback; every zone action is audit-logged
- Stable adapter names use early-ordered, SWAT-owned `systemd.link` files matching permanent MAC addresses; changing a name must coordinate SWAT networkd and nftables references and must not rename a live management interface without reboot-safe recovery
- Network adapter name edits are stored as versioned SWAT desired state and previewed; do not write `/etc/systemd/network` until reboot-safe recovery and networkd/nftables reference migration are implemented
- Native configuration writers may modify only fixed service-owned directories and files carrying the matching SWAT marker and Config-ID; target paths must never come from request data, and writers do not activate network changes or replace reboot-safe recovery
- State dir defaults to `~/.local/state/swat` (`SWAT_STATE_DIR`); confirmed rules are installed to `/etc/swat/swat.nft`
- The packaged `swat.service` is loopback-only, runs as the unprivileged `swat` account, and sets `SWAT_READ_ONLY=1`; do not grant it sudoers permissions as a substitute for the planned privileged helper
- The only packaged privileged module operation is the separate root-owned helper. It requires peer UID `swat` plus independent PAM authentication, accepts compiled module IDs, installs only fixed package lists, and never starts configuration-required units
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
