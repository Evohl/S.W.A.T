# S.W.A.T (System Web Administration Tool)

## Purpose

- Go web dashboard for an Arch Linux homeserver; reads systemd, `ip`, `lsblk`, `journalctl`, `virsh`, nftables directly

## Ownership

- `cmd/swat/`: HTTP server, handlers, templates, static assets (`web/`, vendored `spice-html5` and `xterm`)
- `cmd/servman/`: separate static assets
- `internal/collect/`: read-only data collectors for host state
- `internal/zones/`: firewall zone/policy model, validation, nftables generator, desired-state store (`zones.json` in `SWAT_STATE_DIR`)
- `internal/audit/`: append-only JSON audit log (`audit.log` in the state dir)
- `PKGBUILD` and `packaging/`: local Arch package build, read-only systemd unit, and sysusers account
- `packaging/` and `PKGBUILD`: Arch package systemd unit, sysusers account, and local package build
- `docs/`: permission, ownership, and configuration contracts
- `scripts/`: `deploy-test.sh` (build, upload, start on homeserver) and `restart.sh`

## Local Contracts

- All pages and APIs require a login session; only login page, logout endpoint, and static assets are public
- Config pages are read-only by default; explicit root-mode actions use allowlisted fixed command arguments, never arbitrary shell input (see `docs/permissions.md`)
- System configuration may set hostname, installed `LANG` locale, and listed timezone through `hostnamectl`, `localectl`, and `timedatectl`; `/etc/hosts`, other `LC_*` values, and keyboard settings remain untouched
- Admin login validates via PAM (`SWAT_PAM_SERVICE`, `SWAT_SUDO_PAM_SERVICE`) and creates short-lived sessions only
- Firewall zones: SWAT owns only the `inet swat` nftables table; unlisted traffic between zones is blocked, interfaces outside every zone are untouched; apply = `nft -c` check, load, then confirm within 60 s or automatic rollback; every zone action is audit-logged
- State dir defaults to `~/.local/state/swat` (`SWAT_STATE_DIR`); confirmed rules are installed to `/etc/swat/swat.nft`
- The packaged `swat.service` is loopback-only, runs as the unprivileged `swat` account, and sets `SWAT_READ_ONLY=1`; do not grant it sudoers permissions as a substitute for the planned privileged helper
- The packaged `swat.service` is loopback-only, runs as the unprivileged `swat` account, and sets `SWAT_READ_ONLY=1`; do not grant it sudoers permissions as a substitute for the planned privileged helper

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

- None
