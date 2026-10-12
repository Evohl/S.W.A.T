# SWAT Privileged Helper

## Purpose

- Run the narrowly allowlisted module package installer and the login and sudo PAM checks as root behind a local Unix socket.

## Ownership

- `main.go`: socket lifecycle, `swat` account/group lookup, and helper startup
- `packaging/swat-privileged.service`: root-owned systemd unit

## Local Contracts

- Bind only `/run/swat-privileged/modules.sock`, owned by `root:swat` with mode `0660` inside a `root:swat` mode-`0750` directory.
- Refuse to replace a non-socket path and authenticate the connecting peer UID in the protocol layer.
- The helper must remain a package-only allowlist; it does not accept generic commands or start services.
- Append a helper-side audit record before any package-manager call; refuse the operation if audit storage is unavailable.
- Module installation: the calling system account must be `root` or a member of Arch `wheel`, and is authenticated by PAM for every request.
- Login: any system account accepted by the `SWAT_PAM_SERVICE` PAM stack (default `login`) is accepted; no wheel requirement.
- Sudo re-check: root or `wheel` only, through the `SWAT_SUDO_PAM_SERVICE` PAM stack (default `sudo`).

## Work Guidance

- Do not add general-purpose file writes, systemctl actions, or arbitrary command execution to this daemon.

## Verification

- `go test ./cmd/swat-privileged ./internal/moduleadmin`
- Inspect the packaged systemd unit and socket permissions when changing lifecycle behavior.

## Child DOX Index

- None