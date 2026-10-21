# SWAT Privileged Helper

## Purpose

- Run typed, allowlisted server administration operations and PAM checks as root behind a local Unix socket.

## Ownership

- `main.go`: socket lifecycle, `swat` account/group lookup, and helper startup
- `packaging/swat-privileged.service`: root-owned systemd unit

## Local Contracts

- Bind only `/run/swat-privileged/modules.sock`, owned by `root:swat` with mode `0660` inside a `root:swat` mode-`0750` directory.
- Refuse to replace a non-socket path and authenticate the connecting peer UID in the protocol layer.
- Accept only typed operations implemented in `internal/moduleadmin`; do not accept generic commands, arbitrary paths, or free-form service commands.
- Append a helper-side audit record before every mutation; refuse the operation if audit storage is unavailable, and record the result afterward.
- Network and firewall confirmation/rollback windows are owned by the helper process.
- Module installation: the calling system account must be `root` or a member of Arch `wheel`, and is authenticated by PAM for every request.
- Login: any system account accepted by the `SWAT_PAM_SERVICE` PAM stack (default `login`) is accepted; no wheel requirement.
- Admin re-check: root or `wheel` only, through the `SWAT_SUDO_PAM_SERVICE` PAM stack (default PAM service name `sudo`); the helper does not execute the `sudo` program.

## Work Guidance

- Keep file and command targets fixed or strictly validated by the operation implementation. Do not add generic file writes or arbitrary command execution to this daemon.

## Verification

- `go test ./cmd/swat-privileged ./internal/moduleadmin`
- Inspect the packaged systemd unit and socket permissions when changing lifecycle behavior.

## Child DOX Index

- None