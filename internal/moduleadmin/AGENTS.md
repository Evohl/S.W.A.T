# Module Installer Protocol

## Purpose

- Provide the bounded application client and root-helper protocol for installing selected Arch module package dependencies.

## Ownership

- `protocol.go`: Unix-socket client, peer-credential server, PAM-authenticated request, and fixed-catalog pacman operation
- `cmd/swat-privileged/`: root service process and socket permissions
- `packaging/swat-privileged.service`: systemd lifecycle and runtime directory

## Local Contracts

- Accepted operations: `install-modules` with known compiled module IDs; `authenticate-login` (any system account, audited as `auth/login`); `authenticate-sudo` (root or `wheel` only, audited as `auth/sudo`). Auth operations return OK or a generic failure and never echo the password.
- `authenticate-login` and `authenticate-sudo` must never run PAM in the `swat` process; they stay in the root helper.
- Authenticate the peer as the dedicated `swat` UID using `SO_PEERCRED`; require the submitted system account to be `root` or a member of `wheel`; independently authenticate it through PAM.
- Never accept package names, paths, service names, shell text, or arbitrary operation names from the client.
- The helper may query/install only catalog packages with fixed pacman arguments; it does not run systemctl or activate services.
- The helper must append its own audit-start record before invoking pacman and refuse the operation if that record cannot be written.
- Do not log or persist sudo passwords. Limit request size and operation duration.
- Package installation requires explicit web confirmation and an audit entry before invoking the helper.

## Work Guidance

- Keep privileged behavior narrow. Add a new operation only with a specific allowlist, independent authorization, and tests for invalid IDs and unauthorized peers.

## Verification

- `go test ./internal/moduleadmin ./cmd/swat-privileged`
- `go test ./...` and `go build ./...` from `swat/`

## Child DOX Index

- None