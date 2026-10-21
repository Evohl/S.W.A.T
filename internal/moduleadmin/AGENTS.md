# Module Installer Protocol

## Purpose

- Provide bounded application clients and the root-helper protocol for audited privileged server operations.

## Ownership

- `protocol.go`, `transactions.go`, `vm.go`: Unix-socket protocol, peer-credential server, independent PAM checks, mandatory audit, typed host/account/service/network/firewall/Libvirt actions, and confirm/rollback transactions
- `cmd/swat-privileged/`: root service process and socket permissions
- `packaging/swat-privileged.service`: systemd lifecycle and runtime directory

## Local Contracts

- Accepted operations are typed and allowlisted: module installation by compiled profile ID; PAM checks; system settings; account/group operations; catalog service lifecycle; IPv4/IPv6 forwarding; SWAT bridge/firewall transactions; and bounded Libvirt VM/storage operations.
- `authenticate-login` and `authenticate-sudo` must never run PAM in the `swat` process; they stay in the root helper.
- Authenticate the peer as the dedicated `swat` UID using `SO_PEERCRED`; require the submitted system account to be `root` or a member of `wheel`; independently authenticate it through PAM.
- Never accept shell text, arbitrary commands, arbitrary units, or arbitrary file targets. File operations are restricted to fixed SWAT-owned directories and validated identifiers. Validate operation inputs again in the helper.
- Every mutation requires independent PAM authorization and a successful helper-side audit-start record before execution; append the result or failure afterward.
- Do not log credentials or full sensitive XML/config payloads. Limit request size and operation duration.
- Network/firewall rollback timers run in the helper, not the web process.
- Do not start or enable catalog services marked `ConfigurationRequired` until a reviewed, validated service-configuration apply operation exists.
- Package installation requires explicit web confirmation and an audit entry before invoking the helper.

## Work Guidance

- Keep privileged behavior narrow. Add a new operation only with a specific allowlist, independent authorization, and tests for invalid inputs, audit failures, and unauthorized peers.

## Verification

- `go test ./internal/moduleadmin ./cmd/swat-privileged`
- `go test ./...` and `go build ./...` from `swat/`

## Child DOX Index

- None