# SWAT permissions

This document defines the permission boundary for authenticated read access and helper-mediated write actions.

## Process model

SWAT must run as a dedicated unprivileged system user, not as root. A web login must never turn the whole web process into root.

```text
browser -> SWAT (User=swat) -> read-only Linux APIs
                              -> typed root-helper operations
```

The authenticated application user and the Linux process user are separate concepts.

## Normal user: visible information

The default read-only session may see:

- overview and system health
- systemd service status and descriptions
- storage devices, filesystems, and mount points
- virtual machine inventory and state
- permitted journal entries
- network interfaces, addresses, routes, and DNS status
- firewall status and rules, where the operating system permits read access

Read-only pages must render a useful unavailable state when the host denies access. They must not require root merely to load the dashboard.

## Normal user: no changes

A normal user must not be able to:

- start, stop, restart, enable, or disable services
- change NetworkManager connections, routes, or DNS
- add, remove, or modify nftables rules
- mount, unmount, format, partition, or modify storage
- start, stop, pause, or reconfigure virtual machines
- write system files or execute arbitrary commands
- read logs outside the user's permitted journal scope

These actions must not be exposed as active controls in the normal navigation.

## Administrative session

The UI asks the root helper to validate a system account through PAM and
provides a short-lived `SWAT_Admin` login session. The session submits the
administrator password for independent PAM checks in the root helper; the web
process never becomes root merely because a user logged in.

All application pages and API endpoints require an active session. Only the
login/logout endpoints and static assets are reachable without authentication.

Administrative actions must be explicit allowlisted operations, for example:

- restart one approved systemd unit
- start or stop one approved virtual machine
- reload one approved network connection
- add or remove one approved firewall rule
- set the static hostname, installed system locale, or listed timezone

The backend must reject unknown actions, unknown targets, and actions that do not match the user's role. It must never pass arbitrary user input to a shell.

## Roles

- `viewer`: read-only information
- `operator`: approved service and VM operations
- `admin`: approved configuration operations

A web user named `root` is not automatically the Linux root user. Linux privileges come only from explicit allowlisted helper operations; the SWAT process itself does not run as root.

## Audit requirements

Every privileged operation must record:

- timestamp
- authenticated user
- action and target
- result
- failure reason, if any

The default session remains read-only. Root-mode actions require an active
session and CSRF validation, validate target values, use fixed command argument
lists, and append audit records. They do not grant arbitrary command or file
access.

The Arch package service does not set `SWAT_READ_ONLY`. All privileged
mutations use independently PAM-checked typed operations in
`swat-privileged`; the package installs no sudoers rules. The
service listens on TLS port 8443. It generates a persistent self-signed certificate
on first start. The generated private key is stored mode 0600 under the
protected SWAT state directory; custom certificate keys are delivered through
systemd credentials. See
[`https-deployment.md`](https-deployment.md).
The unit allows `AF_NETLINK` so the unprivileged service can enumerate network
interfaces; it receives no network-administration capabilities.
`swat-privileged` is a root-owned Unix-socket helper that accepts requests only
from peer UID `swat`. It performs its own check for `root` or membership in
Arch's `wheel` administrator group, then authenticates the account independently
through PAM for every operation. Its operations are typed and allowlisted across
system settings, accounts/groups, catalog services, networking, firewall, and
Libvirt. Package names come only from the compiled registry. Audit entries are
written by the helper before and after mutations; credentials and full XML
payloads are not logged. The web session currently keeps the administrator
password in
memory until access is restricted or the session expires. Network/firewall
rollback timers live in the helper so a web-process restart does not cancel
recovery. The helper has no generic command or arbitrary path operation.
