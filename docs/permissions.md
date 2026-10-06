# SWAT permissions

This document defines the permission boundary before authentication and write actions are implemented.

## Process model

SWAT must run as a dedicated unprivileged system user, not as root. A web login must never turn the whole web process into root.

```text
browser -> SWAT (User=swat) -> read-only Linux APIs
                              -> fixed, validated sudo command allowlist
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

The UI validates a system account through PAM and provides a short-lived
`SWAT_Admin` login session. The session can then submit the sudo password for
a second PAM check to request administrative access. The current
implementation invokes fixed commands through `sudo`; the web process never
becomes root merely because a user logged in.

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

A web user named `root` is not automatically the Linux root user. Linux privileges come only from explicit, allowlisted sudo operations; the SWAT process itself does not run as root.

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

The Arch package service sets `SWAT_READ_ONLY=1`. In this mode root access is
hidden from the session view, root requests are rejected, and both sudo command
runners refuse execution. The service runs as the unprivileged `swat` user and
does not install sudoers permissions. Do not disable this mode until a
separately reviewed privileged helper or Polkit boundary replaces the current
sudo command path.

The Arch package service sets `SWAT_READ_ONLY=1`. In this mode root access is
hidden from the session view, root requests are rejected, and both sudo command
runners refuse execution. The service runs as the unprivileged `swat` user and
does not install sudoers permissions. Do not remove read-only mode until a
separately reviewed privileged helper or Polkit boundary replaces the current
sudo command path.
