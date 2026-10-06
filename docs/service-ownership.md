# SWAT service ownership

SWAT treats enabled and active services as an ownership problem, not just a list. The dashboard must show which native service is responsible for each host capability and flag competing services.

## Service domains

| Domain | Preferred owner | Alternatives that must be detected | Typical responsibility |
|---|---|---|---|
| Network management | `systemd-networkd.service` | `NetworkManager.service`, `dhcpcd.service`, `connman.service` | Interfaces, addresses, routes, links |
| DNS resolver | `systemd-resolved.service` or NetworkManager-managed DNS | `dnsmasq.service`, `unbound.service` | Local resolver and upstream DNS |
| DHCP/DNS server | `dnsmasq.service` or Kea | `kea-dhcp4-server.service`, `kea-dhcp6-server.service` | LAN leases and local DNS |
| Firewall | `firewalld.service` | `ufw.service`, direct nftables rules | Policy and firewall configuration |
| Virtualization | `libvirtd.service` / `virtqemud.service` | Docker, Podman | Libvirt and QEMU guests |
| Containers | Docker or Podman | The other container engine | Container lifecycle and networks |
| Time sync | `systemd-timesyncd.service` | `chronyd.service`, `ntpd.service` | System clock synchronization |
| mDNS/service discovery | `avahi-daemon.service` | other mDNS responders | `.local` discovery |

The table is a policy model. A detected alternative is not automatically a failure: SWAT must distinguish an intentional setup from two active owners managing the same resource.

The native service owner and SWAT configuration ownership are separate facts.
For example, `systemd-networkd.service` may be active without SWAT managing
any network file. SWAT may only claim management after it has verified its own
desired-state or generated file, an `Managed-By: SWAT` marker, and the matching
ownership manifest. The UI should then say, for example:

> SWAT verwaltet diesen Bereich über `systemd.network`.

Without that proof, the UI names only the native owner:

> `systemd-networkd.service` verwaltet diesen Bereich.

## SWAT management scope

SWAT plans controlled management only for these domains:

- **Network** through native `systemd-networkd` configuration
- **DNS resolver** through native `systemd-resolved` configuration
- **Firewall** through native nftables or firewalld configuration

These domains remain read-only until an authenticated writer, validation,
rollback, ownership proof, and audit logging are available. Virtualization,
time synchronization, and mDNS are currently inventory-only domains: SWAT may
show their owner and conflicts but does not manage their configuration.

## Detection states

For every known service, collect both systemd states:

- `enabled`: starts automatically at boot
- `active`: currently running
- `masked`: explicitly blocked
- `installed`: unit file or provider command exists

The UI should show one responsibility row per domain:

- **OK**: one preferred owner is active and no competing owner is active
- **Warning**: multiple owners are enabled or active
- **Missing**: no owner is available
- **Inactive**: an owner is installed but currently stopped
- **Manual**: more than one owner is intentionally configured and SWAT cannot prove a conflict

## Network-specific checks

Network conflicts need more than unit states. SWAT should also inspect:

- `nmcli device status`
- `networkctl list`
- `ip -j route show`
- `/etc/systemd/network/*.network`
- DHCP clients and default routes
- DNS ownership through `/etc/resolv.conf` and resolver status

A warning should name the exact services and interfaces involved, for example:

> NetworkManager and systemd-networkd are both active. `enp5s0` has a NetworkManager connection and a matching systemd-networkd configuration. Choose one owner.

## UI presentation

The Overview page should contain a **Service ownership** section with:

- domain
- responsible service
- active/enabled state
- affected interfaces or resources
- purpose in one sentence
- conflict warning
- recommended next action

The Services page remains the detailed systemd inventory. The ownership view is the human explanation layer on top of that inventory.

## Native-only policy

SWAT should prefer Arch/Linux-native interfaces:

- systemd and `systemctl`
- `networkctl` when systemd-networkd owns networking
- NetworkManager CLI and D-Bus only when NetworkManager explicitly owns networking
- `iproute2`
- nftables/firewalld status
- libvirt CLI or D-Bus
- `journalctl`

SWAT must never silently disable a service. Remediation can be suggested first; actual changes belong in the future authenticated Administration section and require explicit confirmation.
