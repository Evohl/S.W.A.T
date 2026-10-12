# S.W.A.T: Homeserver-Anforderungen

Status: Anforderungen für den geplanten Betrieb auf einem Arch-Homeserver, abgeleitet aus dem read-only Ist-Stand vom 2026-10-11. Keine Konfigurationsänderungen sind damit freigegeben.

## Ausgangspunkt

- S.W.A.T ist unfertig; das Paket lauscht read-only per HTTPS auf Port 8443 und erstellt beim ersten Start ein selbstsigniertes Zertifikat. Firewall-Regeln werden nicht automatisch geändert.
- Auf dem Zielhost laufen NetworkManager, dhcpcd, dnsmasq und firewalld gleichzeitig; `systemd-networkd` und `systemd-resolved` sind inaktiv.
- Starlink soll über einen eigenen, nicht gebridgten Ethernet-Port als Rückfall-WAN dienen.
- DHCP und IPv6-RA laufen derzeit über dnsmasq; die IPv6-Prefix-Delegation ist noch nicht geklärt.

## Prioritäten

### P0: Sicherer Netzwerk-MVP

1. **Ownership anzeigen:** aktive und aktivierte Units, Interfaces, Default-Routen, DHCP-/RA-/DHCPv6-PD-Zuständigkeit, DNS-Resolver, Firewall-Zonen und Listener zusammenführen. Konflikte wie NetworkManager plus dhcpcd auf denselben Interfaces konkret benennen; Dienste nie automatisch deaktivieren.
2. **Privilegien begrenzen:** dedizierter Polkit-Helper mit festem, validiertem Operationsumfang, Audit-Log und kurzer Autorisierung. Keine beliebigen Shell-Eingaben und keine pauschalen sudoers-Rechte. Das Paket bleibt read-only, bis diese Grenze umgesetzt und geprüft ist.
3. **Desired State und Ownership beweisen:** strukturierte Eingaben erzeugen ausschließlich SWAT-eigene Dateien wie `90-swat-*.network`/`.netdev`; Marker plus Manifest/Hashes belegen Eigentum. Fremde NM-, dhcpcd-, dnsmasq- und systemd-Dateien nur anzeigen, nie überschreiben.
4. **Netzwerk-Transaktion:** vor dem Schreiben Konflikte und Syntax prüfen, Änderungen atomar installieren und einen systemd-Rollback-Timer außerhalb des Webprozesses starten. Erst nach bestätigten Erreichbarkeitstests wird die Transaktion übernommen; der Rollback stellt Dateien und vorherige Dienstzustände wieder her.
5. **systemd-networkd abbilden:** WAN, Bridge und Ports einschließlich DHCPv4, DHCPv6-PD und Prefix-Verteilung modellieren. Aktuelles IPv6-Präfix auf WAN und LAN getrennt darstellen; RA-only auf einer LAN-Bridge nicht mit Provider-PD verwechseln.
6. **dnsmasq und Resolver schützen:** bestehende DHCP-Range, Leases, Gateway, DNS und RA sichtbar machen. DHCP darf nie unabsichtlich auf WAN starten; Port-53/67-Konflikte vor Apply erkennen. `systemd-resolved` erst übernehmen, wenn Resolver- und `/etc/resolv.conf`-Ownership eindeutig sind.
7. **Firewall-Verantwortung klären:** aktive firewalld-Regeln und Policies müssen vor jeder Änderung sichtbar sein. SWAT darf `inet swat` nicht parallel zu firewalld ändern, solange Koexistenz und zusammengesetzte Drop-Wirkung nicht getestet sind. NAT/DNAT und Sets strikt nach den Grenzen in `network-configuration.md` validieren.

### P1: Verfügbarkeit und Betrieb

- Zweit-WAN auf dediziertem Interface unterstützen: getrennte Zone/Bridge, Routenpriorität, Masquerade und echte Verbindungsgesundheitsprüfung; ein Link-up allein ist kein Internet-Failover.
- Listener, Prozess, Bind-Adresse und wirksame Firewall-Freigabe gemeinsam darstellen. Ein Wildcard-Bind ist nicht automatisch öffentlich erreichbar.
- Servicesicht um Unit-Abhängigkeiten, Systemuser, Ports, Konfigurations- und Datenpfade sowie Backup-/Restore-Zuordnung erweitern.
- Runbooks und Best-Practice-Quellen (Arch Wiki oder Upstream) pro verwaltetem Dienst verlinken.

## Abnahmekriterien für den Netzwerk-MVP

- Alle bestehenden Zustände werden zunächst read-only erkannt; fremde Konfigurationen bleiben unverändert.
- Test auf einem isolierten Interface funktioniert, ohne NetworkManager, dhcpcd und networkd gleichzeitig darauf zu aktivieren.
- Apply hat unabhängigen, getesteten Rückweg auch nach S.W.A.T-Neustart oder verlorener Browserverbindung.
- IPv4, IPv6, DHCP, DNS, VMs und Home Assistant werden vor Commit geprüft; fehlgeschlagener Test löst Rollback aus.
- Firewall-Änderungen werden separat geplant und bestehen nftables-Validierung sowie Bestätigung/Rollback.

## Umsetzung

Zuerst read-only Ownership und Firewall-Transparenz vervollständigen, dann den Helper und Transaktions-Rollback bauen, danach systemd-networkd/DNS-Writer testen. Starlink-Failover und Dienste-/Backup-Verwaltung folgen separat. Bestehende Verträge: [Netzwerkkonfiguration](network-configuration.md), [Berechtigungen](permissions.md), [Service-Ownership](service-ownership.md).