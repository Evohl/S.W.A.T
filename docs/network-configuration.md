# Netzwerk-Konfiguration

SWAT verwaltet Netzwerk nicht als eigenen Daemon. Es modelliert den gewünschten Zustand und delegiert die Ausführung an die nativen Linux-Komponenten.

## Zuständigkeiten

| Aufgabe | Komponente |
|---|---|
| Interfaces, Adressen, Routen, VLAN, Bridge, Bond und Tunnel | `systemd-networkd` |
| Host-DNS, Cache und Split-DNS | `systemd-resolved` |
| DHCP, lokale Namen, einfache RA/DHCPv6- und PXE-Netze | `dnsmasq` |
| Forwarding und Kernel-Netzparameter | `sysctl` / `/etc/sysctl.d` |
| Zonen, Forwarding-Policy und NAT | `nftables` |
| WLAN-Client oder Access Point | `iwd`/`wpa_supplicant` und `hostapd` |

SWAT erkennt konkurrierende Besitzer und schreibt keine Dateien eines fremden Besitzers um.

## Erkennung der SWAT-Verwaltung

Der aktive native Dienst allein bedeutet nicht, dass SWAT die Konfiguration
verwaltet. SWAT unterscheidet deshalb zwischen:

- **technischem Owner**: der aktuell aktive Dienst, zum Beispiel
  `NetworkManager.service` oder `systemd-networkd.service`
- **SWAT-Owner**: ein Bereich, für den eine gültige SWAT-Desired-State-Datei
  und/oder eine von SWAT erzeugte native Datei nachgewiesen ist

Für generierte Dateien werden künftig mehrere Hinweise kombiniert:

1. SWAT-eigener Dateiname und Pfad, zum Beispiel `90-swat-lan.network`
2. Marker in der Datei, zum Beispiel:

   ```ini
   # Managed-By: SWAT
   # SWAT-Config-ID: network/lan
   # SWAT-Generation: <transaction-id>
   ```

3. SWAT-Besitzmanifest mit erwarteten Dateien, Hashes und Transaktions-ID

Nur ein passender Nachweis darf die Anzeige „SWAT verwaltet diesen Bereich
über `systemd.network`“ auslösen. Eine zufällig gleich benannte Datei oder ein
laufender Dienst reicht nicht. Fremde Dateien bleiben externe Konfiguration
und werden nicht automatisch übernommen.

## Read-only Datenmodell

Die Netzwerkseite zeigt zunächst:

- Interface-Zustand und Adressen
- `systemd-networkd`- und `systemd-resolved`-Status
- IPv4- und IPv6-Forwarding
- Resolver-Zustand
- erkannte `.network`, `.netdev` und `.link`-Dateien

Die Anzeige bleibt schreibgeschützt, bis Authentifizierung, Rollen, Polkit-Helper und Audit-Log vorhanden sind.

## Schreibmodell für später

SWAT sollte keine bestehenden Dateien neu formatieren oder mit hunderten auskommentierten Beispielzeilen ergänzen. Stattdessen gilt:

1. Fremde Dateien bleiben unangetastet und werden nur als Konflikt oder externe Konfiguration angezeigt.
2. SWAT besitzt ausschließlich eindeutig benannte Dateien, zum Beispiel `90-swat-lan.network` oder `90-swat-vm.netdev`.
3. Die UI arbeitet mit einem strukturierten Modell, nicht mit freien Textfeldern als primärer Quelle.
4. Der Generator schreibt minimale, vollständige Dateien ohne Kommentarballast.
5. Vor dem Aktivieren wird in eine temporäre Datei geschrieben und syntaktisch validiert.
6. Aktivierung, Reload und Rollback werden als eine auditierte Transaktion behandelt.
7. Der gewünschte Zustand bleibt von der aktuell wirksamen Konfiguration getrennt sichtbar.

Ein späterer Konfigurationsbaum könnte so aussehen:

```text
/etc/swat/network/
  desired.yaml

/etc/systemd/network/
  90-swat-lan.network
  90-swat-vm.netdev
  90-swat-vm.network
```

`desired.yaml` wäre SWAT-eigene Quelle für den gewünschten Zustand. Die Dateien unter `/etc/systemd/network` wären generierte Artefakte. Sie dürfen niemals manuell und gleichzeitig durch SWAT bearbeitet werden.

## Sicherheitsregeln

- Keine Änderungen an WAN-Interfaces ohne explizite Bestätigung.
- Keine Aktivierung von DHCP auf einem als WAN erkannten Interface.
- Keine Änderung von Forwarding ohne passende Firewall-Prüfung.
- Keine DNS- oder DHCP-Aktivierung bei belegtem Port 53 oder 67/68.
- Vor Reload immer Syntax-, Ownership- und Erreichbarkeitsprüfung.
- Bei Fehlern automatische Rückkehr zur letzten gültigen SWAT-Konfiguration.

## Zonen und Inter-Zonen-Firewall

Die Seite `/firewall` (früher `/zones`) verwaltet Firewall-Zonen über eine eigene nftables-Tabelle `inet swat` und zeigt darunter das aktive Regelwerk.

- **Zone**: Gruppe von Interfaces mit Eingangsmodus (`restricted` mit Diensten/Ports und optional Ping, oder `accept`) und optionaler Isolation der Mitglieder.
- **Richtlinie**: pro geordnetem Zonenpaar `allow` oder `limited` (Dienste/Ports), optional mit Masquerade. Ohne Richtlinie ist der Verkehr zwischen Zonen gesperrt.\n- **Port-NAT**: Pro Dienst (nur bei eindeutiger Portnummer) und pro eigenem Port kann ein Ziel \u201e\u00dcbersetzen nach\u201c gesetzt werden: `80` (nur Port, `dnat to :80`) oder `10.0.0.5:80` / `[2001:db8::5]:80` (Weiterleitung an einen Host). Die \u00dcbersetzung gilt f\u00fcr Verkehr, der aus der Quell-Zone eintrifft; die Forward-Freigabe passt auf den \u00fcbersetzten Port. Port-Bereiche k\u00f6nnen nicht \u00fcbersetzt werden, Zonen selbst kennen kein NAT.
- Interfaces ohne Zone bleiben unberührt; Rückverkehr (`established,related`) ist immer erlaubt; IPv6-Neighbor-Discovery und DHCP-Client-Antworten bleiben in eingeschränkten Zonen offen.
- Der Generator (`internal/zones`) validiert streng und ersetzt die Tabelle atomar. Gewünschter Zustand: `zones.json` im State-Verzeichnis (`SWAT_STATE_DIR`).
- Anwenden: `nft -c`, Laden, danach 60 Sekunden Bestätigungsfenster; ohne Bestätigung stellt SWAT die zuletzt bestätigte Tabelle wieder her (Prozessneustart in dieser Zeit verhindert den Rollback). Bestätigte Regeln liegen unter `/etc/swat/swat.nft` und müssen in `/etc/nftables.conf` eingebunden werden.
- Koexistenz mit firewalld ist nicht aufgelöst: beide Tabellen werden unabhängig ausgewertet, ein Drop in einer Tabelle gilt.

## IP-Forwarding

Die Netzwerkseite schaltet IPv4 (`net.ipv4.ip_forward`) und IPv6 (`net.ipv6.conf.all.forwarding`) im Root-Modus per `sysctl -w` um und speichert den Zustand beider Familien in `/etc/sysctl.d/90-swat-forwarding.conf`. Jede Änderung wird im Audit-Log protokolliert.