# Module und Dienstprofile

## Zentrale Auswahl

`/modules` ist die zentrale Registry für SWAT-Funktionen. Das Netzwerk-
Grundprofil ist erforderlich und standardmäßig ausgewählt. Weitere Profile
zeigen Zweck, direkte Arch-Pakete, optionale Pakete und zugehörige systemd-
Units. Beispiele:

| Profil | Pakete | Dienste |
|---|---|---|
| Netzwerk-Grundlage (erforderlich) | `systemd`, `iproute2` | `systemd-networkd.service`, `systemd-resolved.service` |
| nftables-Firewall | `nftables` | `nftables.service` |
| WLAN-Hotspot | `hostapd`, `dnsmasq`, `iw` | `hostapd.service`, `dnsmasq.service` |
| Nginx | `nginx` | `nginx.service` |
| Mailserver | `postfix`, `dovecot`, `rspamd`; `redis` optional | Postfix, Dovecot, Rspamd und optional Redis |
| Fail2ban | `fail2ban` | `fail2ban.service` |

Die Auswahl wird versioniert als `$SWAT_STATE_DIR/modules.json` mit Modus
`0600` gespeichert. Nicht ausgewählte Profile werden nicht installiert;
das Netzwerk-Grundprofil kann nicht abgewählt werden. Abwählen entfernt keine
Pakete und stoppt/deaktiviert keine Dienste.
Eine Konfigurationsseite ist erst erreichbar, wenn ihr Profil ausgewählt und
alle Pflichtpakete installiert sind. Die Navigation blendet sie bis dahin aus.

## Installation und Berechtigungen

Die Weboberfläche verlangt eine frische PAM-Prüfung und eine explizite
Bestätigung der sichtbaren Paketänderung. Sie sendet feste Profil-IDs sowie
Benutzername und Passwort nur an `swat-privileged` über
`/run/swat-privileged/modules.sock`. Der separate Root-Dienst prüft
`SO_PEERCRED` gegen die UID `swat`, verlangt `root` oder Mitgliedschaft in der
Arch-Administratorgruppe `wheel`, authentifiziert das Konto unabhängig erneut
über PAM, lehnt unbekannte Profil-IDs ab und löst Paketnamen
ausschließlich aus der kompilierten Registry auf. Das Passwort wird weder als
Prozessargument noch Umgebungsvariable oder Auditdetail verwendet. Browserdaten
können weder Paketnamen, Pfade noch Systembefehle bestimmen. Das SWAT-Paket
installiert keine sudoers-Regel. Der Root-Helper schreibt selbst einen
Audit-Startdatensatz und verweigert die Pakettransaktion, falls das Audit-Log
nicht schreibbar ist; Ergebnis oder Fehler werden danach ebenfalls erfasst.

Der Helfer installiert nur fehlende Pflichtpakete. Optionales Redis für
Rspamd wird nicht automatisch installiert. Transitive Abhängigkeiten und
Paket-Hooks gehören zum bestätigten Arch-Pacman-Vorgang.

## Dienststart

Die Registry sammelt aktive und aktivierte Units. Sie startet noch keine
konfigurationspflichtigen Dienste: Hotspot-DHCP darf nicht ungebunden starten,
Maildienste benötigen Anti-Open-Relay-/TLS-Prüfung, Nginx braucht
`nginx -t`, und Fail2ban braucht geprüfte Jails/nftables-Aktionen. Dienste
werden erst durch den jeweiligen validierten Apply-Schritt aktiviert. Das
verhindert, dass ein ausgewähltes, aber unkonfiguriertes Profil beim Setup
unerwartet Ports öffnet oder Netzwerkzugriff verliert.

Der aktuelle Pakethelfer installiert Abhängigkeiten und meldet die noch
gestoppten Units. Die Apply-/Aktivierungsphase ist ein nachfolgender Schritt.