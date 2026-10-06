# System-Konfiguration

SWAT zeigt neben Netzwerk, Firewall, Storage und Virtualisierung zentrale
Host-Einstellungen. Hostname, systemweite Locale und Zeitzone können im
Root-Modus über feste native Befehle geändert werden; die übrigen Bereiche
bleiben schreibgeschützt. Jede Änderung muss allowlisted und auditiert sein und
darf fremde Konfiguration nicht still überschreiben.

## Bereiche

| Bereich | Native Quelle oder Komponente | Ziel der Verwaltung |
|---|---|---|
| SSH-Zugang | `sshd`, `sshd_config`, `ss` | Erreichbarkeit und Login-Richtlinien |
| Schlüssel | OpenSSH-Keyfiles und `authorized_keys` | Schlüssel anzeigen, erzeugen und gezielt verteilen |
| Zeitpläne | `systemd`-Timer, `/etc/cron*`, Benutzer-Crontabs | Wiederkehrende Aufgaben und deren Besitzer |
| Hostname | `hostnamectl`, `/etc/hostname`, `/etc/hosts` | stabiler Systemname und lokale Namensauflösung |
| Locale und Zeitzone | `localectl`, `locale -a`, `timedatectl` | Systemsprache und Zeitzone des Hosts |
| Benutzer | `/etc/passwd`, `/etc/shadow`, `loginctl` | Konten, Sperrstatus und interaktive Logins |
| Gruppen | `/etc/group`, Gruppenmitgliedschaften | Berechtigungszuordnung und Zugriffskontrolle |

SWAT zeigt die wirksame Konfiguration getrennt von einem späteren gewünschten
Zustand. Die UI darf keine Passwörter, privaten Schlüssel oder Passwort-Hashes
anzeigen.

## SSH-Zugang

Die SSH-Sektion soll mindestens diese wirksamen Werte und Konflikte anzeigen:

- Dienstzustand von `sshd.service`
- Listen-Adressen und Ports aus der effektiven `sshd`-Konfiguration
- SSH-Zugang insgesamt: aktiviert oder deaktiviert
- Root-Login: erlaubt, nur mit Schlüssel, oder verboten
- Passwort-Authentifizierung: erlaubt oder verboten
- Public-Key-Authentifizierung: erlaubt oder verboten
- `AllowUsers`, `AllowGroups`, `DenyUsers` und `DenyGroups`
- verwendete Host-Keys und deren Fingerprints, niemals private Inhalte
- aktive SSH-Sessions und erreichbare Listen-Sockets, soweit lesbar

Die Anzeige muss die effektive Konfiguration berücksichtigen, einschließlich
`Include`-Dateien und distributionsspezifischer Drop-ins. Eine einzelne
bearbeitete Datei darf nicht als vollständige Wahrheit dargestellt werden.

### Sichere Schreibregeln

- Änderungen an `sshd` werden vor dem Reload mit `sshd -t` validiert.
- Vor einem Reload wird geprüft, ob mindestens eine bestehende
  Administrationsverbindung erhalten bleibt.
- Ein Reload wird bevorzugt; ein Neustart ist nur ausdrücklich erforderlich.
- Der aktuelle Zustand wird vor der Änderung gesichert und bei fehlgeschlagener
  Erreichbarkeitsprüfung automatisch zurückgerollt.
- Root-Login und Passwort-Login erhalten jeweils eine eigene Bestätigung mit
  sichtbarem Risiko-Hinweis.
- Eine Änderung darf niemals den einzigen bekannten administrativen Zugang
  entfernen, ohne dass ein zweiter Zugang explizit bestätigt wurde.

## SSH-Schlüssel

SWAT kann später einen geführten Schlüssel-Workflow anbieten:

1. Algorithmus, Zielbenutzer, Kommentar und Gültigkeitszweck auswählen.
2. Schlüssel lokal im vorgesehenen Benutzerkontext erzeugen.
3. Private Schlüssel nur einmalig und geschützt an den berechtigten Benutzer
   ausgeben; niemals in SWAT-Logs oder im Audit-Log speichern.
4. Den öffentlichen Schlüssel mit Fingerprint anzeigen.
5. Einen Zielhost, Zielbenutzer und Transportweg explizit bestätigen.
6. Den öffentlichen Schlüssel auf dem Zielhost in `authorized_keys` eintragen.
7. Verbindung mit dem neuen Schlüssel prüfen, bevor ein alter Schlüssel
   entfernt werden kann.

Das Senden eines Schlüssels an einen Host ist eine privilegierte Aktion. SWAT
darf keine fremden `authorized_keys` ungefragt zusammenführen, löschen oder
formatieren. Optionen wie `from=`, `command=`, `no-pty` und
`restrict` müssen als strukturierte Felder behandelt und vor dem Aktivieren
sichtbar bestätigt werden.

## Cronjobs und systemd-Timer

SWAT soll wiederkehrende Aufgaben aus allen relevanten Quellen inventarisieren:

- systemweite `systemd`-Timer und ihre zugehörigen Services
- `/etc/crontab`
- `/etc/cron.d/*`, `/etc/cron.hourly/*`, `/etc/cron.daily/*`,
  `/etc/cron.weekly/*` und `/etc/cron.monthly/*`
- Benutzer-Crontabs, sofern die Leseberechtigung vorhanden ist
- Status, nächster Lauf, letzter Lauf, Exit-Code und Besitzer

Neue Aufgaben sollen bevorzugt als systemd-Timer modelliert werden, weil sie
Abhängigkeiten, Logs, Ressourcenlimits, Timeout, Benutzerkontext und
Fehlerstatus klarer beschreiben. Bestehende Cronjobs bleiben sichtbar und
werden nicht automatisch migriert.

Ein zukünftiger Editor muss mindestens Benutzer, Zeitplan, Befehl, Arbeits-
verzeichnis, Umgebungsvariablen, Timeout, Ausgabeziel und Aktivierungsstatus
zeigen. Befehle werden nicht aus unkontrollierten Freitexten mit Root-Rechten
ausgeführt; erlaubte Aufgaben brauchen eine explizite Allowlist oder einen
separaten, validierten Helper.

## Hostname

Die Systemseite soll den aktuell wirksamen Hostnamen sowie Abweichungen
zwischen diesen Quellen anzeigen:

- `hostnamectl` beziehungsweise `uname`
- `/etc/hostname`
- passender lokaler Eintrag in `/etc/hosts`
- optional statischer und transienter systemd-Hostname

Ein neuer Hostname wird als DNS-Hostname validiert und mit
`hostnamectl set-hostname --static` gesetzt. `hostnamectl` verwaltet den
statischen Systemwert und Laufzeit-Hostname; SWAT ändert `/etc/hosts` nicht.
Darum muss die lokale Namensauflösung nach einer Änderung bei Bedarf separat
angepasst werden. Mögliche Management-URLs können den bisherigen Hostnamen
enthalten.

## Locale und Zeitzone

- Die Systemsprache setzt `localectl set-locale LANG=...`; SWAT bietet nur
  Locals an, die `locale -a` als installiert meldet. Andere `LC_*`-Werte
  bleiben unberührt.
- Die Zeitzone setzt `timedatectl set-timezone ...`; SWAT akzeptiert nur Werte
  aus `timedatectl list-timezones`. Dadurch wird die Systemzeitzone geändert,
  nicht die Uhrzeit oder NTP-Konfiguration.
- Hostname, Locale und Zeitzone sind getrennte Root-geschützte Aktionen und
  werden mit Benutzer, Einstellung und Ergebnis auditiert.
- Die Dashboard-Sprache unter „Mein Profil“ bleibt eine browserbezogene
  Darstellungseinstellung und ist unabhängig von der System-Locale.
- Tastaturlayout, NTP/RTC und `/etc/hosts` werden derzeit nur angezeigt oder
  bleiben unverändert.

## Benutzer und Gruppen

Die Inventur soll Benutzer, Gruppen und wirksame Mitgliedschaften getrennt
darstellen:

- Loginname, UID/GID und Herkunft der Kontodaten
- Home-Verzeichnis und Login-Shell
- gesperrt, abgelaufen oder interaktiv nutzbar
- letzte Anmeldung, soweit verfügbar
- direkte und über Gruppen geerbte Mitgliedschaften
- administrative Gruppen wie `wheel`, `sudo`, `docker` oder `libvirt`
- SSH-Schlüssel-Fingerprints ohne private Schlüssel

Passwörter werden weder gelesen noch gesetzt. Änderungen an Konten müssen
Warnungen für den letzten administrativen Benutzer, aktive Sessions,
administrative Gruppen und laufende Dienste auslösen. SWAT darf keine
Systemkonten, Dienstkonten oder fremde Identitätsquellen automatisch löschen.

## Besitz und Konflikte

Für jeden Bereich wird der zuständige Mechanismus sichtbar gemacht. Beispiele:

- `sshd`-Drop-ins versus direkt verwaltete `sshd_config`
- Cronjob versus gleichnamiger systemd-Timer
- lokaler Benutzerbestand versus LDAP/SSSD/anderen NSS-Provider
- manuelle Gruppenänderung versus SWAT-eigene Gruppenquelle

Bei mehreren aktiven Besitzern zeigt SWAT einen Konflikt mit konkreten Dateien,
Diensten oder Benutzern. Fremde Dateien bleiben unangetastet. SWAT darf erst
schreiben, wenn Ziel, Besitzer, Diff, Validierung, Bestätigung, Rollback und
Audit-Eintrag vollständig feststehen.

## Weitere geplante Einstellungen

Die folgenden Bereiche gehören ebenfalls in die spätere System-Konfiguration.
Sie bleiben zunächst read-only und müssen ihre nativen Besitzer und Konflikte
sichtbar ausweisen.

### RAID

RAID wird über `mdadm`, `/proc/mdstat`, `lsblk` und `mdadm --detail` inventarisiert.
SWAT soll anzeigen:

- Arrays, Level, UUID, Geräte und Mount-Beziehungen
- Zustand jedes Mitglieds: aktiv, fehlerhaft, entfernt oder wiederaufbauend
- Degraded-Status, Rebuild-Fortschritt und geschätzte Restdauer
- Spare-Geräte, Write-Intent-Bitmap und erkannte Metadaten
- Konfiguration in `/etc/mdadm.conf` oder `/etc/mdadm/mdadm.conf`

Das Entfernen, Hinzufügen oder Ersetzen eines Laufwerks ist eine besonders
risikoreiche Aktion. Sie braucht eine explizite Gerätebestätigung, eine
Prüfung der Backup- und Redundanzsituation und darf niemals automatisch aus
einer einzelnen fehlerhaften Messung ausgelöst werden. SWAT formatiert keine
Geräte und startet keinen Rebuild ohne eigene Transaktion und sichtbaren
Rollback- beziehungsweise Wiederherstellungsplan.

### Fail2ban

Fail2ban wird als Schutzdienst und nicht als alleiniger Firewall-Owner
behandelt. SWAT soll anzeigen:

- Dienstzustand und verwendetes Backend
- aktive Jails, Filter, Aktionen und überwachte Logquellen
- Zeitfenster, Fehlerschwelle, Ban-Zeit und aktuelle Bans
- verwendete Firewall-Aktion, zum Beispiel nftables oder firewalld
- Ausnahmen und vertrauenswürdige Netze

Fail2ban darf nicht ungeprüft mit firewalld, ufw oder direkt verwalteten
nftables-Regeln konkurrieren. Vor einer Änderung müssen die betroffenen Chains
und Bans konkret benannt werden. Ein Reload darf bestehende Management- oder
Administrationszugänge nicht aussperren.

### Mailserver

Ein Mailserver wird als eigener Dienstverbund erkannt, nicht als einzelner
Schalter. Die Inventur soll mindestens MTA, MDA/IMAP, Submission, TLS,
Spam-/Virenfilter, Queue und DNS-Abhängigkeiten erfassen. Typische Komponenten
sind beispielsweise Postfix, Dovecot, Rspamd und ClamAV.

Anzuzeigen sind insbesondere:

- aktive Dienste und lauschte Ports für SMTP, Submission, IMAP und IMAPS
- konfigurierte Domains, Relay-Regeln und lokale Zustellung
- TLS-Zertifikat, Ablaufdatum und verwendete Protokolle
- Mailqueue, Zustellfehler und Größenlimits
- Abhängigkeiten von DNS, Reverse DNS, SPF, DKIM und DMARC

Passwörter, private Schlüssel, SMTP-Authentifizierungsdaten und Mailinhalte
werden niemals angezeigt oder protokolliert. Schreibaktionen brauchen eine
separate Bestätigung für Relay-Berechtigungen, öffentliche Erreichbarkeit und
DNS-Änderungen. Ein Mailserver darf nicht aktiviert werden, wenn ein offenes
Relay oder eine unklare Domain-Zuständigkeit erkannt wurde.

### Portainer und Containerverwaltung

Portainer wird gemeinsam mit dem tatsächlichen Container-Owner bewertet. SWAT
soll Portainer, Docker, Podman und die verwalteten Endpoints getrennt anzeigen:

- Dienstzustand und Portainer-Version
- lokale und entfernte Endpoints
- Docker-Socket- oder API-Zugriff
- Container, Images, Netzwerke, Volumes und Restart-Policies
- Erreichbarkeit, TLS und administrative Benutzer

Der Zugriff auf `/var/run/docker.sock` entspricht weitgehend Root-Rechten auf
dem Host. SWAT darf Portainer deshalb nicht automatisch über den Host-Socket
verwalten oder öffentlich freigeben. Container-Netzwerke, Volumes und
Restart-Policies werden nur dem Owner zugerechnet, der sie tatsächlich
verwaltet; Docker und Podman gelten nicht gleichzeitig als ein gemeinsamer
Besitzer. Entfernen, Aktualisieren oder Neustarten von Containern bleibt bis
zu einer authentifizierten, allowlist-basierten Administration gesperrt.
