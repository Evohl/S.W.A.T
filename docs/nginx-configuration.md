# Nginx-Konfiguration

## V1 Desired State

Die Nginx-Seite verwaltet strukturierte virtuelle Hosts. Unterstützt werden
Reverse-Proxies zu einem einzelnen HTTP(S)-Host:Port und statische Websites mit
Dokumentenpfaden unter `/srv/www`. Pro vHost sind mehrere eindeutige DNS-
Servernamen möglich. TLS verweist auf vorhandene Zertifikats- und Schlüsseldateien;
SWAT speichert keine privaten Schlüssel.

Der versionierte Desired State liegt in
`$SWAT_STATE_DIR/nginx-sites.json` (standardmäßig
`~/.local/state/swat/nginx-sites.json`) mit Dateirechten `0600`. Die UI zeigt
eine deterministisch generierte Vorschau. Änderungen benötigen Admin-Zugriff,
CSRF-Schutz und werden im Audit-Log erfasst.

## Validierung und Grenzen

- Servernamen sind DNS-Namen; Nginx-Direktiven, Wildcard-Muster und freie
  Snippets können nicht eingegeben werden.
- Reverse-Proxy-Upstreams benötigen ein HTTP(S)-Schema und einen gültigen Port;
  Userinfo, Pfade, Querystrings und Direktiven-Injection werden abgewiesen.
- Statische Dokumentenpfade müssen unter `/srv/www` liegen.
- TLS-Zertifikat und Schlüssel müssen gemeinsam als absolute Pfade angegeben
  werden. Die Dateien und Berechtigungen werden vor einem künftigen Apply noch
  separat geprüft.
- Die generierte Konfiguration enthält Proxy-Header, `try_files` für statische
  Seiten und bei TLS die Protokolle TLS 1.2 und TLS 1.3.

## Apply-Status

V1 speichert und validiert derzeit nur den gewünschten Zustand und zeigt die
generierte Konfiguration an. SWAT schreibt noch nicht nach `/etc/nginx`, führt
kein `nginx -t` gegen Systemdateien aus und lädt Nginx nicht neu. Dafür sind
zuerst der privilegierte Helper, eine Ownership-geprüfte Transaktion,
`nginx -t` gegen Staging-Dateien sowie Rollback und explizite Freigabe von
Firewallports erforderlich. Externe Nginx-Dateien bleiben unberührt.