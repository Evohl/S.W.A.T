# Einheitliche Konfigurationsseiten

SWAT verwendet für native Linux-Konfigurationen ein gemeinsames Seitenmodell. Neue Bereiche sollen keinen eigenen HTML-Aufbau und keine eigene Bedienlogik erhalten.

## Vertrag

`collect.ConfigPage` beschreibt eine Konfigurationsseite:

- `ID`: stabiler technischer Bezeichner
- `Title` und `Description`: sichtbare Einordnung
- `Owner`: zuständiger nativer Dienst
- `Status` und `StatusLabel`: Verfügbarkeit oder Problemzustand
- `ReadOnly`: true for inventory-only views or while ownership conflicts block changes; writable actions require helper authorization and audit
- `Sections`: tabellarische oder rohe Konfigurationsabschnitte

Jeder Bereich besitzt einen eigenen Collector-Adapter, zum Beispiel `NetworkConfig` oder `FirewallConfig`. Der Adapter übersetzt native Daten in `ConfigPage`; das gemeinsame Template `config.html` übernimmt die Darstellung.

## Übersetzungen

Jeder neue sichtbare deutsche Text in einem Template oder Collector erhält im
selben Änderungsschritt einen englischen Eintrag in
`cmd/swat/web/static/theme.js`. Neue Tabellenüberschriften, Statuswerte,
Leerzustände, Hinweise und Empfehlungen dürfen nicht erst später übersetzt
werden. Nach Änderungen werden beide Sprachvarianten im laufenden Dashboard
geprüft.

Geplante weitere Bereiche sind in [System-Konfiguration](system-configuration.md)
beschrieben: SSH-Zugang und Schlüssel, Cronjobs und systemd-Timer, Hostname,
Benutzer sowie Gruppen.

Nginx besitzt eine eigene strukturierte Desired-State-Seite für vHosts und eine
generierte Vorschau. Systemdateien werden bis zur Einführung des privilegierten
Apply-/Rollback-Mechanismus nicht verändert; Details stehen in
[Nginx-Konfiguration](nginx-configuration.md).

Optionale Konfigurationsseiten werden zentral über die Profile in
[Module und Dienstprofile](modules.md) freigeschaltet. Ein Profil muss ausgewählt
und seine Pflichtpakete müssen installiert sein. Die Modulverwaltung zeigt die
Paket- und Unit-Abhängigkeiten; konfigurationspflichtige Dienste starten erst
nach validiertem Apply.

## Standardseiten

Jede Konfigurationsseite enthält grundsätzlich:

1. Titel und Beschreibung
2. Zustand und zuständigen Dienst
3. Hinweis auf den Berechtigungsmodus
4. eine oder mehrere Sections
5. einen einheitlichen Leerzustand

Schreibaktionen dürfen nur ergänzt werden, wenn eine typisierte Helper-Operation, unabhängige PAM-Prüfung, helperseitiger Start-/Ergebnis-Audit und passende Validierung/Rücknahme vorhanden sind. Bereiche ohne diesen Vertrag bleiben reine Inventur- oder Desired-State-Ansichten.

## Erweiterung

Für einen neuen Bereich:

1. nativen Collector in `internal/collect` ergänzen
2. `ConfigPage`-Adapter im selben Package ergänzen
3. Handler mit `config.html` verbinden (alle Seiten nutzen das globale `layout.html`)
4. Owner und Konfliktzustand aus der Service-Inventur übernehmen
5. Route testen und sicherstellen, dass keine direkten Shell-Befehle aus Templates oder HTTP-Handlern ausgeführt werden
