# Einheitliche Konfigurationsseiten

SWAT verwendet für native Linux-Konfigurationen ein gemeinsames Seitenmodell. Neue Bereiche sollen keinen eigenen HTML-Aufbau und keine eigene Bedienlogik erhalten.

## Vertrag

`collect.ConfigPage` beschreibt eine Konfigurationsseite:

- `ID`: stabiler technischer Bezeichner
- `Title` und `Description`: sichtbare Einordnung
- `Owner`: zuständiger nativer Dienst
- `Status` und `StatusLabel`: Verfügbarkeit oder Problemzustand
- `ReadOnly`: bis zur Einführung autorisierter Schreibaktionen `true`
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

## Standardseiten

Jede Konfigurationsseite enthält grundsätzlich:

1. Titel und Beschreibung
2. Zustand und zuständigen Dienst
3. Hinweis auf den Berechtigungsmodus
4. eine oder mehrere Sections
5. einen einheitlichen Leerzustand

Schreibaktionen werden erst ergänzt, wenn der Polkit-/Helper-Mechanismus und das Audit-Log vorhanden sind. Ein neuer Bereich darf bis dahin nur Daten sammeln und anzeigen.

## Erweiterung

Für einen neuen Bereich:

1. nativen Collector in `internal/collect` ergänzen
2. `ConfigPage`-Adapter im selben Package ergänzen
3. Handler mit `config.html` verbinden (alle Seiten nutzen das globale `layout.html`)
4. Owner und Konfliktzustand aus der Service-Inventur übernehmen
5. Route testen und sicherstellen, dass keine direkten Shell-Befehle aus Templates oder HTTP-Handlern ausgeführt werden
