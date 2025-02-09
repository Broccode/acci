# Entwicklungsumgebung

## Übersicht

Unsere Entwicklungsumgebung ist so konfiguriert, dass sie einen konsistenten und effizienten Workflow über alle Entwicklungsmaschinen hinweg gewährleistet. Dieses Dokument beschreibt die wichtigsten Komponenten und Einrichtungsverfahren.

## Voraussetzungen

- Rust (neueste stabile Version)
- Docker und Docker Compose
- VS Code oder JetBrains RustRover
- Git

## IDE-Konfiguration

### VS Code

Das Repository enthält vorkonfigurierte VS Code-Einstellungen:

- Rust-Analyzer-Erweiterungseinstellungen
- Benutzerdefinierte Tasks für häufige Operationen
- Debugging-Konfigurationen
- Empfohlene Erweiterungen

### RustRover

Empfohlene Einstellungen für RustRover sind im Repository enthalten:

- Run/Debug-Konfigurationen
- Code-Style-Einstellungen
- Live-Templates
- Benutzerdefinierte Makros

## Docker-Entwicklungsumgebung

Unsere Docker-Entwicklungsumgebung bietet:

- Konsistente Entwicklungsumgebung über alle Maschinen hinweg
- Isolierte Testumgebung
- Lokale Service-Abhängigkeiten
- Hot-Reload-Funktionen

### Hauptmerkmale

1. Multi-Stage-Builds für optimale Image-Größe
2. Entwicklungsspezifische Konfigurationen
3. Volume-Mounting für schnelle Entwicklungszyklen
4. Integration mit IDE-Debugging

## Linting und Formatierung

### Clippy-Konfiguration

Benutzerdefinierte Clippy-Regeln sind in `.clippy.toml` definiert:

- Strikte Linting-Regeln
- Projektspezifische Konfigurationen
- Performance-bezogene Prüfungen
- Sicherheitsbezogene Prüfungen

### Rustfmt-Konfiguration

Konsistente Code-Formatierung wird durch rustfmt erzwungen:

- Standard-Rust-Formatierungsregeln
- Benutzerdefinierte Konfigurationen für Projektspezifika
- Integration mit IDE-Formatierung

## Test-Infrastruktur

- Unit-Tests neben dem Quellcode
- Integrationstests im `/tests`-Verzeichnis
- End-to-End-Tests mit Docker Compose
- Test-Helfer und Utilities

## Entwicklungs-Workflow

1. Repository klonen
2. Voraussetzungen installieren
3. `cargo build` ausführen zur Überprüfung der Einrichtung
4. Docker-Entwicklungsumgebung starten
5. In VS Code oder RustRover öffnen
6. Entwicklung mit Hot-Reload beginnen

## Best Practices

1. Immer die Docker-Entwicklungsumgebung verwenden
2. Tests vor dem Commit ausführen
3. Linting-Regeln befolgen
4. Abhängigkeiten aktuell halten
5. Neue Entwicklungsanforderungen dokumentieren
