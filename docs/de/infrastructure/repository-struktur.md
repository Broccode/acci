# Repository-Struktur

## Übersicht

Das Repository folgt einer Standard-Rust-Workspace-Struktur mit zusätzlicher Organisation für Enterprise-Grade-Entwicklung. Nachfolgend finden Sie eine detaillierte Aufschlüsselung der wichtigsten Verzeichnisse und ihrer Zwecke.

## Verzeichnisstruktur

```text
acci/
├── .github/                    # GitHub-spezifische Konfigurationen
│   └── workflows/             # CI/CD-Pipeline-Definitionen
├── .vscode/                   # VS Code-Konfigurationen
├── crates/                    # Rust-Workspace-Mitglieder
│   └── acci-core/            # Kern-Bibliotheksfunktionalität
├── deploy/                    # Deployment-Konfigurationen
│   └── docker/               # Docker-bezogene Dateien
├── docs/                      # Projektdokumentation
│   ├── en/                   # Englische Dokumentation
│   ├── de/                   # Deutsche Dokumentation
│   └── sq/                   # Albanische Dokumentation
├── src/                      # Haupt-Anwendungsquelle
└── tests/                    # Integrationstests
```

## Wichtige Konfigurationsdateien

- `.clippy.toml` - Benutzerdefinierte Clippy-Linting-Regeln
- `.cursorrules` - Projektspezifische Entwicklungsrichtlinien
- `Cargo.toml` - Workspace- und Abhängigkeitsdefinitionen
- `deny.toml` - Abhängigkeits-Audit-Konfiguration
- `CHANGELOG.md` - Projekt-Changelog
- `MILESTONES.md` - Projekt-Meilensteine und Fortschritt
- `PLAN.md` - Detailliertes Projektplanungsdokument

## Entwicklungsrichtlinien

1. Alle neuen Crates sollten unter dem `crates/`-Verzeichnis hinzugefügt werden
2. Dokumentation muss in allen drei Sprachen gepflegt werden (EN, DE, SQ)
3. Konfigurationsdateien sollten im Repository-Root platziert werden
4. Tests sollten nach Typ organisiert werden (Unit, Integration, E2E)
5. Docker-bezogene Dateien sollten in `deploy/docker/` platziert werden

## Best Practices

1. Befolgen Sie die etablierte Verzeichnisstruktur für neue Komponenten
2. Halten Sie die Dokumentation in allen Sprachversionen synchron
3. Aktualisieren Sie relevante Konfigurationsdateien beim Hinzufügen neuer Features
4. Behalten Sie eine klare Trennung der Zuständigkeiten zwischen Crates bei
5. Folgen Sie der Testverzeichnisstruktur für neue Tests
