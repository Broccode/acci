# Repository-Struktur

## Übersicht

Das Repository folgt einer Standard-Rust-Workspace-Struktur mit zusätzlicher Organisation für Enterprise-Grade-Entwicklung. Nachfolgend finden Sie eine detaillierte Aufschlüsselung der wichtigsten Verzeichnisse und ihrer Zwecke.

## Verzeichnisstruktur

```text
acci/
├── .github/                    # GitHub-spezifische Konfigurationen
│   ├── workflows/             # CI/CD-Pipeline-Definitionen
│   └── ISSUE_TEMPLATE/        # Issue- und PR-Templates
├── .vscode/                   # VS Code-Konfigurationen
├── crates/                    # Rust-Workspace-Mitglieder
│   ├── acci-core/            # Kern-Bibliotheksfunktionalität
│   ├── acci-db/              # Datenbankzugriffsschicht
│   └── acci-api/             # API-Implementierung
├── deploy/                    # Deployment-Konfigurationen
│   ├── docker/               # Docker-bezogene Dateien
│   └── k8s/                  # Kubernetes-Manifeste
├── docs/                      # Projektdokumentation
│   ├── en/                   # Englische Dokumentation
│   ├── de/                   # Deutsche Dokumentation
│   └── sq/                   # Albanische Dokumentation
├── src/                      # Haupt-Anwendungsquelle
└── tests/                    # Integrationstests
    ├── api/                  # API-Integrationstests
    ├── database/             # Datenbank-Integrationstests
    └── helpers/              # Test-Hilfsfunktionen
```

## Wichtige Konfigurationsdateien

- `.clippy.toml` - Benutzerdefinierte Clippy-Linting-Regeln
- `.cursorrules` - Projektspezifische Entwicklungsrichtlinien
- `.editorconfig` - Editor-Konfiguration für einheitlichen Codestil
- `.gitignore` - Git-Ignore-Muster
- `Cargo.toml` - Workspace- und Abhängigkeitsdefinitionen
- `deny.toml` - Abhängigkeits-Audit-Konfiguration
- `devbox.json` - Entwicklungsumgebungskonfiguration
- `rust-toolchain.toml` - Rust-Toolchain-Spezifikation
- `CHANGELOG.md` - Projekt-Changelog
- `MILESTONES.md` - Projekt-Meilensteine und Fortschritt
- `PLAN.md` - Detailliertes Projektplanungsdokument
- `bom.json` - Software-Stückliste (SBOM)

## Entwicklungsrichtlinien

1. Alle neuen Crates sollten unter dem `crates/`-Verzeichnis hinzugefügt werden
2. Dokumentation muss in allen drei Sprachen gepflegt werden (EN, DE, SQ)
3. Konfigurationsdateien sollten im Repository-Root platziert werden
4. Tests sollten nach Typ organisiert werden (Unit, Integration, E2E)
5. Docker-bezogene Dateien sollten in `deploy/docker/` platziert werden
6. Jedes Crate sollte seine eigene umfassende Testsuite haben
7. API-Dokumentation muss mit rustdoc generiert werden
8. Datenbank-Migrationen sollten versioniert werden
9. Sicherheitsbezogene Konfigurationen müssen ordnungsgemäß verwaltet werden

## Best Practices

1. Befolgen Sie die etablierte Verzeichnisstruktur für neue Komponenten
2. Halten Sie die Dokumentation in allen Sprachversionen synchron
3. Aktualisieren Sie relevante Konfigurationsdateien beim Hinzufügen neuer Features
4. Behalten Sie eine klare Trennung der Zuständigkeiten zwischen Crates bei
5. Folgen Sie der Testverzeichnisstruktur für neue Tests
6. Verwenden Sie durchgängig ordnungsgemäße Fehlerbehandlung und Logging
7. Implementieren Sie umfassende Tests für alle neuen Features
8. Befolgen Sie Sicherheits-Best-Practices für alle Komponenten
9. Halten Sie Abhängigkeiten aktuell und führen Sie regelmäßige Audits durch
10. Pflegen Sie ordnungsgemäße Versionierung und Changelog-Updates

## Sicherheitsaspekte

1. Sensible Konfiguration muss Umgebungsvariablen verwenden
2. API-Schlüssel und Geheimnisse dürfen niemals in das Repository committet werden
3. Regelmäßige Sicherheitsaudits müssen durchgeführt werden
4. Abhängigkeiten müssen regelmäßig aktualisiert und überprüft werden
5. Alle sicherheitsrelevanten Änderungen müssen dokumentiert werden

## Dokumentationsstandards

1. Alle öffentlichen APIs müssen dokumentiert sein
2. Code-Beispiele müssen wo angebracht eingefügt werden
3. Konfigurationsoptionen müssen gründlich erklärt werden
4. Sicherheitsimplikationen müssen klar dargestellt werden
5. Versionskompatibilität muss dokumentiert sein
6. Breaking Changes müssen hervorgehoben werden
7. Dokumentation muss mit Code-Änderungen synchron gehalten werden

## Testanforderungen

1. Unit-Tests für alle Geschäftslogik
2. Integrationstests für API-Endpunkte
3. Datenbank-Migrationstests
4. Performance-Benchmarks wo anwendbar
5. Sicherheitstests für Authentifizierung/Autorisierung
6. Lasttests für kritische Endpunkte
7. Ordnungsgemäße Testisolation und Aufräumarbeiten
