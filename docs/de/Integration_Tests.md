# Integrationstests

Dieses Dokument beschreibt die Struktur und Verwendung von Integrationstests im ACCI-Projekt.

## Verzeichnisstruktur

```text
tests/
├── Cargo.toml             # Test-Crate-Konfiguration
└── src/
    ├── lib.rs            # Haupteinstiegspunkt der Testbibliothek
    ├── api/              # API-Integrationstests
    │   ├── mod.rs        # API-Modulkonfiguration
    │   ├── health_test.rs    # Health-Endpoint-Tests
    │   ├── user_test.rs      # Benutzerverwaltungstests
    │   └── ...
    └── helpers/          # Gemeinsame Testhilfsmittel
        ├── mod.rs        # Hilfsmodulkonfiguration
        └── db.rs         # Datenbank-Testhilfen
```

## Testorganisation

- Alle Testmodule sind mit `#[cfg(test)]` markiert
- Tests sind nach Funktionsbereichen im `api/`-Verzeichnis organisiert
- Gemeinsame Testhilfsmittel sind im `helpers/`-Verzeichnis zentralisiert
- Jede Testdatei konzentriert sich auf eine bestimmte Funktion oder einen Endpoint
- Testdateien folgen der Namenskonvention `*_test.rs`

## Datenbanktests mit TestContainers

Wir verwenden das `testcontainers`-Framework, um Integrationstests gegen eine echte PostgreSQL-Datenbank auszuführen:

- Jeder Test erhält seinen eigenen isolierten PostgreSQL-Container
- Container werden nach Testabschluss automatisch bereinigt
- Datenbankeinrichtung umfasst:
  - Erforderliche PostgreSQL-Erweiterungen (pgcrypto, uuid-ossp)
  - Schema-Erstellung
  - Migrationsausführung
  - Testdaten-Initialisierung

### Verwendung der Datenbank-Helfer

```rust
use crate::helpers::db::setup_database;

async fn setup() -> Result<(Box<dyn std::any::Any>, PgUserRepository)> {
    let (container, pool) = setup_database().await?;
    let repo = PgUserRepository::new(pool);
    Ok((container, repo))
}
```

## Hinzufügen neuer Integrationstests

Um einen neuen Integrationstest hinzuzufügen:

1. Erstellen Sie eine neue Datei in `tests/src/api/` mit dem Namen `ihre_funktion_test.rs`
2. Fügen Sie das Modul zu `tests/src/api/mod.rs` hinzu:

   ```rust
   mod ihre_funktion_test;
   ```

3. Strukturieren Sie Ihre Testdatei:

   ```rust
   use anyhow::Result;
   use crate::helpers::db::setup_database;
   
   async fn setup() -> Result<(Box<dyn std::any::Any>, IhrRepository)> {
       let (container, pool) = setup_database().await?;
       let repo = IhrRepository::new(pool);
       Ok((container, repo))
   }
   
   #[tokio::test]
   async fn test_ihre_funktion() -> Result<()> {
       let (_container, repo) = setup().await?;
       // Ihr Testcode hier
       Ok(())
   }
   ```

### Best Practices

1. **Testunabhängigkeit**
   - Jeder Test sollte isoliert laufen
   - Nicht auf Zustände aus anderen Tests verlassen
   - Setup-Helfer für eine frische Datenbank verwenden

2. **Ressourcenbereinigung**
   - Container-Handle bis zum Testende im Scope behalten
   - `Result`-Typ für korrekte Fehlerbehandlung verwenden
   - Containerbereinigung dem Test-Framework überlassen

3. **Testorganisation**
   - Verwandte Tests in derselben Datei gruppieren
   - Beschreibende Testnamen verwenden
   - Komplexe Testszenarien kommentieren

4. **Datenbanknutzung**
   - Bereitgestellte Datenbank-Helfer verwenden
   - Schema nicht direkt in Tests modifizieren
   - Migrationen für Schema-Änderungen nutzen

5. **Fehlerbehandlung**
   - `anyhow::Result` für Testergebnisse verwenden
   - Beschreibende Fehlermeldungen hinzufügen
   - Sowohl Erfolgs- als auch Fehlerfälle testen

### Beispiel-Teststruktur

```rust
use anyhow::Result;
use crate::helpers::db::setup_database;

async fn setup() -> Result<(Box<dyn std::any::Any>, TestRepo)> {
    let (container, pool) = setup_database().await?;
    let repo = TestRepo::new(pool);
    Ok((container, repo))
}

#[tokio::test]
async fn test_erfolgreiche_operation() -> Result<()> {
    // Arrange
    let (_container, repo) = setup().await?;
    
    // Act
    let result = repo.do_something().await?;
    
    // Assert
    assert!(result.is_ok());
    Ok(())
}

#[tokio::test]
async fn test_fehlerbehandlung() -> Result<()> {
    // Arrange
    let (_container, repo) = setup().await?;
    
    // Act
    let result = repo.invalid_operation().await;
    
    // Assert
    assert!(result.is_err());
    Ok(())
}
```

## Tests ausführen

Alle Integrationstests ausführen:

```bash
cargo test
```

Bestimmte Tests ausführen:

```bash
cargo test test_name
```

Tests mit Ausgabe ausführen:

```bash
cargo test -- --nocapture
```
