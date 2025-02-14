# Testet e Integrimit

Ky dokument përshkruan strukturën dhe përdorimin e testeve të integrimit në projektin ACCI.

## Struktura e Direktorisë

```text
tests/
├── Cargo.toml             # Konfigurimi i crate-it të testeve
└── src/
    ├── lib.rs            # Pika kryesore e hyrjes së bibliotekës së testeve
    ├── api/              # Testet e integrimit të API-së
    │   ├── mod.rs        # Konfigurimi i modulit API
    │   ├── health_test.rs    # Testet e endpoint-it të shëndetit
    │   ├── user_test.rs      # Testet e menaxhimit të përdoruesve
    │   └── ...
    └── helpers/          # Utilitetet e përbashkëta të testeve
        ├── mod.rs        # Konfigurimi i modulit ndihmës
        └── db.rs         # Ndihmësit e testeve të bazës së të dhënave
```

## Organizimi i Testeve

- Të gjitha modulet e testeve janë të shënuara me `#[cfg(test)]`
- Testet janë të organizuara sipas zonave të funksionalitetit në direktorinë `api/`
- Utilitetet e përbashkëta të testeve janë të centralizuara në direktorinë `helpers/`
- Çdo skedar testi fokusohet në një funksionalitet ose endpoint specifik
- Skedarët e testeve ndjekin konventën e emërtimit `*_test.rs`

## Testimi i Bazës së të Dhënave me TestContainers

Ne përdorim framework-un `testcontainers` për të ekzekutuar teste integrimi kundrejt një baze të dhënash PostgreSQL reale:

- Çdo test merr kontejnerin e vet të izoluar PostgreSQL
- Kontejnerët pastrohen automatikisht pas përfundimit të testeve
- Konfigurimi i bazës së të dhënave përfshin:
  - Zgjerimet e kërkuara PostgreSQL (pgcrypto, uuid-ossp)
  - Krijimin e skemës
  - Ekzekutimin e migrimeve
  - Inicializimin e të dhënave të testit

### Përdorimi i Ndihmësve të Bazës së të Dhënave

```rust
use crate::helpers::db::setup_database;

async fn setup() -> Result<(Box<dyn std::any::Any>, PgUserRepository)> {
    let (container, pool) = setup_database().await?;
    let repo = PgUserRepository::new(pool);
    Ok((container, repo))
}
```

## Shtimi i Testeve të Reja të Integrimit

Për të shtuar një test të ri integrimi:

1. Krijoni një skedar të ri në `tests/src/api/` të quajtur `funksionaliteti_juaj_test.rs`
2. Shtoni modulin në `tests/src/api/mod.rs`:

   ```rust
   mod funksionaliteti_juaj_test;
   ```

3. Strukturoni skedarin tuaj të testit:

   ```rust
   use anyhow::Result;
   use crate::helpers::db::setup_database;
   
   async fn setup() -> Result<(Box<dyn std::any::Any>, RepositoriJuaj)> {
       let (container, pool) = setup_database().await?;
       let repo = RepositoriJuaj::new(pool);
       Ok((container, repo))
   }
   
   #[tokio::test]
   async fn test_funksionaliteti_juaj() -> Result<()> {
       let (_container, repo) = setup().await?;
       // Kodi juaj i testit këtu
       Ok(())
   }
   ```

### Praktikat më të Mira

1. **Pavarësia e Testeve**
   - Çdo test duhet të ekzekutohet i izoluar
   - Mos u mbështetni në gjendjen nga testet e tjera
   - Përdorni ndihmësin e konfigurimit për një bazë të dhënash të freskët

2. **Pastrimi i Burimeve**
   - Mbani handle-in e kontejnerit në scope deri në përfundim të testit
   - Përdorni tipin `Result` për trajtimin e duhur të gabimeve
   - Lini framework-un e testeve të merret me pastrimin e kontejnerit

3. **Organizimi i Testeve**
   - Gruponi testet e lidhura në të njëjtin skedar
   - Përdorni emra përshkrues për testet
   - Shtoni komente që shpjegojnë skenarët kompleksë të testeve

4. **Përdorimi i Bazës së të Dhënave**
   - Përdorni ndihmësit e ofruar të bazës së të dhënave
   - Mos modifikoni skemën direkt në teste
   - Përdorni migrime për ndryshimet e skemës

5. **Trajtimi i Gabimeve**
   - Përdorni `anyhow::Result` për rezultatet e testeve
   - Shtoni mesazhe përshkruese të gabimeve
   - Testoni si rastet e suksesit ashtu edhe të gabimit

### Struktura Shembull e Testit

```rust
use anyhow::Result;
use crate::helpers::db::setup_database;

async fn setup() -> Result<(Box<dyn std::any::Any>, TestRepo)> {
    let (container, pool) = setup_database().await?;
    let repo = TestRepo::new(pool);
    Ok((container, repo))
}

#[tokio::test]
async fn test_operacioni_i_suksesshem() -> Result<()> {
    // Arrange
    let (_container, repo) = setup().await?;
    
    // Act
    let result = repo.do_something().await?;
    
    // Assert
    assert!(result.is_ok());
    Ok(())
}

#[tokio::test]
async fn test_trajtimi_i_gabimit() -> Result<()> {
    // Arrange
    let (_container, repo) = setup().await?;
    
    // Act
    let result = repo.invalid_operation().await;
    
    // Assert
    assert!(result.is_err());
    Ok(())
}
```

## Ekzekutimi i Testeve

Për të ekzekutuar të gjitha testet e integrimit:

```bash
cargo test
```

Për të ekzekutuar teste specifike:

```bash
cargo test test_name
```

Për të ekzekutuar teste me output:

```bash
cargo test -- --nocapture
```
