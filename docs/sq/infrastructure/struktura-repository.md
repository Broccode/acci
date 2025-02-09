# Struktura e Repository-t

## Përmbledhje

Repository ndjek një strukturë standarde të Rust workspace me organizim shtesë për zhvillim në nivel ndërmarrjeje. Më poshtë është një ndarje e detajuar e direktorive kryesore dhe qëllimeve të tyre.

## Struktura e Direktorive

```
acci/
├── .github/                    # Konfigurimet specifike të GitHub
│   └── workflows/             # Përkufizimet e pipeline-ve CI/CD
├── .vscode/                   # Konfigurimet e VS Code
├── crates/                    # Anëtarët e workspace-it Rust
│   └── acci-core/            # Funksionaliteti bazë i bibliotekës
├── deploy/                    # Konfigurimet e deployment
│   └── docker/               # Skedarët e lidhur me Docker
├── docs/                      # Dokumentacioni i projektit
│   ├── en/                   # Dokumentacioni në anglisht
│   ├── de/                   # Dokumentacioni në gjermanisht
│   └── sq/                   # Dokumentacioni në shqip
├── src/                      # Burimi kryesor i aplikacionit
└── tests/                    # Testet e integrimit
```

## Skedarët Kryesorë të Konfigurimit

- `.clippy.toml` - Rregullat e personalizuara të Clippy linting
- `.cursorrules` - Udhëzimet e zhvillimit specifike të projektit
- `Cargo.toml` - Përkufizimet e workspace-it dhe varësive
- `deny.toml` - Konfigurimi i auditimit të varësive
- `CHANGELOG.md` - Changelog-u i projektit
- `MILESTONES.md` - Pikat kryesore dhe progresi i projektit
- `PLAN.md` - Dokumenti i detajuar i planifikimit të projektit

## Udhëzimet e Zhvillimit

1. Të gjitha crates e reja duhet të shtohen nën direktorinë `crates/`
2. Dokumentacioni duhet të mirëmbahet në të tre gjuhët (EN, DE, SQ)
3. Skedarët e konfigurimit duhet të vendosen në rrënjën e repository-t
4. Testet duhet të organizohen sipas llojit (unit, integration, e2e)
5. Skedarët e lidhur me Docker duhet të vendosen në `deploy/docker/`

## Praktikat më të Mira

1. Ndiqni strukturën e vendosur të direktorive për komponentët e rinj
2. Mbani dokumentacionin të sinkronizuar në të gjitha versionet gjuhësore
3. Përditësoni skedarët përkatës të konfigurimit kur shtoni veçori të reja
4. Ruani ndarjen e qartë të përgjegjësive midis crates
5. Ndiqni strukturën e direktorisë së testimit për testet e reja
