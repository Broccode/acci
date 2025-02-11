# Struktura e Repository-t

## Përmbledhje

Repository ndjek një strukturë standarde të Rust workspace me organizim shtesë për zhvillim në nivel ndërmarrjeje. Më poshtë është një ndarje e detajuar e direktorive kryesore dhe qëllimeve të tyre.

## Struktura e Direktorive

```text
acci/
├── .github/                    # Konfigurimet specifike të GitHub
│   ├── workflows/             # Përkufizimet e pipeline-ve CI/CD
│   └── ISSUE_TEMPLATE/        # Templates për Issues dhe PR
├── .vscode/                   # Konfigurimet e VS Code
├── crates/                    # Anëtarët e Rust workspace
│   ├── acci-core/            # Funksionaliteti bazë i bibliotekës
│   ├── acci-db/              # Shtresa e qasjes në bazën e të dhënave
│   └── acci-api/             # Implementimi i API
├── deploy/                    # Konfigurimet e deployment
│   ├── docker/               # Skedarët e lidhur me Docker
│   └── k8s/                  # Manifestet e Kubernetes
├── docs/                      # Dokumentacioni i projektit
│   ├── en/                   # Dokumentacioni në anglisht
│   ├── de/                   # Dokumentacioni në gjermanisht
│   └── sq/                   # Dokumentacioni në shqip
├── src/                      # Burimi kryesor i aplikacionit
└── tests/                    # Testet e integrimit
    ├── api/                  # Testet e integrimit të API
    ├── database/             # Testet e integrimit të bazës së të dhënave
    └── helpers/              # Funksionet ndihmëse të testeve
```

## Skedarët Kryesorë të Konfigurimit

- `.clippy.toml` - Rregullat e personalizuara të Clippy linting
- `.cursorrules` - Udhëzimet e zhvillimit specifike të projektit
- `.editorconfig` - Konfigurimi i editorit për stil të qëndrueshëm të kodimit
- `.gitignore` - Modelet e Git ignore
- `Cargo.toml` - Përkufizimet e workspace dhe varësive
- `deny.toml` - Konfigurimi i auditimit të varësive
- `devbox.json` - Konfigurimi i mjedisit të zhvillimit
- `rust-toolchain.toml` - Specifikimi i toolchain-it të Rust
- `CHANGELOG.md` - Changelog-u i projektit
- `MILESTONES.md` - Pikat kryesore dhe progresi i projektit
- `PLAN.md` - Dokumenti i detajuar i planifikimit të projektit
- `bom.json` - Lista e materialeve të softuerit (SBOM)

## Udhëzimet e Zhvillimit

1. Të gjitha crates e reja duhet të shtohen nën direktorinë `crates/`
2. Dokumentacioni duhet të mirëmbahet në të tre gjuhët (EN, DE, SQ)
3. Skedarët e konfigurimit duhet të vendosen në rrënjën e repository-t
4. Testet duhet të organizohen sipas llojit (unit, integration, e2e)
5. Skedarët e lidhur me Docker duhet të vendosen në `deploy/docker/`
6. Çdo crate duhet të ketë suite-in e vet gjithëpërfshirës të testeve
7. Dokumentacioni i API duhet të gjenerohet duke përdorur rustdoc
8. Migrimet e bazës së të dhënave duhet të jenë të versionuara
9. Konfigurimet e lidhura me sigurinë duhet të menaxhohen siç duhet

## Praktikat më të Mira

1. Ndiqni strukturën e vendosur të direktorive për komponentët e rinj
2. Mbani dokumentacionin të sinkronizuar në të gjitha versionet gjuhësore
3. Përditësoni skedarët përkatës të konfigurimit kur shtoni veçori të reja
4. Ruani ndarjen e qartë të përgjegjësive midis crates
5. Ndiqni strukturën e direktorisë së testeve për testet e reja
6. Përdorni trajtim të duhur të gabimeve dhe logging në të gjithë kodin
7. Implementoni teste gjithëpërfshirëse për të gjitha veçoritë e reja
8. Ndiqni praktikat më të mira të sigurisë për të gjithë komponentët
9. Mbani varësitë të përditësuara dhe auditoni rregullisht
10. Ruani versionimin e duhur dhe përditësimet e changelog-ut

## Konsiderata të Sigurisë

1. Konfigurimi i ndjeshëm duhet të përdorë variablat e mjedisit
2. Çelësat e API dhe sekretet nuk duhet të komiten kurrë në repository
3. Duhet të kryhen auditime të rregullta të sigurisë
4. Varësitë duhet të përditësohen dhe verifikohen rregullisht
5. Të gjitha ndryshimet e lidhura me sigurinë duhet të dokumentohen

## Standardet e Dokumentacionit

1. Të gjitha API-të publike duhet të dokumentohen
2. Shembujt e kodit duhet të përfshihen ku është e përshtatshme
3. Opsionet e konfigurimit duhet të shpjegohen plotësisht
4. Implikimet e sigurisë duhet të deklarohen qartë
5. Përputhshmëria e versionit duhet të dokumentohet
6. Ndryshimet thelbësore duhet të theksohen
7. Dokumentacioni duhet të mbahet i sinkronizuar me ndryshimet e kodit

## Kërkesat e Testimit

1. Unit teste për të gjithë logjikën e biznesit
2. Teste integrimi për endpoints të API
3. Teste të migrimit të bazës së të dhënave
4. Benchmarks të performancës ku është e aplikueshme
5. Teste të sigurisë për autentifikim/autorizim
6. Teste të ngarkesës për endpoints kritike
7. Izolim dhe pastrim i duhur i testeve
