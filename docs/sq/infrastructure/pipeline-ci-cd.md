# Pipeline CI/CD

## Përmbledhje

Pipeline ynë CI/CD është implementuar duke përdorur GitHub Actions dhe ofron procese të automatizuara të testimit, ndërtimit dhe deployment. Pipeline është projektuar për të siguruar cilësinë e kodit, sigurinë dhe deployment të besueshëm.

## Struktura e Pipeline

### Pipeline CI (Në Pull Request)

1. Kontrollet e Cilësisë së Kodit
   - Kontrolli i formatimit të Rust
   - Linting me Clippy
   - Auditimi i varësive
   - Gjenerimi dhe verifikimi i SBOM

2. Testimi
   - Testet e njësisë
   - Testet e integrimit
   - Testet end-to-end
   - Raportimi i mbulimit

3. Kontrollet e Sigurisë
   - Skanimi i dobësive të varësive
   - Skanimi i sekreteve
   - Kontrolli i përputhshmërisë së licencës
   - Skanimi i imazhit të container-it

### Pipeline CD (Në Branch Main)

1. Procesi i Ndërtimit
   - Ndërtime multi-stage Docker
   - Gjenerimi i artefakteve
   - Gjenerimi i dokumentacionit
   - Tagging i versioneve

2. Fazat e Deployment
   - Mjedisi i zhvillimit
   - Mjedisi i staging
   - Mjedisi i prodhimit
   - Deployment i dokumentacionit

## Veçoritë Kryesore

### Testimi i Automatizuar

- Ekzekutimi paralel i testeve
- Raportimi i rezultateve të testeve
- Gjurmimi i mbulimit
- Testimi i regresionit të performancës

### Masat e Sigurisë

- Skanimi i dobësive të varësive
- Gjenerimi i SBOM (CycloneDX)
- Skanimi i sigurisë së container-it
- Zbulimi i sekreteve

### Sigurimi i Cilësisë

- Zbatimi i stilit të kodit
- Analiza statike
- Validimi i dokumentacionit
- Kontrollet e përputhshmërisë së API

## Skedarët e Konfigurimit

Skedarët kryesorë të konfigurimit për pipeline:

- `.github/workflows/ci.yml` - Përkufizimi i pipeline CI
- `.github/workflows/cd.yml` - Përkufizimi i pipeline CD
- `.github/workflows/docs-sync.yml` - Sinkronizimi i dokumentacionit
- `.github/workflows/release.yml` - Procesi i release

## Praktikat më të Mira

1. Të gjitha ndryshimet duhet të kalojnë përmes procesit PR
2. PR-të kërkojnë kalimin e kontrolleve CI
3. Branch main është i mbrojtur
4. Release-t ndjekin versionimin semantik
5. Dokumentacioni mbahet i sinkronizuar

## Monitorimi dhe Metrikat

- Gjurmimi i kohës së ekzekutimit të pipeline
- Metrikat e mbulimit të testeve
- Rezultatet e skanimit të sigurisë
- Shkallët e suksesit të deployment

## Procedurat e Emergjencës

1. Trajtimi i dështimit të pipeline
2. Procedurat e rollback
3. Rregullimet emergjente
4. Përgjigja ndaj incidenteve të sigurisë
