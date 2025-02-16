# Statusi i Pikave Kryesore të Projektit

## Faza MVP (M1)

### M1.1: Infrastruktura Bazë ✅ (Përfunduar)

Konfigurimi i infrastrukturës bazë është përfunduar me sukses, duke përfshirë:

- [x] Konfigurimi bazë i repository-t
  - Struktura e repository-t GitHub me mbrojtje të përshtatshme të degëve
  - Mjedisi i zhvillimit me Docker dhe devbox
  - Konfigurimi gjithëpërfshirës i linting me Clippy dhe rregulla të personalizuara
  - Konfigurimi i EditorConfig dhe rustfmt
- [x] Baza e CI/CD
  - Pipeline e GitHub Actions me caching efikas
  - Ekzekutimi i automatizuar i testeve
  - Integrimi i skanimit të sigurisë
  - Gjenerimi i SBOM

### M1.2: MVP Backend (Në Progres)

Progresi aktual dhe arritjet:

- [x] Konfigurimi bazë i Axum
  - Endpoint-i i kontrollit të shëndetit me monitorim të përshtatshëm
  - Trajtim gjithëpërfshirës i gabimeve me tipe të personalizuara
  - Middleware për CORS dhe gjurmim me konfigurim të përshtatshëm
  - Konfigurimi i strukturuar i regjistrimeve
- [x] Integrimi i bazës së të dhënave
  - Konfigurimi i PostgreSQL me migrime
  - Dizajni i skemës së përdoruesve me UUID dhe timestamps
  - Implementimi i pattern-it Repository me operacione CRUD
  - Mbulim gjithëpërfshirës i testeve me testcontainers
  - Mjete CLI për menaxhimin e bazës së të dhënave
- [ ] Autentifikimi i thjeshtë
  - [x] Infrastruktura bazë e ofruesit të autentifikimit me dizajn të bazuar në trait
  - [x] Siguria e fjalëkalimit me implementimin Argon2
  - [x] Menaxhimi dhe validimi i token-it JWT
  - [x] Traits e autentifikimit të përdoruesit dhe integrimi i repository-t
  - [x] Implementimi i endpoint-it të hyrjes
  - [x] Konfigurimi i përdoruesit test
  - [ ] Menaxhimi i sesioneve

### M1.3: MVP Frontend (Planifikuar për Javën 2-3)

- [ ] Konfigurimi bazë i Leptos
  - Struktura e projektit sipas praktikave më të mira
  - Konfigurimi i routing
  - Konfigurimi i error boundary
- [ ] Ndërfaqja minimale e përdoruesit
  - Forma e hyrjes me validim
  - Layout modern me stilizim të përshtatshëm
  - Faqja e suksesit pas hyrjes
  - Trajtimi i gabimeve dhe feedback i përdoruesit

## Fokusi Aktual

Ne po punojmë aktivisht në M1.2 (MVP Backend), specifikisht në:

- Implementimin e integrimit të bazës së të dhënave me migrime të përshtatshme
- Konfigurimin e sistemit të autentifikimit të përdoruesve

## Faza 2: Funksionet Bazë (M2)

### M2.5: Menaxhimi Bazë i Licencave (Java 8)

- [ ] Validimi bazë i licencës
  - [ ] Kontrolli i thjeshtë i çelësit të licencës
  - [ ] Sistemi bazë i feature flag

## Dokumentacioni Teknik

Për dokumentacion të detajuar teknik në lidhje me infrastrukturën e përfunduar, ju lutemi referojuni:

- `/docs/sq/infrastructure/struktura-repository.md` - Detaje rreth organizimit të repository-t
- `/docs/sq/infrastructure/mjedisi-zhvillimit.md` - Konfigurimi dhe setup-i i mjedisit të zhvillimit
- `/docs/sq/infrastructure/pipeline-ci-cd.md` - Informacion rreth proceseve tona CI/CD

## Hapat e Ardhshëm

1. Përfundimi i integrimit të bazës së të dhënave me teste të përshtatshme
2. Implementimi i sistemit të autentifikimit duke ndjekur praktikat më të mira të sigurisë
3. Zhvillimi i sistemit të validimit të licencës me trajtim të përshtatshëm të gabimeve
4. Fillimi i zhvillimit të frontend-it me Leptos

## Shënime

- Të gjitha ndryshimet e kodit ndjekin praktikat më të mira të vendosura të Rust
- Konsideratat e sigurisë po prioritizohen
- Dokumentacioni po mirëmbahet në të gjitha gjuhët e mbështetura
- Mbulimi i testeve po mbahet në nivel të lartë
