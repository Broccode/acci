# Mjedisi i Zhvillimit

## Përmbledhje

Mjedisi ynë i zhvillimit është konfiguruar për të siguruar një workflow të qëndrueshëm dhe efikas në të gjitha makinat e zhvillimit. Ky dokument përshkruan komponentët kryesorë dhe procedurat e konfigurimit.

## Parakushtet

- Rust (versioni më i fundit i qëndrueshëm)
- Docker dhe Docker Compose
- VS Code ose JetBrains RustRover
- Git

## Konfigurimi i IDE

### VS Code

Repository përfshin konfigurime të paracaktuara të VS Code:

- Konfigurimet e zgjerimit Rust-analyzer
- Detyra të personalizuara për operacionet e zakonshme
- Konfigurimet e debugging
- Zgjerimet e rekomanduara

### RustRover

Konfigurimet e rekomanduara për RustRover janë të përfshira në repository:

- Konfigurimet Run/Debug
- Konfigurimet e stilit të kodit
- Template-t live
- Makrot e personalizuara

## Mjedisi i Zhvillimit Docker

Mjedisi ynë i zhvillimit Docker ofron:

- Mjedis zhvillimi të qëndrueshëm në të gjitha makinat
- Mjedis testimi të izoluar
- Varësitë e shërbimeve lokale
- Aftësitë e hot-reload

### Veçoritë Kryesore

1. Ndërtime multi-stage për madhësi optimale të imazhit
2. Konfigurime specifike për zhvillim
3. Montim i volumeve për cikle të shpejta zhvillimi
4. Integrim me debugging të IDE

## Linting dhe Formatimi

### Konfigurimi i Clippy

Rregullat e personalizuara të Clippy janë përcaktuar në `.clippy.toml`:

- Rregulla të rrepta linting
- Konfigurime specifike të projektit
- Kontrolle të lidhura me performancën
- Kontrolle të lidhura me sigurinë

### Konfigurimi i Rustfmt

Formatimi i qëndrueshëm i kodit zbatohet përmes rustfmt:

- Rregullat standarde të formatimit Rust
- Konfigurime të personalizuara për specifikat e projektit
- Integrim me formatimin e IDE

## Infrastruktura e Testimit

- Testet e njësisë pranë kodit burimor
- Testet e integrimit në direktorinë `/tests`
- Testet end-to-end me Docker compose
- Ndihmësit dhe utilitetet e testimit

## Workflow i Zhvillimit

1. Klononi repository-n
2. Instaloni parakushtet
3. Ekzekutoni `cargo build` për të verifikuar konfigurimin
4. Startoni mjedisin e zhvillimit Docker
5. Hapni në VS Code ose RustRover
6. Filloni zhvillimin me hot-reload

## Praktikat më të Mira

1. Gjithmonë përdorni mjedisin e zhvillimit Docker
2. Ekzekutoni testet para commit-it
3. Ndiqni rregullat e linting
4. Mbani varësitë të përditësuara
5. Dokumentoni kërkesat e reja të zhvillimit
