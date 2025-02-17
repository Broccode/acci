#!/bin/bash
set -e

# Farbkonstanten
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

# Schwellenwerte aus Umgebungsvariablen oder Standardwerte
CRITICAL_THRESHOLD=${CRITICAL_COVERAGE_THRESHOLD:-95}
CORE_THRESHOLD=${CORE_COVERAGE_THRESHOLD:-90}
GENERAL_THRESHOLD=${GENERAL_COVERAGE_THRESHOLD:-80}

echo "Überprüfe Coverage-Schwellenwerte:"
echo "- Kritische Pfade: ${CRITICAL_THRESHOLD}%"
echo "- Kernfunktionalität: ${CORE_THRESHOLD}%"
echo "- Allgemeiner Code: ${GENERAL_THRESHOLD}%"

# JSON-Report generieren
cargo llvm-cov report --json > coverage.json

# Funktion zum Extrahieren der Coverage aus JSON
get_coverage() {
    local crate=$1
    jq -r ".\"$crate\".coverage // 0" coverage.json
}

# Kritische Pfade überprüfen
check_critical() {
    local crate=$1
    local coverage=$(get_coverage "$crate")
    if (( $(echo "$coverage < $CRITICAL_THRESHOLD" | bc -l) )); then
        echo -e "${RED}Fehler: Coverage für $crate ($coverage%) unter kritischem Schwellenwert ($CRITICAL_THRESHOLD%)${NC}"
        return 1
    else
        echo -e "${GREEN}✓ $crate: $coverage% (kritischer Pfad)${NC}"
        return 0
    }
}

# Kernfunktionalität überprüfen
check_core() {
    local crate=$1
    local coverage=$(get_coverage "$crate")
    if (( $(echo "$coverage < $CORE_THRESHOLD" | bc -l) )); then
        echo -e "${RED}Fehler: Coverage für $crate ($coverage%) unter Kern-Schwellenwert ($CORE_THRESHOLD%)${NC}"
        return 1
    else
        echo -e "${GREEN}✓ $crate: $coverage% (Kernfunktionalität)${NC}"
        return 0
    }
}

# Allgemeinen Code überprüfen
check_general() {
    local crate=$1
    local coverage=$(get_coverage "$crate")
    if (( $(echo "$coverage < $GENERAL_THRESHOLD" | bc -l) )); then
        echo -e "${YELLOW}Warnung: Coverage für $crate ($coverage%) unter allgemeinem Schwellenwert ($GENERAL_THRESHOLD%)${NC}"
        return 0
    else
        echo -e "${GREEN}✓ $crate: $coverage% (allgemeiner Code)${NC}"
        return 0
    }
}

echo -e "\nÜberprüfe kritische Pfade..."
check_critical "acci-auth" || exit 1
check_critical "acci-core/src/auth.rs" || exit 1

echo -e "\nÜberprüfe Kernfunktionalität..."
check_core "acci-core" || exit 1
check_core "acci-db" || exit 1
check_core "acci-api" || exit 1

echo -e "\nÜberprüfe allgemeinen Code..."
check_general "acci-cli" || true
check_general "acci-frontend" || true

# Gesamtcoverage berechnen und ausgeben
TOTAL_COVERAGE=$(jq -r '.total.coverage' coverage.json)
echo -e "\nGesamtcoverage: ${GREEN}${TOTAL_COVERAGE}%${NC}"

# Coverage-Report für CI-Artefakte generieren
echo "Generiere detaillierten Coverage-Report..."
mkdir -p target/coverage-report
{
    echo "# Coverage Report"
    echo "## Zusammenfassung"
    echo "- Gesamtcoverage: ${TOTAL_COVERAGE}%"
    echo "- Zeitpunkt: $(date)"
    echo "- Commit: ${GITHUB_SHA:-lokal}"
    echo
    echo "## Details nach Komponente"
    echo "### Kritische Pfade"
    echo "- acci-auth: $(get_coverage 'acci-auth')%"
    echo "- acci-core/auth: $(get_coverage 'acci-core/src/auth.rs')%"
    echo
    echo "### Kernfunktionalität"
    echo "- acci-core: $(get_coverage 'acci-core')%"
    echo "- acci-db: $(get_coverage 'acci-db')%"
    echo "- acci-api: $(get_coverage 'acci-api')%"
    echo
    echo "### Allgemeiner Code"
    echo "- acci-cli: $(get_coverage 'acci-cli')%"
    echo "- acci-frontend: $(get_coverage 'acci-frontend')%"
} > target/coverage-report/report.md

echo "Coverage-Report wurde in target/coverage-report/report.md gespeichert"
