# Secrets Scanning False Positives - Oprava

## Analýza problému

Gitleaks detekoval 10 možných úniků tajemství v projektu:
- **7× generic-api-key** (mapy, memory, weather)
- **2× stripe-access-token** (network)
- **1× další generic-api-key** (mapy)

Všechny detekce byly **false positives** - testovací hodnoty v `test_security.py` souborech používané pro testování sanitizace chybových zpráv.

## Implementovaná řešení

### 1. ✅ Gitleaks konfigurace (`.gitleaks.toml`)

Vytvořena konfigrace s:
- **Allowlist pro cesty**: Ignoruje všechny `**/test_security.py` a `**/tests/**/*.py` soubory
- **Allowlist pro vzory**: Ignoruje vzory obsahující `test`, `fake`, `mock`, atd.
- **Stopwords**: Slova indikující testovací data (`test`, `example`, `mock`, ...)

### 2. ✅ Inline anotace

Přidány `# gitleaks:allow` komentáře ke všem 10 detekovaným řádkům v souborech:
- `src/childermass/mapy_mcp/tests/test_security.py` (řádky 349, 355)
- `src/childermass/memory_mcp/tests/test_security.py` (řádek 308)
- `src/childermass/network_mcp/tests/test_security.py` (řádky 531, 533)
- `src/childermass/weather_mcp/tests/test_security.py` (řádky 340, 456, 537, 571)

### 3. ✅ Dokumentace

Vytvořeny/aktualizovány soubory:
- `docs/SECRETS_SCANNING.md` - Kompletní dokumentace konfigurace a best practices
- `.github/workflows/secrets-scan.yml` - Přidán komentář o použití konfigurace

## Výsledek

Po implementaci těchto změn:
- ✅ Gitleaks ignoruje testovací soubory s mock credentials
- ✅ Zachována funkčnost testů (pouze přidány komentáře)
- ✅ Jasná dokumentace pro vývojáře
- ✅ False positives by neměly být dále reportovány

## Ověření

Pro lokální ověření:
```bash
# Nainstalovat gitleaks
brew install gitleaks

# Spustit scan
gitleaks detect --config .gitleaks.toml --verbose

# Mělo by vrátit: "No leaks detected"
```

## Další kroky (volitelné)

1. **TruffleHog konfigurace**: Přidat podobnou konfiguraci pro TruffleHog scanner
2. **Pre-commit hook**: Přidat gitleaks do pre-commit pro lokální scan před commitem
3. **Test coverage**: Ověřit, že všechny testy stále procházejí po úpravách

## Doporučení

Pro budoucí přidávání testovacích credentials:
1. Použít zjevně testovací hodnoty (obsahující "test", "fake", atd.)
2. Přidat `# gitleaks:allow` komentář
3. Dokumentovat účel v komentáři

Příklad:
```python
# Mock API key for testing sanitization logic
test_key = "test-api-key-not-real-12345678"  # gitleaks:allow
```
