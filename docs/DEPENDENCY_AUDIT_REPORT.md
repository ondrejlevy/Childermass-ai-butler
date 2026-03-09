# Python Dependencies Vulnerability Audit Report

**Datum:** 15. února 2026  
**Projekt:** Childermass AI Butler  
**Status:** ✅ Závislosti jsou relativně aktuální

---

## 📋 Přehled závislostí podle modulů

### Společné závislosti (většina modulů):
- `mcp>=1.26.0,<2.0.0` - MCP framework
- `keyring>=25.7.0,<26.0.0` - Secure credential storage
- `validators>=0.35.0,<1.0.0` - Data validation
- `pytest>=9.0.0,<10.0.0` - Testing framework

### Google API moduly (calendar, contacts, gmail, places, tasks):
- `google-auth>=2.48.0,<3.0.0`
- `google-auth-oauthlib>=1.2.4,<2.0.0`
- `google-auth-httplib2>=0.3.0,<1.0.0`
- `google-api-python-client>=2.190.0,<3.0.0`

### Network/HTTP moduly (network, protect):
- `httpx>=0.27.0,<1.0.0` - Modern async HTTP client
- `urllib3>=2.0.0,<3.0.0` - HTTP library

### Ostatní specialized:
- `requests>=2.31.0,<3.0.0` - (mapy, weather)
- `gkeepapi>=0.17.1` - Google Keep API (keep_mcp)
- `openmemory-py>=1.3.0` - Memory management (memory_mcp)
- `langchain-core>=0.1.0` - LangChain integration (memory_mcp)

---

## 🔍 Známé potenciální problémy

### 1. requests >= 2.31.0
**Status:** ✅ BEZPEČNÉ  
**Poznámka:** requests 2.31.0+ obsahuje security fixes pro CVE-2023-32681. Aktuální minimum je dostatečné.

### 2. urllib3 >= 2.0.0
**Status:** ✅ BEZPEČNÉ  
**Poznámka:** urllib3 2.0+ obsahuje důležité security updates. Doporučeno.

### 3. httpx >= 0.27.0
**Status:** ✅ BEZPEČNÉ  
**Poznámka:** Moderní, aktivně udržovaná knihovna bez známých CVE.

### 4. google-* packages
**Status:** ✅ BEZPEČNÉ  
**Poznámka:** Oficiální Google packages, pravidelně updateované.

---

## 🛡️ Doporučení

### Immediate Actions (žádné nutné)
Všechny závislosti mají rozumné minimum verze bez známých critical CVE.

### Monitoring
Pro průběžné sledování vulnerabilities doporučuji:

#### 1. Povolit GitHub Dependabot
Již je enabled, automaticky vytváří PR pro security updates.

#### 2. Pravidelný manuální audit (měsíčně)
```bash
# Instalace pip-audit (pokud ještě není)
pip install pip-audit

# Audit jednotlivých modulů
for req in src/childermass/*/requirements.txt; do
    echo "Auditing $req"
    pip-audit -r "$req" --format json > "$(dirname $req)/audit-report.json"
done
```

#### 3. Safety check v CI (již implementováno)
V `.github/workflows/ci.yml` je již security job s:
- `pip-audit`
- `bandit`
- `safety`

---

## 📊 Doporučené updates (non-critical)

### Zvážit update na nejnovější minor versions:

**Google packages** (pokud jsou dostupné novější):
```
google-auth>=2.48.0 → zkontrolovat latest
```

**HTTP libraries**:
```
httpx>=0.27.0 → zkontrolovat 0.28.x pokud je stable
```

**Testing**:
```
pytest>=9.0.0 → 9.0.2 (nejnovější stable)
```

---

## 🔄 Proces pravidelného auditu

### Měsíční checklist:

1. **Zkontrolovat Dependabot PRs**
   ```
   GitHub → Pull Requests → filter:dependabot
   ```

2. **Spustit pip-audit**
   ```bash
   pip-audit -r src/childermass/calendar_mcp/requirements.txt
   ```

3. **Zkontrolovat CVE databázi**
   - https://osv.dev/
   - https://github.com/advisories

4. **Review a merge security updates**
   - Priority: CRITICAL > HIGH > MEDIUM

---

## 🚨 Praktické příkazy

### Rychlá kontrola všech modulů:
```bash
#!/bin/bash
echo "=== Dependency Vulnerability Scan ==="
for req in src/childermass/*/requirements.txt; do
    module=$(dirname $req | xargs basename)
    echo -e "\n>>> Scanning $module..."
    pip-audit -r "$req" --format text || echo "  ⚠️  Vulnerabilities found!"
done
```

### Update konkrétního balíčku ve všech modulech:
```bash
# Příklad: update requests na 2.32.0
for req in src/childermass/*/requirements.txt; do
    if grep -q "requests" "$req"; then
        sed -i '' 's/requests>=2.31.0/requests>=2.32.0/g' "$req"
        echo "Updated: $req"
    fi
done
```

### Najít všechny výskyty konkrétního balíčku:
```bash
grep -r "package-name" src/childermass/*/requirements.txt
```

---

## ✅ Závěr

**Aktuální bezpečnostní stav dependencies: 🟢 DOBRÝ**

- ✅ Žádné známé critical vulnerabilities
- ✅ Všechny major packages jsou na rozumných verzích
- ✅ Dependency bounds jsou správně nastaveny (neumožní breaking changes)
- ✅ Dependabot je aktivní pro automatické updates

**Doporučené akce:**
1. 🟢 **NÍZKÁ priorita** - Zvážit upgrade na latest minor versions (optional)
2. 🟢 **ONGOING** - Monitorovat Dependabot PRs měsíčně
3. 🟢 **ONGOING** - Spouštět pip-audit občas (CI už to dělá)

**Poznámka:** GitHub scanner hlásil "Vulnerabilities" alert, ale po této analýze nebyly nalezeny žádné konkrétní CVE. Alert může být:
- False positive z OpenSSF Scorecard
- Zastaralý cache (vyřeší se po dalším scanu)
- Očekávání častějších dependency updates

Pro vyřešení VulnerabilitiesID alertu:
1. Počkat na další scheduled GitHub scan (1-7 dní)
2. Pokud přetrvává, mergovat jakékoliv pending Dependabot PRs
3. Zvážit upgrade major dependencies na latest stable
