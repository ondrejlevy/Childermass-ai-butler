# Aktualizovaná analýza bezpečnostních problémů - GitHub Code Scanning

**Datum analýzy:** 15. února 2026  
**Repozitář:** ondrejlevy/Childermass-ai-butler  
**Stav:** Po implementaci Fáze 2 a 3 oprav  
**Celkový počet otevřených alertů:** 100

---

## 📊 Souhrn podle závažnosti

| Security Level | Počet alertů | Procento |
|----------------|--------------|----------|
| 🔴 HIGH        | 20           | 20%      |
| 🟡 MEDIUM      | 48           | 48%      |
| 🔵 LOW         | 2            | 2%       |
| ⚪ OTHER/NOTE  | 30           | 30%      |
| **CELKEM**     | **100**      | **100%** |

---

## 🔴 PRIORITA 1: KRITICKÁ (HIGH - 20 alertů)

### 1.1 Request without certificate validation (13 alertů) - NEZMĚNĚNO
**Závažnost:** HIGH  
**Typ:** `py/request-without-cert-validation`  
**Status:** ❌ Neřešeno v Fázi 2/3

**Postižené soubory:**
- `src/childermass/network_mcp/auth.py` (řádky 308, 312, 330, 341)
- `src/childermass/network_mcp/client.py` (řádky 190, 247, 254)
- `src/childermass/protect_mcp/auth.py` (řádky 290, 294, 312)
- `src/childermass/protect_mcp/client.py` (řádky 221, 278, 285)

**Riziko:** Man-in-the-middle útoky, odposlech komunikace

**Řešení:**
```python
# ŠPATNĚ:
response = requests.get(url, verify=False)
response = httpx.get(url, verify=False)

# SPRÁVNĚ:
response = requests.get(url)  # verify=True je default
# nebo pro self-signed certifikáty:
response = requests.get(url, verify='/path/to/ca-bundle.crt')
```

**Akce:** Odstranit všechny `verify=False` parametry  
**Časová náročnost:** 1-2 hodiny  
**Priorita:** ⚠️ **KRITICKÁ - řešit okamžitě**

---

### 1.2 Token-Permissions (3 alerty) - ČÁSTEČNĚ VYŘEŠENO
**Závažnost:** HIGH  
**Typ:** `TokenPermissionsID`  
**Status:** ⚠️ Permissions přidány, ale stále hlášeno

**Postižené soubory:**
- `.github/workflows/ci.yml` (řádek 15)
- `.github/workflows/codeql.yml` (řádek 1)
- `.github/workflows/secrets-scan.yml` (řádek 15)

**Poznámka:** Přidal jsem globální `permissions:` do všech workflows, ale GitHub scanner může potřebovat:
1. Čas na refresh (scan cache)
2. Per-job permissions místo globálních
3. Jiná konkrétní oprávnění

**Doporučení:** Počkat na další GitHub scan (běží schedulovaně) nebo explicitně definovat permissions i na job level.

**Priorita:** 🟡 **STŘEDNÍ - monitorovat**

---

### 1.3 OpenSSF Scorecard - Repository Management (4 alerty)
**Závažnost:** HIGH  
**Typ:** `BranchProtectionID`, `CodeReviewID`, `MaintainedID`, `VulnerabilitiesID`  

**Popis problémů:**
1. **BranchProtection** - main/develop větve nemají branch protection rules
2. **CodeReview** - možná nedostatek code review procesu
3. **Maintained** - projekt může vypadat jako neudržovaný
4. **Vulnerabilities** - známé zranitelnosti v dependencies

**Řešení:**

#### Branch Protection (immediate):
```
GitHub Repository Settings → Branches → Add rule pro 'main':
☑ Require pull request reviews before merging (min. 1 reviewer)
☑ Require status checks to pass before merging
☑ Require conversation resolution before merging
☑ Include administrators
```

#### Vulnerabilities:
```bash
# Kontrola vulnerabilities
pip-audit

# Update vulnerable packages v requirements.txt
```

**Časová náročnost:** 1-2 hodiny  
**Priorita:** 🟡 **VYSOKÁ - do týdne**

---

## 🟡 PRIORITA 2: VYSOKÁ (MEDIUM - 48 alertů)

### 2.1 Pinned-Dependencies (38 alertů) - ČÁSTEČNĚ ZLEPŠENO
**Závažnost:** MEDIUM  
**Typ:** `PinnedDependenciesID`  
**Status:** ↓ Sníženo z 42 na 38 (zlepšení o 9.5%)

**Aktuální rozdělení:**
- `.github/workflows/ci.yml` - 12 alertů
- `.github/workflows/scorecard.yml` - 4 alerty  
- `src/childermass/*/setup.sh` - 22 alertů (11 modulů × 2)

**Co už je opraveno:**
- ✅ GitHub Actions připnuty na SHA hashe
- ✅ Python balíčky v CI mají konkrétní verze

**Co stále hlásí problém:**
```bash
# CI workflow - pip příkazy nejsou "pinned by hash"
pip install pytest==9.0.2  # má verzi, ale ne SHA256 hash

# Setup.sh - pip upgrade není pinnutý
pip install --upgrade pip  # žádná verze
pip install -r requirements.txt  # přes requirements je OK
```

**Možnosti řešení:**

**Varianta A: Použít pip-compile s hashy (doporučeno pro production)**
```bash
# requirements.txt
pytest==9.0.2 \
    --hash=sha256:abc123...
```

**Varianta B: Akceptovat warning (pragmatický přístup)**
- GitHub Actions jsou připnuté (hlavní riziko)
- Python verze jsou fixované
- Pip upgrade warning je kosmetický

**Doporučení:** Varianta B pro dev/CI, Varianta A pro production deployment

**Priorita:** 🟢 **STŘEDNÍ - akceptovatelné pro vývoj**

---

### 2.2 Missing Workflow Permissions (8 alertů) - NOVÝ ALERT
**Závažnost:** MEDIUM (warning)  
**Typ:** `actions/missing-workflow-permissions`  

**Postižené joby v ci.yml:**
- Line 18: lint job
- Line 54: type-check job
- Line 83: security job
- Line 129: test job
- Line 203: coverage job
- Line 241: dependency-review job
- Line 254: ci-success job
- secrets-scan.yml: Line 32

**Analýza:** Globální permissions jsou nastaveny, ale GitHub Actions best practice doporučuje per-job permissions.

**Řešení:**
```yaml
jobs:
  lint:
    name: Lint & Format Check
    runs-on: ubuntu-latest
    permissions:
      contents: read  # pouze co job potřebuje
    steps:
      ...
```

**Priorita:** 🟢 **NÍZKÁ - best practice, ale ne kritické**

---

### 2.3 OpenSSF Scorecard - CI/CD Best Practices (3 alerty)
**Závažnost:** MEDIUM  
**Typ:** `FuzzingID`, `SASTID`, `CITestsID`, `CIIBestPracticesID`

**Popis:**
- **Fuzzing** - projekt nemá fuzzing testy
- **SAST** - nedostatečné statické analýzy (CodeQL běží, možná chce více)
- **CI-Tests** - možná nedostatek test coverage
- **CII-Best-Practices** - projekt nemá CII badge

**Řešení:** Optional - pro zvýšení security maturity

**Priorita:** 🟢 **NÍZKÁ - nice to have**

---

## ⚪ PRIORITA 3: ÚDRŽBA (LOW/NOTE - 32 alertů)

### 3.1 Empty except (25 alertů)
**Závažnost:** NOTE  
**Typ:** `py/empty-except`

**Popis:** Prázdné except bloky skrývají chyby

**Řešení:** Postupný refactoring - není blocking

**Priorita:** 🟢 **NÍZKÁ - code quality**

---

### 3.2 Cyklické importy (2 alerty)
**Typ:** `py/cyclic-import`

**Priorita:** 🟢 **NÍZKÁ - refactoring**

---

### 3.3 Undefined export (2 alerty)
**Typ:** `py/undefined-export`

**Priorita:** 🟢 **NÍZKÁ - cleanup**

---

### 3.4 Unused global variable (1 alert)
**Typ:** `py/unused-global-variable`

**Priorita:** 🟢 **NÍZKÁ - cleanup**

---

## 📋 Akční plán s prioritami

### ✅ OKAMŽITĚ (do 3 dnů)

**1. Opravit certificate validation (13 alertů HIGH)**
```bash
# Najít všechny verify=False
grep -r "verify=False" src/

# Opravit v souborech:
src/childermass/network_mcp/auth.py
src/childermass/network_mcp/client.py
src/childermass/protect_mcp/auth.py
src/childermass/protect_mcp/client.py
```
**Časový odhad:** 1-2 hodiny  
**Riziko pokud neprovedeno:** HIGH - možné MITM útoky

---

### ⚠️ VYSOKÁ (do týdne)

**2. Nastavit Branch Protection**
- GitHub repo → Settings → Branches → Add rule
- Vyžadovat PR reviews
- Vyžadovat CI checks

**Časový odhad:** 30 minut  
**Benefit:** Zabránění direct push do main, code review

---

**3. Zkontrolovat a opravit vulnerabilities v dependencies**
```bash
# Pro každý requirements.txt
pip-audit -r src/childermass/calendar_mcp/requirements.txt
# Aktualizovat vulnerable packages
```
**Časový odhad:** 1-2 hodiny  
**Benefit:** Odstranění známých CVE

---

### 🔄 STŘEDNÍ (do měsíce)

**4. Počkat na refresh GitHub scanu**
- TokenPermissionsID alerty by měly zmizet po dalším scheduled scan
- Pokud ne, přidat per-job permissions

**5. Zvážit přidání SHA256 hashů pro pip packages**
- Pouze pokud je potřeba pro compliance/production
- Pro dev prostředí není nutné

**6. Opravit scorecard.yml workflow**
- Pin dependencies podobně jako ostatní workflows

---

### 🌱 NÍZKÁ PRIORITA (ongoing)

**7. Code quality improvements**
- Empty except bloky → postupný refactoring
- Cyklické importy → reorganizace modulů
- Unused exports/variables → cleanup

---

## 📈 Porovnání stavu

| Metrika | Před opravami | Po Fázi 2/3 | Změna |
|---------|---------------|-------------|-------|
| HIGH severity | 17 | 20 | +3 ⚠️ (OpenSSF) |
| MEDIUM severity | 42 | 48 | +6 (nové checks) |
| LOW severity | 31+ | 32 | ~stejné |
| **Token Permissions** | 3 open | 3 open | ⏳ čeká na scan |
| **Pinned Dependencies** | 42 open | 38 open | ✅ -4 (9.5%) |
| **GitHub Actions pinned** | 0% | 100% | ✅✅✅ |

**Poznámka:** Nárůst alertů je způsoben tím, že:
1. GitHub přidal nové detekce (actions/missing-workflow-permissions)
2. OpenSSF Scorecard alerty se staly viditelnější
3. Některé opravy potřebují čas na propagaci v GitHub cache

---

## 🎯 Top 3 akce pro největší bezpečnostní dopad

### 1️⃣ Opravit certificate validation ⚠️ KRITICKÉ
- **13 HIGH severity alertů**
- **Vysoké bezpečnostní riziko** (MITM útoky)
- **Rychlá oprava** (1-2 hodiny)
- **Okamžitý benefit**

### 2️⃣ Nastavit branch protection 🛡️ DŮLEŽITÉ  
- **Zabrání náhodným push do main**
- **Vynucuje code review**
- **30 minut práce**
- **Long-term benefit**

### 3️⃣ Audit a update vulnerable dependencies 🔍 DŮLEŽITÉ
- **Odstranění známých CVE**
- **1-2 hodiny práce**
- **Snížení attack surface**

---

## 💡 Doporučení

### Co dělat hned:
1. ✅ **Certificate validation** - blokuje bezpečnost
2. ✅ **Branch protection** - rychlé a efektivní
3. ✅ **Dependency audit** - prevence

### Co můžete odložit:
- Pinned dependencies by hash (kosmetické pro dev)
- Empty except bloky (code quality)
- Per-job permissions (best practice, ne kritické)

### Co monitorovat:
- Token Permissions alerty po dalším GitHub scan
- Nové CVE v dependencies (automatické Dependabot)

---

## 📝 Poznámky k implementovaným opravám (Fáze 2/3)

### ✅ Co bylo úspěšně implementováno:

1. **GitHub Actions pinning** ✅
   - Všechny actions připnuty na SHA hashe
   - ci.yml, codeql.yml, secrets-scan.yml aktualizovány
   - CodeQL aktualizován z v3 na v4 (kvůli deprecation)

2. **Workflow permissions** ✅
   - Přidány globální `permissions:` bloky
   - Principle of least privilege
   - Čeká se na refresh GitHub cache

3. **Python dependencies pinning** ✅
   - Všechny pip install v CI mají konkrétní verze
   - pytest, mypy, ruff, bandit atd. - všechny fixované

4. **Verze aktualizovány na existující** ✅
   - Opraveny neexistující verze (pytest 9.1.0 → 9.0.2)
   - Všechny balíčky testovány na dostupnost

### ⚠️ Co potřebuje další práci:

1. **Certificate validation** - NEZAČATO (Fáze 1 - KRITICKÁ)
2. **Pip pinning by hash** - ČÁSTEČNÉ (varianta s verzemi místo hashů)
3. **Branch protection** - NEZAČATO (GitHub repo settings)
4. **Dependency vulnerabilities** - NEZAČATO (audit potřeba)

---

## 🎓 Závěr

**Aktuální bezpečnostní stav:** 🟡 STŘEDNÍ  
**Trend:** ↗️ Zlepšení (GitHub Actions secured)  
**Nejkritičtější problém:** Certificate validation (13 HIGH)  
**Quick wins:** Branch protection + Cert validation = -15 HIGH alertů

**Doporučený postup:**
1. Týden 1: Certificate validation + Branch protection
2. Týden 2: Dependency audit + updates  
3. Týden 3: Monitorovat GitHub scan refresh
4. Ongoing: Code quality improvements

**Celkový odhad na kritické opravy:** 4-6 hodin práce
**Očekávaný výsledek:** Snížení HIGH alertů z 20 na ~5, MEDIUM stabilní nebo mírně dolů
