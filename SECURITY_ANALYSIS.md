# Analýza bezpečnostních problémů - GitHub Code Scanning

**Datum analýzy:** 15. února 2026  
**Repozitář:** ondrejlevy/Childermass-ai-butler  
**Celkový počet alertů:** 100+ (analyzováno prvních 100)

## Souhrn podle závažnosti

### 🔴 HIGH SEVERITY (17 otevřených alertů)

#### 1. Request without certificate validation (13 alertů)
**Závažnost:** HIGH (security_severity_level: high)  
**Typ:** `py/request-without-cert-validation`  
**Stav:** 13/13 otevřených

**Popis problému:**  
Aplikace provádí HTTP/HTTPS requesty bez validace SSL/TLS certifikátů, což umožňuje man-in-the-middle útoky.

**Postižené soubory:**
- `src/childermass/network_mcp/client.py` (řádky 190, 247, 254)
- `src/childermass/network_mcp/auth.py` (řádky 308, 312, 330, 341)
- `src/childermass/protect_mcp/client.py` (řádky 221, 278, 285)
- `src/childermass/protect_mcp/auth.py` (řádky 290, 294, 312)

**Řešení:**
- Odstranit parametr `verify=False` z requests volání
- Použít `verify=True` nebo cestu k CA bundle
- Pro development použít vlastní CA certifikáty místo vypnutí validace

**Priorita:** ⚠️ KRITICKÁ - mělo by být opraveno okamžitě

---

#### 2. Token-Permissions (3 alerty)
**Závažnost:** HIGH (security_severity_level: high)  
**Typ:** `TokenPermissionsID`  
**Stav:** 3/3 otevřených

**Popis problému:**  
GitHub Actions workflows mají příliš široká oprávnění, což zvyšuje riziko zneužití GITHUB_TOKEN.

**Postižené soubory:**
- `.github/workflows/ci.yml`
- `.github/workflows/codeql.yml`
- `.github/workflows/secrets-scan.yml`

**Řešení:**
Explicitně definovat minimální potřebná oprávnění:
```yaml
permissions:
  contents: read
  security-events: write  # pouze pokud je potřeba
```

**Priorita:** ⚠️ VYSOKÁ

---

#### 3. Code-Review, Maintained, Vulnerabilities (3 alerty)
**Závažnost:** HIGH  
**Typ:** OpenSSF Scorecard checks  
**Stav:** Otevřené

**Popis problému:**
- **Code-Review**: Možná nedostatečná kontrola pull requestů
- **Maintained**: Projekt může vypadat neudržovaný
- **Vulnerabilities**: Známé zranitelnosti v závislostech

**Řešení:**
- Nastavit branch protection rules s povinným code review
- Pravidelně mergovat dependabot updates
- Aktualizovat závislosti a skenovat vulnerabilities

**Priorita:** ⚠️ STŘEDNÍ až VYSOKÁ

---

### 🟡 MEDIUM SEVERITY (42 otevřených alertů)

#### 4. Pinned-Dependencies (42 alertů)
**Závažnost:** MEDIUM (security_severity_level: medium)  
**Typ:** `PinnedDependenciesID`  
**Stav:** 42/47 otevřených

**Popis problému:**  
Závislosti nejsou přesně specifikované (pinnuté), což může vést k supply chain útokům nebo nekonzistentním buildům.

**Postižené soubory:**
- **GitHub Actions workflows:**
  - `.github/workflows/ci.yml`
  - `.github/workflows/codeql.yml`
  - `.github/workflows/secrets-scan.yml`
  
- **Setup skripty všech MCP modulů:**
  - `src/childermass/*/setup.sh` (calendar, contacts, gmail, keep, mapy, memory, network, places, protect, tasks, weather)

**Řešení:**

**Pro GitHub Actions:**
```yaml
# Špatně:
- uses: actions/checkout@v4

# Správně (pinnutí na SHA):
- uses: actions/checkout@b4ffde65f46336ab88eb53be808477a3936bae11  # v4.1.1
```

**Pro Python dependencies v setup.sh:**
```bash
# Špatně:
pip install google-auth

# Správně:
pip install google-auth==2.27.0
```

**Priorita:** 🟡 STŘEDNÍ - důležité pro production nasazení

---

### 🔵 LOW SEVERITY / NOTE (31 otevřených alertů)

#### 5. Empty except (25 alertů)
**Závažnost:** NOTE  
**Typ:** `py/empty-except`  
**Stav:** 25/25 otevřených

**Popis problému:**  
Prázdné except bloky ("silent failures") potlačují všechny výjimky, což znesnadňuje debugging a může skrýt vážné chyby.

**Postižené soubory:**
- `src/childermass/memory_mcp/client.py` (řádek 647)
- `src/childermass/*/auth.py` - většina auth modulů (weather: 48, 57, 125, 133; mapy: 51, 60, 124, 132; atd.)

**Řešení:**
```python
# Špatně:
try:
    some_operation()
except:
    pass

# Správně:
try:
    some_operation()
except SpecificError as e:
    logger.warning(f"Expected error: {e}")
    # nebo raise, pokud je to kritické
```

**Priorita:** 🟢 NÍZKÁ až STŘEDNÍ - spíše code quality issue

---

#### 6. Cyclic import (2 alerty)
**Závažnost:** NOTE  
**Typ:** `py/cyclic-import`  
**Stav:** 2/2 otevřených

**Popis problému:**  
Cyklické importy mohou vést k runtime chybám při importu modulů.

**Řešení:**
- Refaktorovat kód pro odstranění cyklických závislostí
- Použít lazy imports uvnitř funkcí
- Reorganizovat moduly

**Priorita:** 🟢 NÍZKÁ až STŘEDNÍ

---

#### 7. Undefined export (2 alerty)
**Závažnost:** ERROR (severity: error, ale security_level: N/A)  
**Typ:** `py/undefined-export`  
**Stav:** 2/2 otevřených

**Popis problému:**  
`__all__` obsahuje symboly, které nejsou definované v modulu.

**Řešení:**
- Opravit `__all__` seznam
- Nebo odstranit neexistující export

**Priorita:** 🟢 NÍZKÁ

---

#### 8. Ostatní (5 alertů)
- **Unused global variable** (1 alert) - code cleanup
- **CI-Tests, CII-Best-Practices, SAST, Fuzzing** (4 alerty) - OpenSSF Scorecard pravidla pro zlepšení CI/CD procesu

**Priorita:** 🟢 NÍZKÁ - best practices

---

## Doporučený plán oprav (podle priority)

### Fáze 1: KRITICKÉ (do 1 týdne)
1. ✅ **Opravit certificate validation** (13 alertů)
   - Odstranit všechny `verify=False` parametry
   - Otestovat, že aplikace funguje s validací
   - Případně přidat custom CA bundle

### Fáze 2: VYSOKÁ (do 2 týdnů)
2. ✅ **Opravit GitHub Actions permissions** (3 alerty)
   - Přidat explicitní `permissions:` do všech workflows
   - Použít principle of least privilege

3. ✅ **Zkontrolovat a opravit závislosti** (Vulnerabilities alert)
   - Spustit `pip audit` nebo `safety check`
   - Aktualizovat vulnerable packages

### Fáze 3: STŘEDNÍ (do 1 měsíce)
4. ✅ **Pin dependencies** (42 alertů)
   - GitHub Actions: použít SHA hash místo tag
   - Python: přidat přesné verze do requirements/setup.sh
   - Případně použít tools jako Dependabot pro automatické updates

5. ✅ **Nastavit branch protection** (Code-Review alert)
   - Vyžadovat alespoň 1 review před merge
   - Vyžadovat úspěšné CI checks

### Fáze 4: NÍZKÁ PRIORITA (ongoing)
6. 🔄 **Opravit empty except bloky** (25 alertů)
   - Postupně refaktorovat na specific exceptions
   - Přidat logging

7. 🔄 **Vyřešit cyklické importy** (2 alerty)
   - Code refactoring

8. 🔄 **Code quality improvements**
   - Undefined exports, unused variables

---

## Statistika

| Závažnost | Počet otevřených | Procento |
|-----------|------------------|----------|
| HIGH      | 17               | ~17%     |
| MEDIUM    | 42               | ~42%     |
| LOW/NOTE  | 30+              | ~30%+    |
| **CELKEM** | **100+**        | **100%** |

---

## Automatizace oprav

Pro některé problémy lze použít automatické nástroje:

```bash
# Auto-fix imports, formatting
ruff check --fix src/

# Check for security issues
bandit -r src/

# Find outdated dependencies
pip list --outdated

# Check for vulnerabilities
pip-audit
```

---

## Závěr

**Nejzávažnější problémy:**
1. 🔴 **Certificate validation** - bezpečnostní riziko při komunikaci přes síť
2. 🔴 **Token permissions** - riziko kompromitace GitHub Actions
3. 🟡 **Unpinned dependencies** - supply chain risk

**Doporučení:**  
Prioritně řešit HIGH severity alerty (certificate validation a token permissions). Pinned dependencies jsou důležité zejména pro production nasazení. Empty except bloky a ostatní code quality issues lze řešit postupně v rámci běžného vývoje.

**Odhad času na opravu:**
- Kritické problémy: 2-4 hodiny
- Vysoká priorita: 4-8 hodin
- Střední priorita: 1-2 dny
- Celkem: ~3-5 dnů práce
