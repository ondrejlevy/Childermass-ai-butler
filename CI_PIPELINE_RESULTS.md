# CI Pipeline - Lokální Spuštění a Výsledky

**Datum:** 15. února 2026  
**Python verze:** 3.14.3

## 📊 Souhrn Výsledků

| Nástroj | Status | Počet problémů | Závažnost |
|---------|--------|----------------|-----------|
| **Ruff** | ⚠️ Částečně opraveno | 765 zbývajících (z 2132) | Střední |
| **Black** | ✅ Opraveno | 53 souborů přeformátováno | - |
| **isort** | ✅ OK | 1 soubor přeskočen | - |
| **MyPy** | ⚠️ Vyžaduje pozornost | 115 type errors | Střední |
| **Bandit** | ⚠️ Vyžaduje review | 802 low, 9 medium | Nízká-Střední |
| **pip-audit** | ✅ OK | 0 vulnerabilities | - |
| **pytest** | ✅✅✅ Úspěch | 134/134 passed (calendar_mcp) | - |

## 🔍 Detailní Analýza

### 1. Ruff Linting ⚠️

**Status:** Automaticky opraveno 1367 problémů, zbývá 765

**Hlavní problémy:**
- ✅ **I001**: Import blocks - automaticky opraveno
- ⚠️ **PLW0603**: Global statement usage - 44 výskytů
- ⚠️ **PLC0415**: Imports not at top-level - 159 výskytů
- ⚠️ **S110**: Try-except-pass without logging - 23 výskytů
- ⚠️ **TRY300**: Statement after try that should be in else - 41 výskytů
- ⚠️ **PTH123**: Use Path.open() instead of open() - 15 výskytů
- ⚠️ **T201**: Print statements found - 38 výskytů
- ⚠️ **PLR2004**: Magic values in comparisons - 78 výskytů (hlavně v testech)

**Příklady konkrétních problémů:**

```python
# Problem: PLC0415 - Import uvnitř funkce
def _is_keyring_available() -> bool:
    try:
        import keyring  # ← Mělo by být na začátku souboru
        ...
```

```python
# Problem: S110 - Try-except-pass
try:
    for acc in json.loads(index_raw):
        accounts.add(acc)
except Exception:
    pass  # ← Mělo by logovat exception
```

```python
# Problem: PTH123 - Použití open() místo Path.open()
with open(token_path, "w") as f:  # ← Použít token_path.open("w")
    f.write(token_json)
```

### 2. Black Formatting ✅

**Status:** Úspěšně dokončeno

- **Přeformátováno:** 53 souborů
- **Beze změn:** 25 souborů
- **Celkový počet:** 78 Python souborů

### 3. isort Import Sorting ✅

**Status:** Úspěšně dokončeno

- **Přeskočeno:** 1 soubor
- Importy jsou nyní správně seřazeny podle black profilu

### 4. MyPy Type Checking ⚠️

**Status:** 115 type errors nalezeno

**Kategorie problémů:**

1. **Unreachable statements** (75 výskytů)
   - Většinou v security validation funkcích
   - Kód po `raise` statements označen jako unreachable
   - Příklad: `src/childermass/weather_mcp/security.py:83`

2. **Missing type stubs** (3 výskyty)
   ```
   error: Library stubs not installed for "requests"
   note: Hint: "python3 -m pip install types-requests"
   ```

3. **no-any-return** (28 výskytů)
   - Funkce vracející Any místo konkrétního typu
   - Příklad: `auth.py` credential loading funkce

4. **unused-ignore comments** (15 výskytů)
   - `# type: ignore` komentáře, které už nejsou potřeba

5. **arg-type mismatches** (8 výskytů v testech)
   - Testy záměrně posílají špatné typy pro testování validace

**Příklad problému:**
```python
def load_token_from_keyring(account: str) -> str | None:
    try:
        import keyring
        token_json = keyring.get_password(KEYRING_SERVICE, account)
        return token_json  # ← Returns Any, not str | None
    except Exception:
        return None
```

### 5. Bandit Security Analysis ⚠️

**Status:** 802 Low severity, 9 Medium confidence issues

**Rozložení problémů:**

1. **B101: assert_used** (~780 výskytů)
   - **Lokace:** Výhradně v test souborech
   - **Závažnost:** Low
   - **Řešení:** OK pro testy, ignorovat v pyproject.toml

2. **B110: try_except_pass** (23 výskytů)
   - **Lokace:** auth.py, security.py soubory
   - **Závažnost:** Low-Medium
   - **Problém:** Výjimky jsou tichounce ignorovány
   - **Příklad:**
     ```python
     try:
         for acc in json.loads(index_raw):
             accounts.add(acc)
     except Exception:
         pass  # ← Špatná praxe
     ```

**Detekované oblasti:**
```
src/childermass/calendar_mcp/auth.py:114
src/childermass/calendar_mcp/auth.py:342
src/childermass/calendar_mcp/security.py:583
... (další 20 míst)
```

### 6. pip-audit Vulnerability Scan ✅

**Status:** Žádné známé zranitelnosti

- **Zkontrolováno:** calendar_mcp/requirements.txt
- **Výsledek:** No known vulnerabilities found
- **Doporučení:** Spustit pro všech 11 MCP serverů

### 7. pytest Tests ✅✅✅

**Status:** Všechny testy úspěšné

**calendar_mcp výsledky:**
- **Celkem testů:** 134
- **Úspěšných:** 134 (100%)
- **Neúspěšných:** 0
- **Čas:** 1.52s

**Test pokrytí:**
- ✅ Validation functions (calendar IDs, event IDs, datetime, timezone)
- ✅ Security functions (sanitization, rate limiting, audit logging)
- ✅ Authentication basics
- ✅ Client validation

## 🔧 Doporučené Opravy

### Priorita 1: Kritické (Ihned)

#### 1.1 Nainstalovat chybějící type stubs
```bash
pip install types-requests
```

#### 1.2 Opravit medium confidence security issues
Přidat logging do try-except bloků:
```python
# Před:
except Exception:
    pass

# Po:
except Exception as e:
    logger.warning("Operation failed: %s", e)
    # nebo
    logger.debug("Optional operation skipped: %s", e)
```

### Priorita 2: Vysoká (Tento týden)

#### 2.1 Přesunout importy na začátek souborů
```python
# Přesunout keyring import na začátek
import keyring  # Na začátek souboru

# Místo opakovaného importu v každé funkci
def function():
    import keyring  # ← Odstranit
```

**Poznámka:** Pokud je import keyring uvnitř funkce záměrný (optional dependency), přidat:
```python
import keyring  # type: ignore[import]
```

#### 2.2 Použít Path.open() místo open()
```python
# Před:
with open(token_path, "w") as f:
    f.write(token_json)

# Po:
token_path.write_text(token_json)
# nebo
with token_path.open("w") as f:
    f.write(token_json)
```

#### 2.3 Opravit type hints pro return values
```python
# Před:
def load_token() -> str | None:
    return keyring.get_password(...)  # Returns Any

# Po:
def load_token() -> str | None:
    result = keyring.get_password(...)
    return str(result) if result else None
```

### Priorita 3: Střední (Tento měsíc)

#### 3.1 Odstranit print statements
Nahradit print() loggingem:
```python
# Před:
print(f"Token saved for {account}")

# Po:
logger.info("Token saved for account %s", account)
```

#### 3.2 Refaktorovat globální proměnné
```python
# Místo global statements, zvážit:
class KeyringManager:
    def __init__(self):
        self._available = None
    
    def is_available(self) -> bool:
        if self._available is None:
            self._available = self._check_keyring()
        return self._available
```

#### 3.3 Přidat konstanty pro magic values
```python
# V testech:
DEFAULT_TEMPERATURE = 15.5
MAX_RESULTS_LIMIT = 2500

# Místo:
assert weather.temperature == 15.5
assert max_results <= 2500
```

### Priorita 4: Nízká (Nice to have)

#### 4.1 Přesunout statements z try bloků do else
```python
# Před:
try:
    keyring.set_password(...)
    return True
except Exception:
    return False

# Po:
try:
    keyring.set_password(...)
except Exception:
    return False
else:
    return True
```

#### 4.2 Aktualizovat pyproject.toml pro Bandit
```toml
[tool.bandit]
exclude_dirs = ["/tests/"]
skips = ["B101"]  # assert_used - OK v testech
```

## 📝 Konfigurace Opravy

### Aktualizovat .ruffignore nebo ruff.toml

```toml
[lint.per-file-ignores]
"**/tests/**" = [
    "S101",     # assert_used
    "PLR2004",  # magic values
]
"**/auth.py" = [
    "PLC0415",  # late imports (optional dependency)
]
```

### Aktualizovat pyproject.toml

```toml
[tool.mypy]
# Ignorovat unreachable statements po raise
disable_error_code = ["unreachable"]

# Nebo specificky pro security moduly
[[tool.mypy.overrides]]
module = "*.security"
disable_error_code = ["unreachable"]
```

## 🚀 Automatizační Script

Vytvořit `scripts/fix_issues.sh`:

```bash
#!/bin/bash
set -e

echo "🔧 Automatické opravy..."

# 1. Instalace type stubs
pip install types-requests types-PyYAML

# 2. Auto-fix s Ruff
ruff check src/ --fix --unsafe-fixes

# 3. Formatting
black src/
isort --profile black src/

# 4. Type check
mypy src/ --ignore-missing-imports --no-strict-optional

echo "✅ Automatické opravy dokončeny"
echo "⚠️  Zkontrolujte manuální opravy v CI_PIPELINE_RESULTS.md"
```

## 📈 Tracking Progress

### Checklist pro opravu

- [x] Spustit všechny nástroje lokálně
- [x] Analyzovat výsledky
- [ ] Nainstalovat types-requests
- [ ] Opravit try-except-pass bloky (23 míst)
- [ ] Přesunout importy na začátek (159 míst - zvážit záměrnost)
- [ ] Nahradit open() za Path.open() (15 míst)
- [ ] Odstranit print statements (38 míst)
- [ ] Opravit type hints (28 míst)
- [ ] Přidat konstanty pro magic values (78 míst v testech)
- [ ] Aktualizovat konfigurace (ruff.toml, pyproject.toml)
- [ ] Spustit testy pro všechny MCP servery
- [ ] Spustit pip-audit pro všechny MCP servery
- [ ] Commitnout změny

## 🎯 Další Kroky

1. **Okamžitě:**
   - Instalovat types-requests: `pip install types-requests`
   - Opravit critical security issues (try-except-pass s logging)

2. **Tento týden:**
   - Refaktorovat importy (zvážit optional dependencies)
   - Použít Path API konzistentně
   - Opravit type hints

3. **Průběžně:**
   - Nahradit print() logging
   - Vyčistit magic values v testech
   - Odstranit unused type: ignore komentáře

4. **CI/CD:**
   - Aktualizovat GitHub Actions s novými dependency
   - Přidat types-requests do requirements-dev.txt
   - Nastavit ruff/mypy pro ignorování expected warnings

## 💡 Poznámky

### Co je OK ignorovat:

1. **B101 (assert_used) v testech** - Normální použití pytest
2. **PLR2004 (magic values) v testech** - Test data jsou OK
3. **Unreachable statements** po `raise SecurityError` - MyPy false positive
4. **Some PLC0415** - Pokud jsou importy záměrně optional (keyring)

### Co opravit prioritně:

1. **Try-except-pass** - Špatná praxe, skrývá problémy
2. **Missing type stubs** - Zlepší type checking
3. **Print statements** - Použít logging framework
4. **Path API** - Modernější a bezpečnější

---

**Celkové hodnocení:** 🟡 **Dobré s několika oblastmi ke zlepšení**

Projekt má solidní základ:
- ✅ Testy procházejí
- ✅ Žádné security vulnerabilities v dependencies  
- ✅ Code formatting je konzistentní
- ⚠️ Potřeba cleanup linting issues
- ⚠️ Zlepšit type annotations
- ⚠️ Better error handling v některých místech

**Doporučení:** Opravit Priority 1 a 2 před merge do main branch.
