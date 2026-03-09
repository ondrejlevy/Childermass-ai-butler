# Branch Protection Setup Guide

**Důvod:** Vyřešení 1 HIGH severity alertu (BranchProtectionID)  
**Časová náročnost:** 5-10 minut  
**Benefit:** Ochrana před accidental/malicious změnami v main větvi

## Kroky pro nastavení

### 1. Otevřete Repository Settings

1. Jděte na: https://github.com/ondrejlevy/Childermass-ai-butler
2. Zvolte **Settings** (tab nahoře)
3. V levém menu zvolte **Branches**

### 2. Přidejte Branch Protection Rule pro `main`

Klikněte na **"Add rule"** nebo **"Add branch protection rule"**

#### Branch name pattern:
```
main
```

#### Doporučená nastavení:

**☑️ Require a pull request before merging**
- ☑️ Require approvals: **1** (minimálně 1 reviewer)
- ☑️ Dismiss stale pull request approvals when new commits are pushed
- ☑️ Require review from Code Owners (pokud máte CODEOWNERS file)

**☑️ Require status checks to pass before merging**
- ☑️ Require branches to be up to date before merging
- Vyberte tyto status checks (po prvním CI run budou viditelné):
  - `lint`
  - `type-check`
  - `security`
  - `test`
  - `ci-success`

**☑️ Require conversation resolution before merging**
- Zajistí, že všechny code review komentáře jsou vyřešeny

**☑️ Require signed commits** (optional, ale doporučeno)
- Vyžaduje GPG signing

**☑️ Include administrators**
- Pravidla platí i pro adminy (důležité pro security!)

**☑️ Restrict who can push to matching branches** (optional)
- Pokud máte team, můžete omezit kdo může pushovat

**☑️ Allow force pushes**
- ❌ **VYPNOUT** - nebezpečné pro main větev

**☑️ Allow deletions**
- ❌ **VYPNOUT** - main větev by neměla být smazána

### 3. Uložte změny

Klikněte na **"Create"** nebo **"Save changes"** dole

### 4. Opakujte pro `develop` větev (pokud používáte)

Stejná pravidla jako pro `main`, případně mírně uvolněná (např. bez povinného review pro hotfixy).

---

## Ověření

Po nastavení:

1. Zkuste pushovat přímo do `main`:
   ```bash
   git checkout main
   git commit --allow-empty -m "test"
   git push
   ```
   
   ❌ Mělo by selhat s hláškou o branch protection

2. Správný workflow:
   ```bash
   # Vytvořit feature branch
   git checkout -b feature/my-feature
   
   # Commit změny
   git add .
   git commit -m "Add feature"
   
   # Push a create PR
   git push -u origin feature/my-feature
   ```
   
   Na GitHubu vytvořte Pull Request → počkejte na CI checks → získejte review → merge

---

## Dodatečná doporučení

### CODEOWNERS file

Vytvořte `.github/CODEOWNERS`:
```
# Global owners
* @ondrejlevy

# Specific paths
/src/childermass/  @ondrejlevy
/.github/workflows/  @ondrejlevy
```

### Auto-merge pro Dependabot

Pokud používáte Dependabot, můžete povolit auto-merge pro minor/patch updates:

```yaml
# .github/workflows/dependabot-auto-merge.yml
name: Dependabot Auto-Merge
on: pull_request

permissions:
  contents: write
  pull-requests: write

jobs:
  dependabot:
    runs-on: ubuntu-latest
    if: github.actor == 'dependabot[bot]'
    steps:
      - name: Enable auto-merge for Dependabot PRs
        run: gh pr merge --auto --squash "$PR_URL"
        env:
          PR_URL: ${{github.event.pull_request.html_url}}
          GITHUB_TOKEN: ${{secrets.GITHUB_TOKEN}}
```

---

## Řešení problémů

### "Cannot push to protected branch"
✅ Správně! Vytvořte PR místo direct push.

### "Status checks never complete"
- Zkontrolujte CI workflow v Actions tabu
- Možná potřebujete fixnout failing tests

### "Cannot merge - missing required reviews"
- Požádejte někoho o code review
- Nebo přidejte jiného collaboratora do repo

---

## Bezpečnostní benefit

Po nastavení branch protection:
- ✅ Žádné accidental force pushes do main
- ✅ Všechny změny prochází code review
- ✅ CI checks musí projít před mergem
- ✅ Historie je chráněna proti přepisování
- ✅ Vyřešen 1 HIGH severity alert

**Další krok:** Po nastavení počkejte ~24h na další GitHub CodeQL scan, alert by měl zmizet.
