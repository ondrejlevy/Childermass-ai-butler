---
name: tracking-workflow
description: |
  Instrukce pro sledování zásilek z e-shopů a od dopravců.
  Popisuje workflow detekce zásilkových emailů, registrace zásilek,
  kontroly stavu a odpovídání na dotazy uživatele.
  Používá tracking_mcp server ve spolupráci s gmail_mcp.
---

# Sledování zásilek — Workflow

## Přehled

Tato dovednost popisuje jak detekovat, registrovat a sledovat zásilky
z českých e-shopů (Alza, Rohlik, Mall, CZC, Notino, Datart) a od
dopravců (Zásilkovna, Balíkovna, PPL, DPD, GLS).

## 1. Detekce zásilkových emailů

Při ranním briefingu nebo na dotaz uživatele prohledej inbox:

```
gmail_search("(from:zasilkovna OR from:ppl OR from:dpd OR from:gls OR from:balikovna OR from:cpost OR from:alza OR from:rohlik OR from:mall.cz OR from:czc.cz OR from:notino OR from:datart OR subject:zásilka OR subject:doručení OR subject:tracking OR subject:sledování OR subject:\"objednávka odeslána\" OR subject:\"shipment\" OR subject:\"balík\") newer_than:7d is:unread")
```

## 2. Registrace nové zásilky

Pro každý nalezený zásilkový email:

1. Načti celý email: `gmail_read_email(message_id)`
2. Parsuj tracking info: `tracking_parse_email(email_body, email_subject, email_from, email_body_html)`
3. Zkontroluj duplikáty: `tracking_list()` — ověř, že tracking_url ještě není registrovaný
4. Zaregistruj zásilku: `tracking_register(carrier, tracking_url, ...)` s daty z parseru
5. Označ email jako přečtený: `gmail_mark_as_read(message_id)`

**Důležité:**
- Vždy předávej `email_body_html` pokud je k dispozici — obsahuje přesné tracking URL
- Pokud `tracking_parse_email` vrátí `confidence < 0.3`, informuj uživatele a požádej o potvrzení
- Pokud `tracking_url` je `null`, informuj uživatele — zásilku nelze automaticky sledovat

## 3. Kontrola stavu zásilek

### Při ranním briefingu
Zavolej `tracking_check_all()` pro hromadnou kontrolu všech aktivních zásilek.
Výsledky zahrň do briefingu v sekci **Zásilky**:

- Zásilky se změnou stavu (zvýrazni)
- Zásilky blížící se doručení (dnes/zítra)
- Zásilky připravené k vyzvednutí
- Celkový počet aktivních zásilek

### Na dotaz uživatele
- "Kde je moje zásilka z Alzy?" → `tracking_list(order_source="alza.cz")` → `tracking_status(shipment_id)`
- "Přehled zásilek" → `tracking_list()`
- "Stav zásilky XYZ" → `tracking_get(shipment_id)` nebo `tracking_status(shipment_id)` pro live update
- "Kdy dorazí balík?" → `tracking_status(shipment_id)` → vrátit `expected_delivery`
- "Kam bude doručena zásilka?" → `tracking_get(shipment_id)` → vrátit `delivery_location`

## 4. Odpovídání na dotazy

### Stav konkrétní zásilky
Odpověz česky s detaily:
- Dopravce a číslo zásilky
- Aktuální stav (přeložený do češtiny)
- Kde se zásilka nachází
- Předpokládaný čas doručení
- Místo doručení / výdejní místo

### Přehled všech zásilek
Seřaď podle priority:
1. Zásilky připravené k vyzvednutí (pickup_ready)
2. Zásilky v doručování (out_for_delivery)
3. Zásilky na cestě (in_transit)
4. Nově registrované (registered)

### Mapování stavů do češtiny
- `registered` → "Zaregistrována"
- `in_transit` → "Na cestě"
- `out_for_delivery` → "V doručování"
- `delivered` → "Doručena"
- `pickup_ready` → "Připravena k vyzvednutí"
- `returned` → "Vrácena"
- `cancelled` → "Zrušena"
- `unknown` → "Stav neznámý"

## 5. Archivace

Zásilky ve stavu `delivered`, `returned` nebo `cancelled` se automaticky
archivují (is_active=false). Uživatel může manuálně archivovat zásilku
příkazem "Archivuj zásilku XYZ" → `tracking_archive(shipment_id)`.

## 6. Omezení

- Tracking stránky se scrapují — mohou se měnit, parsery mohou přestat fungovat
- Některé stránky vyžadují JavaScript — v tom případě je vrácen raw text
- Rate limiting: max 20 scrapů/min, max 5 batch kontrol/min
- Zásilky nelze sledovat bez tracking URL
