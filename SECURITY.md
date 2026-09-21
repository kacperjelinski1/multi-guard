# Security Policy — Multi-Guard

## Supported Versions

| Version | Supported |
|---|---|
| 1.0.x | ✅ Active support |
| < 1.0 | ❌ End of life |

---

## Reporting a Vulnerability

Bezpieczeństwo stacji roboczych naszych klientów jest dla nas najwyższym priorytetem. Jeśli odkryjesz lukę w zabezpieczeniach aplikacji **Multi-Guard** lub systemu licencjonowania **KeyGate**, prosimy o jej odpowiedzialne zgłoszenie.

**PROSIMY NIE ZGŁASZAĆ luk bezpieczeństwa w publicznych issues na GitHub.**

### Jak zgłosić podatność

1. **Kontakt bezpośredni:**
   - **E-mail:** `kontakt@multi-servis.pl` (z tematem `[SECURITY] Zgłoszenie podatności Multi-Guard`)
   - **Telefon:** `505 012 914`
   - **Formularz kontaktowy:** [https://multi-servis.pl](https://multi-servis.pl)

2. **Zgłoszenie powinno zawierać:**
   - Dokładny opis podatności i wektora ataku
   - Kroki do zreplikowania problemu (Proof of Concept)
   - Potencjalny wpływ na stację roboczą lub środowisko sieciowe
   - Sugerowane kroki naprawcze (jeśli są znane)

### Czas reakcji zespołu Multi-Servis

- **Potwierdzenie przyjęcia zgłoszenia:** do 24–48 godzin roboczych.
- **Wstępna analiza techniczna:** do 5 dni roboczych.
- **Wydanie poprawki / aktualizacji:** do 14 dni dla krytycznych podatności.

---

## Zakres zgłoszeń bezpieczeństwa

### Priorytetowe podatności:
- Możliwość ominięcia kryptograficznej weryfikacji tokena licencyjnego Ed25519
- Obejście skarbca kwarantanny (AES-256-CBC)
- Eskalacja uprawnień za pośrednictwem procesów Multi-Guard
- Podatności typu Remote Code Execution (RCE) w silniku parsowania PE lub skanera
- Niekontrolowane uszkodzenie pamięci w silniku PE Repair Engine

### Poza zakresem:
- Ataki wymagające uprzedniego fizycznego dostępu root/SYSTEM do stacji roboczej
- Inżynieria społeczna
- DoS wywołany celowospreparowanymi plikami o gigantycznym rozmiarze

---

*Multi-Servis Security Response Team — https://multi-servis.pl*
