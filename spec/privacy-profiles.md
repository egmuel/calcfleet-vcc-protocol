# VCC Privacy Profiles — piano (§31.6)

Status: **Piano (v0.3+)** · Data: 2026-07-12 · Isola VCC-B, FASE 1.
Fonti: [ADR-007](../adr/ADR-007-privacy-model.md), [spec §2/§8](./spec-v0.2.md).

> Questo documento **pianifica** i cinque privacy profiles del master (§31.6) e le privacy features di /verify (§30). Non modifica il costruito. Termini normativi (MUST/SHOULD/MAY) in inglese.

> **Onestà (v0.2).** Oggi non esiste alcun selective disclosure, redaction o
> encryption: un VCC è un **bearer document** che porta **in chiaro tutti gli
> input numerici dichiarati**. Anche senza nome o email, quei numeri possono
> essere sensibili nel contesto (importi di prestito, reddito, età, valori
> medici). Un VCC va quindi trattato come potenzialmente sensibile e condiviso
> solo deliberatamente. I profili sotto sono **piano**, non costruito.

---

## 1. Stato reale (onestà dell'audit)

Oggi VCC v0.2 implementa **un solo profilo, implicito e non nominato: "full"**, con privacy **by construction** (audit §31.6). Non esiste un sistema di profili selezionabili; il campo `statement.privacyProfile` **non esiste** nello schema (`src/lib/vcc/schemas.ts`, Zod strict). Il "full" attuale è forte ma è un'altra cosa dai cinque profili chiesti dal master.

Il "full" attuale poggia su tre lock fail-closed ([ADR-007](../adr/ADR-007-privacy-model.md)):

1. **Solo formule number-shaped** — ogni input è `number | boolean | closed enum`; un solo campo free-text squalifica la formula dalla certificazione.
2. **Schema allowlist strict** — la PII non può viaggiare in campi extra perché i campi extra non esistono (Zod strict).
3. **Pattern guard** (`src/lib/vcc/privacy.ts`, ~274 righe) — walk dello statement *completo* prima della firma; nomi-chiave vietati e valori PII-shaped ⇒ `certificateReason: "privacy-rejected"`, calcolo mai bloccato.

Ne segue una proprietà chiave che i profili futuri **MUST** preservare: un certificato rivela il calcolo (formula, versione, input, output, timestamp, issuer) e **nulla su chi ha chiesto** oltre a un `requestId` opaco.

### 1.1 ADR-007 e il profilo `redacted` — divergenza da citare

ADR-007 **ha rifiutato la redaction**, ma di una forma **diversa** da quella del master. L'ADR respinge la *redazione silenziosa pre-firma* ("silent mutation of what the user sent is worse than refusing... 'sanitized' PII detection is unwinnable. Fail-closed is honest"). Il master §31.6 intende invece un profilo `redacted` **dichiarato nello statement**: il verifier *sa* cosa è omesso e la firma copre l'omissione dichiarata. Questa seconda forma **non è mai stata valutata** da ADR-007. Conseguenza operativa: `redacted` non è coperto dall'ADR attuale e richiede una **decisione esplicita in v0.3** (nuovo ADR), non è un semplice sblocco. Lo stesso vale per l'`hash-only` salted respinto in ADR-007: là era respinto nel contesto *dedup/abuse* per ragioni GDPR, **non** come profilo di disclosure.

---

## 2. I cinque profili (§31.6) — design proposto

Tutti i profili condividono un principio: **il profilo è dichiarato dentro lo statement e coperto dalla firma**. Introdurre `statement.privacyProfile` è un **cambio di formato** ⇒ spec bump (v0.3), gestito dalla change-process di [governance](./governance.md). Un verifier v0.2 che riceve un profilo sconosciuto **MUST** fallire in modo esplicito (payloadType/specVersion bump), mai degradare silenziosamente.

Campo proposto:

```json
"privacy": {
  "profile": "full | redacted | hash-only | encrypted-to-recipient | selective-disclosure",
  "disclosed": ["calculation.inputs.principal", "…"],
  "commitments": { "<path>": { "algorithm": "sha-256", "value": "<hex>", "salt": "<base64>" } },
  "recipient": { "keyId": "…", "algorithm": "…" }
}
```

`disclosed`/`commitments`/`recipient` sono presenti **solo** per i profili che li usano (Zod discriminated union sul valore di `profile`).

### 2.1 `full` — FATTO (by construction), da nominare

Il profilo attuale. Piano: **renderlo esplicito** (`privacy.profile: "full"`) senza cambiare comportamento. Ogni input/output è disclosed in chiaro. Nessun `commitments`, nessun `recipient`. È l'unico profilo che v0.2 sa già emettere; la migrazione è "aggiungere il nome a ciò che già facciamo".

### 2.2 `redacted` — MANCANTE, richiede nuovo ADR

Omissione **dichiarata**: alcuni leaf numerici sono sostituiti da un marker `{ "redacted": true }` e il loro path compare in un campo `redacted[]`; il resto è in chiaro. La firma copre lo statement redatto (nessuna mutazione silenziosa: il verifier vede *cosa* manca, non *cosa c'era*). Vincolo di integrità: se i valori omessi entrano in un output certificato, l'output resta in chiaro ma **non è più L2-riproducibile** da un terzo che non abbia gli input omessi ⇒ lo stato L2 corretto è `not-reproducible` con motivo `inputs-redacted`, mai `mismatch`. **Prerequisito: ADR v0.3** che superi esplicitamente la divergenza §1.1.

### 2.3 `hash-only` — MANCANTE

Impegno sull'input **senza rivelarlo**: al posto del valore, un commitment `sha-256(salt || canonical-value)` con `salt` per-field (contro brute-force su domini piccoli, es. età). Prova "conoscevo questo input al momento della firma" senza pubblicarlo. L2 diventa un *check di consistenza* (ricalcolo del commitment dal valore fornito fuori banda), non una riproduzione completa. GDPR: un commitment saltato è comunque dato personale se il dominio è enumerabile ⇒ documentare i limiti, non venderlo come anonimizzazione (coerente con la nota GDPR di ADR-007).

### 2.4 `encrypted-to-recipient` — MANCANTE

Gli input (o un loro subset) sono cifrati verso la chiave pubblica di un destinatario nominato (`recipient.keyId`), es. HPKE / X25519 + AEAD. Chiunque verifica **autenticità e integrità** (firma sul ciphertext dichiarato); solo il destinatario decifra e può fare L2. Estende l'asse crypto senza toccare Ed25519 della firma DSSE (firma sul ciphertext, non sul plaintext). Extension point: nessuna nuova primitiva di firma (coerente con §31.3 "non reinventare la firma").

### 2.5 `selective-disclosure` — MANCANTE

Il più complesso. Merkle tree sui leaf dello statement (o BBS+ su un profilo dedicato): l'issuer firma la root; l'holder rivela un subset con proof di inclusione, tenendo il resto nascosto ma vincolato. Prerequisito duro: i **numeric profiles** e il **formula package** devono essere normativi *prima* (altrimenti non c'è una serializzazione canonica stabile dei leaf su cui costruire il Merkle tree). Anti-priorità dichiarata: la spec §9 elenca selective-disclosure crittografica come **dopo** il blocco 61-90; qui è pianificata, non schedulata.

### 2.6 Riepilogo profili

| Profilo | Stato | Rivela | Verifica L1 (chiunque) | Verifica L2 | Prerequisito |
|---|---|---|---|---|---|
| `full` | FATTO (implicito) | tutto in chiaro | sì | sì | nominarlo + spec bump |
| `redacted` | MANCANTE | in chiaro − omessi dichiarati | sì | `not-reproducible` sui rami omessi | **ADR v0.3** (§1.1) |
| `hash-only` | MANCANTE | commitment saltati | sì | consistency check fuori banda | design salt + GDPR note |
| `encrypted-to-recipient` | MANCANTE | ciphertext | sì (sul ciphertext) | solo il recipient | schema HPKE/X25519 |
| `selective-disclosure` | MANCANTE | subset + inclusion proof | sì | subset | numeric+formula **normativi** |

---

## 3. Privacy /verify (§30) — piano

L'audit §30 misura queste feature contro il costruito. Piano incrementale:

| Feature (§30) | Oggi | Piano |
|---|---|---|
| **Local verification (in-browser)** | Il paste verifier POSTa al server (`VccPasteVerifier.tsx`); local solo via CLI offline | **WebCrypto Ed25519** (già notato come possibile in ADR-001) su /verify: L1 interamente nel browser, zero upload dell'envelope. È anche il gap privacy più visibile; abilitato dallo stesso lavoro che pubblica il TS SDK ([interoperability report §SDK](./interoperability-report.md)) |
| **Upload (file)** | Solo textarea paste | Aggiungere `<input type=file>` accanto alla textarea; la verifica resta locale |
| **Explicit sharing** | FATTO come postura (`certify=1`, "nothing you paste is stored") | Mantenere; nessuna emissione silenziosa **MUST** restare invariante |
| **Expiration** | MANCANTE (nessun TTL su certificati/store) | Campo opzionale `statement.expiresAt` (coperto dalla firma) + TTL opzionale sullo store; un verifier segnala `expired` come **stato separato**, mai come `authentic:false` (la firma resta matematicamente valida) |
| **Deletion** | MANCANTE (store append-only, "never delete" ADR-006) | Meccanismo per cui l'holder chiede la rimozione dal *store* (non tocca copie condivise, immutabili by design); risolve la tensione GDPR di ADR-006 a livello di **policy**, non di crittografia |
| **Private / redacted / hash-only receipt** | MANCANTE | Coperte dai profili §2 sopra |

Invarianti trasversali che ogni feature **MUST** preservare: (a) nessun "verified" singolo; (b) i quattro assi (`authentic/intact/reproducible/trusted`) restano ortogonali; `expired`/`redacted` sono **stati aggiuntivi**, non collassano su questi quattro; (c) la firma è timeless — expiration e deletion sono metadati/operazioni di store, non invalidano la matematica.

---

## 4. Sequenza e prerequisiti

1. **Spec bump v0.3** con `statement.privacy` opzionale (default assente ≡ `full`) — governato da [governance](./governance.md).
2. **`full` esplicito** — costo minimo, sblocca la nomenclatura.
3. **Local in-browser verification + upload** — indipendente dai profili, alto valore percepito; agganciato al TS SDK.
4. **`redacted`** solo dopo il **nuovo ADR** che supera la divergenza §1.1.
5. **`hash-only`**, **`encrypted-to-recipient`** — schema-level, dopo i numeric profiles normativi.
6. **`selective-disclosure`** — ultimo: richiede numeric profiles **e** formula package normativi (serializzazione canonica dei leaf).
7. **Expiration / deletion** — trasversali, agganciati allo store e alla privacy policy del sito (§32).
