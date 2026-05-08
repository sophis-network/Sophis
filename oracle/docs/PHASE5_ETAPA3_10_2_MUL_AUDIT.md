# Phase 5 — Etapa 3.10.2 Mul Stack Audit

**Data:** 2026-05-07
**Sub-fase:** 3.10.2 (auditoria MulPipelineChip + carry_fold/second_fold/etc.)
**Predecessor:** `oracle/docs/PHASE5_ETAPA3_10_CHUNKED_DESIGN.md` (3.10.D)

---

## TL;DR

Auditoria revela que o Mul stack tem gaps de soundness análogos aos do Add/Sub stack (BB-wrap collision class `k≥1`). Para fechar Etapa 3.10 corretamente, **a sub-fase original 3.10.2 expande de "1 sessão" para "10 sessões"** — refactoring chunked dos seguintes chips:

- `FirstFoldChip` → `FirstFoldChunkedChip` (PROBABLE GAP)
- `SecondFoldOnePassChip` → `SecondFoldChunkedChip` (CONFIRMED GAP)
- `LimbAssemblyChip` → `LimbAssemblyChunkedChip` (PROBABLE GAP)
- `CondPSubChip` (já planejado em 3.10.D) → `CondPSubChunkedChip` (CONFIRMED GAP)
- `ModPChipFull` (compositor) → `ModPChunkedChip` (inherits)
- `MulPipelineChip` (compositor) → `MulPipelineChunkedChip` (inherits)
- `MulCanonicalFullChip` (compositor) → `MulCanonicalFullChunkedChip` (inherits)

Sub-fases adicionais necessárias: 3.10.2.0 → 3.10.2.6.

**Chips já sound (sem refactor):**
- `MulChip` (sub-fase 3.2): output positions bounded `< 2^25 ≪ p` ✅
- `CarryFoldChip` (sub-fase 3.8): LHS/RHS bounded `< 2^26 ≪ p` ✅

---

## 1. Metodologia da auditoria

Para cada chip emitido na pipeline, examinou-se:

1. **Bound LHS_int** das equações lineares emitidas (max valor inteiro do lado esquerdo)
2. **Bound RHS_int** simétrico
3. Se `max(LHS_int, RHS_int) < p`: chip sound (k=0 única solução)
4. Se `max(LHS_int, RHS_int) ≥ p`: gap potencial; verificar se atribuição alternativa `(witness')` válida existe satisfazendo equação BB-level mas correspondendo a integer LHS' ≠ RHS_honest

---

## 2. Chip por chip

### 2.1 MulChip — SOUND ✅

**Constraints emitidas:**

a) **Decomposição limb→pieces** (18 instâncias):
```
a_limb = a_p0 + 2^10·a_p1 + 2^20·a_p2
```
- Pieces range-checked 10-bit (sub-fase 3.2 via `RangeNChip<10>`)
- LHS = a_limb (forçado pela equação)
- RHS_max = 3 · (2^10 − 1) · 2^20 ≈ 2^30 − 1
- **Sound:** RHS < 2^30 < p; força a_limb à mesma faixa.

b) **Output positions** (53 instâncias):
```
out_pos[k] = Σ a_p[i] · b_p[j]
```
- Pieces range-checked < 2^10
- RHS_max = 27 · (2^10 − 1)^2 ≈ 27 · 2^20 ≈ 2^25
- LHS = out_pos[k] forçado
- **Sound:** ambos < 2^25 < p.

**Conclusão:** MulChip é sound (closure 3.2 funcionou).

### 2.2 CarryFoldChip — SOUND ✅

**Constraint emitida (53 instâncias):**
```
can[k] + 2^10 · carry_out = pos[k] + carry_in
```
- can range-checked 10-bit (3.8): can < 2^10
- carry range-checked 16-bit (3.8): carry < 2^16

Bounds:
- LHS_max = (2^10 − 1) + 2^10 · (2^16 − 1) = 2^26 − 2^10
- RHS_max = pos_max + carry_max = 2^25 + 2^16 ≈ 2^25.5
- max(LHS, RHS) ≈ 2^26 < p ≈ 2^31

**Sound:** k=0 única solução.

### 2.3 SecondFoldOnePassChip — GAP CONFIRMED ❌

**Constraint #3 (prod_9 split):**
```
prod_9_low + 2^30 · prod_9_high = q_lo + 2^7 · q_mid + 2^14 · q_hi
```

Onde:
- prod_9_low range-checked 30-bit: < 2^30
- prod_9_high range-checked 12-bit: < 2^12
- q_x = a_x · M, com a_x range-checked 7-bit, M = 19 · 2^15 = 622592

Bounds:
- LHS_max = (2^30 − 1) + 2^30 · (2^12 − 1) = 2^42 − 2^30 ≈ **2^42**
- RHS_max = (2^26 + 2^7 · 2^26 + 2^14 · 2^26) ≈ 2^40

**Excede p ≈ 2^31.** Adversarial assignment alternativa explorável:

Para honest_int = 2^40 − 1, target = honest_int + p ≈ 1.10 × 10^12:
- alt_high = target / 2^30 = 1025 (< 2^12 ✅)
- alt_low = target − 2^30 · 1025 = 939_524_096 (< 2^30 ✅)

Para honest_int = 0, target = p:
- alt_high = 1, alt_low = 939_524_097 (ambos válidos).

**Forge bem-sucedido.** SecondFoldOnePassChip permite prover adversarial substituir prod_9_low/prod_9_high por valores alternativos válidos sob range checks mas representando `prod_9_int + p`. Esse erro propaga para constraint #6 (carry chain), distorcendo `acc_out[0..2]`, e portanto o resultado final de mod-p reduction.

**Closure necessária:** `SecondFoldChunkedChip` reescrito para ter LHS/RHS de toda equação linear < p. Estimativa: 2 sessões. Ver §3.

### 2.4 FirstFoldChip — PROBABLE GAP ⚠️

Não auditado em detalhe nesta sessão, mas estrutura similar (mod_p reduction via `19` multiplier): mesmo padrão de gap esperado em constraints de produto + split.

**Closure necessária:** `FirstFoldChunkedChip`. Estimativa: 2 sessões.

### 2.5 LimbAssemblyChip — PROBABLE GAP ⚠️

Re-empacota 53 base-2^10 positions em 9 limbs de 30 bits. Constraints provavelmente envolvem somas grandes (53 positions × magnitude 2^25) cuja BB representation pode ter aliasing.

**Closure necessária:** `LimbAssemblyChunkedChip`. Estimativa: 1 sessão.

### 2.6 CondPSubChip — GAP (já conhecido) ❌

Mesma classe de gap k=1 que motivou Etapa 3.10.D. Já planejado para refactor chunked.

**Closure necessária:** `CondPSubChunkedChip` separado (ou absorvido por `MulCanonicalFullChunkedChip`). Estimativa: 1 sessão (versão standalone) ou inline no compositor.

### 2.7 ModPChipFull (composite) — INHERITS GAPS

Compõe FirstFold + 2× SecondFold + 2× CondPSub. Todos componentes têm gaps.

**Closure necessária:** `ModPChunkedChip` que compõe versões chunked. Estimativa: 1 sessão.

### 2.8 MulPipelineChip (composite) — INHERITS GAPS

Compõe Mul + CarryFold + ModPChipFull (essentially). Mul/CarryFold sound; ModP gap.

**Closure necessária:** `MulPipelineChunkedChip`. Estimativa: 1 sessão.

### 2.9 MulCanonicalFullChip (composite) — INHERITS GAPS

Top-level: MulPipeline + ModPChipFull. Inherits gaps de ambos.

**Closure necessária:** `MulCanonicalFullChunkedChip`. Estimativa: 1 sessão.

---

## 3. Sub-fases adicionais necessárias

Etapa 3.10.2 expande para:

| Sub-fase | Conteúdo | Estimativa |
|---|---|---|
| 3.10.2 | Audit doc (este documento) | ✅ done |
| 3.10.2.0 | `FirstFoldChunkedChip` + tests | 2 sessões |
| 3.10.2.1 | `SecondFoldChunkedChip` + tests (mais complexo: split via chunks 16+14) | 2 sessões |
| 3.10.2.2 | `LimbAssemblyChunkedChip` + tests | 1 sessão |
| 3.10.2.3 | `CondPSubChunkedChip` standalone (ou absorber no 3.10.2.5) | 1 sessão |
| 3.10.2.4 | `ModPChunkedChip` (compositor) + tests | 1 sessão |
| 3.10.2.5 | `MulPipelineChunkedChip` (compositor) + tests | 1 sessão |
| 3.10.2.6 | `MulCanonicalFullChunkedChip` (compositor) + tests | 1 sessão |

**Total Mul stack:** 10 sessões.

**Estimativa revisada Etapa 3.10 completa:**
- 3.10.D ✅ (1 sessão done)
- 3.10.0 ✅ (2 sessões done)
- 3.10.1 ✅ (2 sessões done)
- 3.10.2.x (10 sessões) ⏳
- 3.10.3 rebind topo (PowAir → verify_air) — agora também precisa rebind dos novos chunked Mul chips: 3 sessões
- 3.10.4 STARK regression + delete trust-shims: 2 sessões
- 3.10.5 commit master + memory + CLAUDE.md: 1 sessão

**Total:** ~21 sessões. Etapa 3.10 evolui de "design-only" (3.10.D) para "20+ session implementation".

---

## 4. Princípio de design para Mul stack chunked

Mesmo princípio dos Add/Sub:

1. **Inputs/outputs em chunks 16+14 bit per limb** (compatível com AddChunked / SubChunked).
2. **Toda constraint linear emitida bound `< 2^26 ≪ p`** (para deixar margem em produtos chunk × chunk).
3. **Range checks inline via `Range16Chip` / `RangeNChip<14>`** em cada cell witness.
4. **Carry chains chunked** (intra-limb + inter-limb).
5. **Multiplicação de chunks**: chunk × chunk de 16-bit dá ≤ 2^32, **excede p**. Logo precisa decompor produto também: e.g., 16-bit × 16-bit = 32-bit = (lo 16) + 2^16 · (hi 16). Cada metade < 2^16, sound.
6. **Pieces 10-bit existentes** (do MulChip 3.2) permanecem; a redução stack (FirstFold/SecondFold/LimbAssembly) é o que precisa refactor.

### 4.1 Detalhe específico SecondFoldChunked

Substitui constraint problemática:
```
prod_9_low + 2^30 · prod_9_high = q_lo + 2^7 · q_mid + 2^14 · q_hi   [LHS, RHS up to 2^42]
```

Por chunked:
```
# decompor q_lo + 2^7·q_mid + 2^14·q_hi em 4 chunks 16-bit:
# total ≤ 2^40 → 3 chunks 16-bit + 1 chunk small

# constraint chunked (cada chunk < 2^16 < p):
chunk[0] = (q_lo + 2^7·q_mid + 2^14·q_hi) & 0xFFFF                    # < 2^16
chunk[1] = ((q_lo + 2^7·q_mid + 2^14·q_hi) >> 16) & 0xFFFF            # < 2^16
chunk[2] = ((...) >> 32) & 0xFFFF                                     # < 2^16
chunk[3] = ((...) >> 48) & 0xFF                                       # < 2^8

# emit 4 small chunked equations cada uma com lhs/rhs < 2^17 < p
# recompõe prod_9_low, prod_9_high a partir dos chunks com pesos 2^k
```

Mesmo padrão de bound analysis dos Add/Sub.

---

## 5. Decisão final

Audit confirmou gaps reais no Mul stack equivalentes ao Add/Sub stack. Sub-fases 3.10.2.0 → 3.10.2.6 adicionadas ao plano.

**Compromisso pre-mainnet:** todos chips do Mul stack refactorados chunked antes do gênese, alinhado com decisão "perfeitos ou não vamos".

**Estimativa total Etapa 3.10:** ~21 sessões. Bem além das 10-15 originalmente planejadas.

---

**Fim do documento.**
