# Phase 5 — Etapa 3.10 Chunked Redesign Design Document

**Status:** DESIGN (não implementado ainda)
**Data:** 2026-05-07
**Autor:** sessão Etapa 3.10 design
**Predecessor:** Etapa 3.7 audit (`project_phase5_etapa3_7_audit.md`)
**Pré-requisito de:** sub-fases 3.10.0 → 3.10.5 implementação

---

## 0. Sumário executivo (TL;DR)

A audit da Etapa 3.7 documentou gaps residuais em quatro chips do stack `field25519`:
`AddChip`, `SubChip`, `ReduceChip`, `CondPSubChip`. O memo escopou closure como
"bit decomposition dos output cells (~270 cells/chip × 4 chips ≈ 40k cells totais)".

**Esse escopo é insuficiente.** Bit decomposition simples nos output cells fecha apenas
a sub-classe trivial de ataques (`out > 2^30` aceito) mas deixa aberta uma classe de
colisão estrutural derivada do **wrap-around BabyBear**. Especificamente: como BabyBear
é o campo nativo (`p ≈ 2^31 − 2^27 + 1`) e os chips emitem constraints lineares em BB
cujos lados podem exceder `p`, um prover adversarial pode produzir um traço alternativo
satisfazendo a equação BB-level mas representando outro inteiro mod `p`.

Esta classe de ataque é nomeada `BB-wrap collision class k≥1`. Range checks 30-bit em
output cells **não fecham k=1** — o adversário pode ainda construir traço válido onde
o output canônico está deslocado em `p ≈ 2 × 10⁹`.

A closure correta exige refatoração completa do stack para representação **chunked
(16+14 bit por limb)** com carry chains explícitas inter-chunk e inter-limb, igual ao
padrão usado pelo `word64_add` no stack sha512. Sob essa representação, todo lado de
constraint linear é estritamente bounded `< 2^17 ≪ p`, eliminando wrap-around por
construção.

Este documento define o esquema de chunks, prova bound-equivalência por chip, descreve
a API nova (`AddCanonicalChunkedChip`, `SubCanonicalChunkedChip`, deprecation de
`ReduceChip`), audita o `MulPipeline` (já parcialmente chunked), define rebind plan
para chips topo (`MulCanonicalFull`, `PowAir`, `point_add_air`, `scalar_mul_air`,
`decompress_air`, `verify_air`), e prova invariância do wire format.

**Estimativa de implementação:** 10-15 sessões (não 5-7 como o memo da 3.7 sugeriu).

**Wire format invariance:** PV layout estável → upgrade post-mainnet sem hard fork.

---

## 1. Threat model — formalização

### 1.1 BB-wrap collision class

Seja `p = 2^31 − 2^27 + 1` (BabyBear prime). Para qualquer constraint da forma
`L = R` em BB, com `L, R` interpretados como inteiros `≥ 0`, existem múltiplas
soluções inteiras separadas por múltiplos de `p`:

```
L_int = R_int + k · p,   k ∈ ℤ
```

A classe `k = 0` é o caso "honesto" (igualdade integer). Classes `k ≥ 1` são
**colisões aritméticas BB** — válidas em BB, inválidas em ℤ.

**Defesa estrutural (chunked):** se `L_int < L_max` e `R_int < R_max` com
`L_max + R_max < p`, então `|L_int − R_int| < p`, logo `k ∈ {−1, 0, 1}`. Se
adicionalmente `L_int, R_int ≥ 0` com `max(L_max, R_max) < p`, então `k = 0` é
única solução. Isso é o que o esquema chunked garante: `L_max, R_max ≤ 2^17 ≪ p`.

### 1.2 Por que bit decomp falha contra `k=1`

Considere `ReduceChip` com input `in[i] = X` (inteiro, `X < 2^33`):

```
out[i] + 2^30 · carry_out = in[i] + carry_in   (em BB)
```

Solução honesta (`k=0`): `out_int = X mod 2^30`, `carry_out_int = X >> 30`.

Solução adversarial (`k=1`): `out' + 2^30 · carry' = X + carry_in + p`. Resolvendo:
`out' = (X + carry_in + p) mod 2^30`, `carry' = (X + carry_in + p) >> 30`. Para
`X ≤ 2^33`: `carry' ≤ (2^33 + 2^31)/2^30 ≈ 10`, cabe em 4-bit ✅. `out' < 2^30` ✅.

**Range checks 30-bit + 4-bit aceitam `(out', carry')`.** Forge bem-sucedido.

A colisão só falha estruturalmente se as duas sides forem bounded `< p` (ou se
forçarmos integer-equality via decomposição chunked).

### 1.3 Onde o threat se materializa em produção

```
relayer (Dilithium-trusted)
  └─ produz proof Plonky3 stack
      └─ verify_air → embeddings de point_add/scalar_mul/decompress
          └─ field ops (Add, Sub, Reduce, CondPSub)
              └─ se gap exploitable → output canônico errado em até p ≈ 2·10⁹
```

Sob threat model atual (relayer trusted via Dilithium), o blast radius de gaps
field-arith é equivalente a relayer malicioso assinando bundle inválido. Por isso
a Etapa 3.7 documentou gaps como "post-mainnet hardening". Este doc fecha o gap
para o cenário **post-relayer-trust** (se threat model evoluir, ou se proofs forem
agregados de fontes independentes em fase futura).

---

## 2. Representação chunked

### 2.1 Esquema base

Cada limb canônico 30-bit é representado internamente como:

```
limb = lo + 2^16 · hi
   onde  lo ∈ [0, 2^16),  hi ∈ [0, 2^14)
```

Cada chip emite os range checks `Range16Chip::split` em `lo` e `RangeNChip<14>::split`
em `hi` (sub-fase 3.0/3.1 já entregou `RangeNChip<N>` para `N ≤ 30`).

Para limb 8 (top, max `2^15 − 1` no `P_LIMBS[8]`): `hi` cai em `[0, 2^14)` → bound
ainda válido. Estrutura uniforme em todos os 9 limbs.

### 2.2 Bound analysis canônico

| Quantidade | Max value | Bits | Notes |
|---|---|---|---|
| `lo[i]` | `2^16 − 1` | 16 | range-checked Range16 |
| `hi[i]` | `2^14 − 1` | 14 | range-checked Range14 |
| `limb[i]` | `2^30 − 1` | 30 | derivado: `lo + 2^16·hi` |
| `lo_a + lo_b` | `2^17 − 2` | 17 | soma de dois `lo`s |
| `hi_a + hi_b + carry_intra` | `2^15` | 15 | soma de dois `hi`s + carry |
| `borrow_carry` | `1` | 1 | bool |
| `inter_limb_carry` | `1` | 1 | bool (uma vez chunks estão certos) |

**Invariante crítico:** todo lado LHS/RHS de constraint linear no chip novo é
**estritamente** `≤ 2^17 ≪ p ≈ 2^31 − 2^27`. Logo `k = 0` é única solução
inteira do sistema.

### 2.3 Por que 16+14, não 16+16 ou 15+15

- **16+16 = 32 bits**: > 30, inflate desnecessário; range check 16-bit já é o
  primitivo mais barato (`Range16Chip` é chip dedicated do stack sha512).
- **15+15 = 30 bits**: força introdução de `Range15Chip` (não existe). Mais
  manutenção sem ganho.
- **16+14 = 30 bits**: aproveita `Range16Chip` existente + `RangeNChip<14>` via
  generic. Match exato com 30-bit canônico.

---

## 3. API nova — chips a entregar

### 3.1 `AddCanonicalChunkedChip` (substitui Add + Reduce + CondPSub)

**Função:** `c = (a + b) mod p`, todos canônicos 30-bit.

**Layout (uma operação por row):**

| Range | Width | Conteúdo |
|---|---|---|
| `0..18` | 18 | `a_lo[9]`, `a_hi[9]` (input `a` em chunks) |
| `18..36` | 18 | `b_lo[9]`, `b_hi[9]` (input `b` em chunks) |
| `36..54` | 18 | `c_lo[9]`, `c_hi[9]` (output `c` em chunks) |
| `54..72` | 18 | `sum_lo[9]`, `sum_hi[9]` (a+b sem cond_p_sub, lazy) |
| `72..90` | 18 | `inter_carry[9]`, `intra_carry[9]` (carry chains) |
| `90..99` | 9 | `borrow[9]` (cond_p_sub borrow chain) |
| `99..117` | 18 | `t_lo[9]`, `t_hi[9]` (`a + b − p` lazy) |
| `117..135` | 18 | `sub_borrow_intra[9]`, `sub_borrow_inter[9]` |
| `135..279` | 144 | Range16 bit decomp para `a_lo`, `b_lo`, `c_lo`, `sum_lo`, `t_lo` (5 × 9 × 16 = 720) |

Wait — recalculando: 5 × 9 = 45 valores de 16-bit, 45 × 16 = 720 bit cells.

| Range continuação | Width | Conteúdo |
|---|---|---|
| `135..855` | 720 | Range16 bit decomp (5 × 9 × 16) |
| `855..1485` | 630 | RangeN<14> bit decomp para `a_hi`, `b_hi`, `c_hi`, `sum_hi`, `t_hi` (5 × 9 × 14) |

**NUM_COLS estimado:** ~1485 (vs. 144 do `AddCanonical` atual).

**Constraints emitidas:**

1. **Range checks** (135 → 855: Range16 split, 855 → 1485: Range14 split): cada
   chunk validado bit-a-bit. ~9 × 5 × (16 + 14) = 1350 boolean constraints +
   ~9 × 5 × 2 = 90 recomposition constraints.

2. **Reconstrução chunked → 30-bit**: para auditoria/output downstream consumers,
   verificar `a[i]_real = a_lo[i] + 2^16 · a_hi[i]` se algum embedder querer ler
   o limb completo. Opcional — chips downstream também consomem chunked.

3. **Lazy sum chunked com carry chain**:
   ```
   for i in 0..9:
       sum_lo[i] + 2^16 · intra_carry[i] = a_lo[i] + b_lo[i]
       sum_hi[i] + 2^14 · inter_carry[i] = a_hi[i] + b_hi[i] + intra_carry[i] + inter_carry_in
       inter_carry_in = inter_carry[i]
   ```
   LHS, RHS bound `≤ 2 · 2^16 + 2 = 2^17 + 1 ≪ p`. ✅

4. **Cond-p-sub chunked com borrow chain**:
   ```
   for i in 0..9:
       t_lo[i] + p_lo[i] + sub_borrow_intra[i] · 2^16 = sum_lo[i] + sub_borrow_intra_in
       t_hi[i] + p_hi[i] + sub_borrow_inter[i] · 2^14 = sum_hi[i] + intra_borrow_chained
   ```
   Mesmo bound argument.

5. **Select**: `c[i] = (1 − final_borrow) · t[i] + final_borrow · sum[i]`, expressed
   chunk-a-chunk:
   ```
   c_lo[i] = t_lo[i] + final_borrow · (sum_lo[i] − t_lo[i])
   c_hi[i] = t_hi[i] + final_borrow · (sum_hi[i] − t_hi[i])
   ```
   Degree 2.

**Total constraints:** ~1350 (range) + 90 (recomp) + 18 (sum chain) + 18 (sub chain) +
18 (select) ≈ 1494 constraints, max degree 2.

### 3.2 `SubCanonicalChunkedChip`

Simétrico. Computa `c = (a − b) mod p`. Adiciona `p` antes de subtrair para evitar
underflow:

```
sum_lo + 2^16 · intra = a_lo + p_lo + (2^31 padding) − b_lo
```

(Detalhe: na verdade replica o pattern do `SubChip` atual: `c[i] = a[i] + p[i] − b[i]`,
estendendo para chunks.)

NUM_COLS estimado similar (~1485).

### 3.3 `ReduceChip` — DEPRECATED

Funcionalidade absorvida pelo carry chain interno do `AddCanonicalChunkedChip` /
`SubCanonicalChunkedChip`. Marcar `#[deprecated]` no commit master e remover usage
em chips downstream durante rebind (sub-fase 3.10.3).

Manter file `reduce.rs` por 1 release ciclo com `#[deprecated]` atribute, depois
deletar. Tests do `ReduceTestAir` ficam até deletion final.

### 3.4 `MulPipelineChip` — auditoria pendente

Já é parcialmente chunked (pieces 10-bit, ver `chips/field25519/mul.rs`). Sub-fase
3.10.2 audita:

- `MulChip` raw: cada output piece é 10-bit + carry. **Verificar:** ambos lados de
  `piece + 2^10 · carry = sum_of_products` são bounded `< p`?
  - `sum_of_products`: pior caso `9 × (2^30) × (2^30) = 9 · 2^60`. ENORME, **>> p**.
  - **Gap real.** MulChip provavelmente também sofre BB-wrap collision.
  - Decisão: se confirmar gap, expandir Etapa 3.10 com `MulChunkedChip` (12-15 sessões
    adicionais). Se gap for transitivamente fechado por composições posteriores
    (`MulCanonicalFull`), documentar e seguir.

- `carry_fold` / `second_fold`: já têm range checks via Etapa 3 sub-fases 3.0-3.6.
  Confirmar bounds.

Auditoria entrega relatório no commit `phase5 etapa 3.10.2 — MulPipeline audit`.

---

## 4. Rebind plan (chips topo)

Todos chips que embedam `AddChip` / `SubChip` / `ReduceChip` / `CondPSubChip`
(direta ou indiretamente via `AddTrunc` / `AddCanonical` / `SubCanonical`) precisam:

1. Trocar embedding para `AddCanonicalChunkedChip` / `SubCanonicalChunkedChip`.
2. Atualizar `start_col` offsets downstream (NUM_COLS cresce).
3. Atualizar `populate_*_to` functions para popular chunks `_lo`/`_hi` em vez de
   limb single column.
4. `assert_chunks_eq` connection asserts trocam para `assert_chunks_lo_hi_eq`
   (helper novo).

**Lista de chips topo afetados:**

| Chip | Localização | Embeds atuais |
|---|---|---|
| `AddTruncChip` | `add_trunc.rs` | Add + Reduce → **REMOVE** (absorvido) |
| `SubTruncChip` | `sub_trunc.rs` | Sub + Reduce → **REMOVE** |
| `AddCanonicalChip` | `add_canonical.rs` | AddTrunc + CondPSub → **REPLACE** with `AddCanonicalChunkedChip` |
| `SubCanonicalChip` | `sub_canonical.rs` | SubTrunc + CondPSub → **REPLACE** |
| `MulCanonicalFullChip` | `mul_canonical_full.rs` | MulPipeline + reduce + cond_p_sub | precisa rebind |
| `ModPChipFull` | `mod_p_chip_full.rs` | FirstFold + 2×SecondFold + 2×CondPSub | precisa rebind do CondPSub |
| `PowAirChip` | `pow_air.rs` | 2× MulCanonicalFull/row + bit-cond select | precisa rebind |
| `PointAddAirChip` | `chips/ed25519/point_add_air.rs` | 5 add + 4 sub + 9 mul_canonical_full | precisa rebind |
| `ScalarMulAirChip` | `chips/ed25519/scalar_mul_air.rs` | 2× PointAddAir/row | precisa rebind |
| `DecompressAirChip` | `chips/ed25519/decompress_air.rs` | 11 muls + 1 add + 1 sub | precisa rebind |
| `VerifyAirChip` | `chips/ed25519/verify_air.rs` | 1× point_add + 4× cross-product muls | precisa rebind |

**Magnitude estimada:** cada rebind `start_col` é mecânica (já estabelecida em
sub-fases anteriores), mas **NUM_COLS dos chips topo crescem proporcional**:

```
verify_air NUM_COLS atual: 10956
verify_air NUM_COLS pós-3.10: ~10956 + (1485 − 144) × 5 + ... ≈ 18-22k cells/row
```

STARK prove time impact: ~2-3× (cells crescem ~2×, FRI scales ~linear no cells).

---

## 5. Wire format invariance

### 5.1 PV layout (Public Values)

`VerifyAirChip` expõe 240 PV elements (NUM_PV = 240) representando:

```
pk[32 bytes] || sig[64 bytes] || R[36 limbs] || A[36 limbs] || sB[36 limbs] || hA[36 limbs]
```

**Isso é o wire format.** Bytes serialized via Plonky3 STARK proof, validados pelo
`Capability::VerifyPlonky3Proof` no sVM (`air_id` dispatch).

### 5.2 Invariância sob 3.10

Mudanças em chips internos:
- Aumentam `NUM_COLS/row` (trace width)
- Não tocam `NUM_PV`
- Não tocam ordem ou tamanho dos PV elements
- Não tocam `air_id` registry

**Logo:** wire format dos proofs **inalterado**. Verificadores externos (sVM,
oracle/verifier crate, oracle/sdk) **não exigem upgrade** quando 3.10 deploya.
Apenas o **prover** (relayer) exige upgrade — produzindo proofs com trace mais
largo, mas mesmo PV/serialization.

### 5.3 Roll-out post-mainnet sem fork

Sequência:
1. Deploy 3.10 no relayer (off-chain).
2. Relayer começa a produzir proofs novos com trace expandido.
3. Verificadores on-chain aceitam **identicamente** (PV match).
4. Trust-shims residuais (5.6.b.1/c.1/d.1 wrappers) podem ser deletados pois
   chips reais agora são sound.
5. Hard fork **não necessário**.

Isso é o argumento canônico do trust-shim model — wire format estável é o que
permite hardening incremental sem fork.

---

## 6. Test strategy

### 6.1 Unit tests por chip novo

Para cada chip novo (`AddCanonicalChunkedChip`, `SubCanonicalChunkedChip`):

1. **Honest cases**: dezenas de inputs canônicos, verificar `c = (a±b) mod p`.
2. **Edge cases**: `a = 0`, `b = 0`, `a = p−1`, `b = p−1`, `a = p−1, b = 1` (overflow exato).
3. **Adversarial k=0**: tampered output → constraint deve rejeitar.
4. **Adversarial k=1** (NOVO, crítico): construir `(c', t', borrow')` que satisfaz
   equação BB-level mas representa `c_real + p`. Constraint **deve rejeitar**
   (porque chunks bound `< 2^17` impossibilita `k=1`). Esse teste é a prova de que
   3.10 fecha o gap.
5. **Adversarial chunks**: tampered `lo`/`hi` violando range → constraint rejeita.
6. **Adversarial carry**: tampered `intra_carry`/`inter_carry`/`borrow` → rejeita.

### 6.2 Integration tests

- `verify_air` round-trip RFC 8032 Test 1 com chip novo: STARK prove + verify.
- `decompress_air`, `scalar_mul_air`, `point_add_air` end-to-end.
- Performance regression: prove time ≤ 3× baseline atual.

### 6.3 Fuzz tests

Cargo nextest com seed determinístico, ~10k iterations:
- Fuzz inputs randômicos canônicos → assert constraint passes.
- Fuzz adversarial witnesses (perturbação de chunks) → assert constraint rejects.

---

## 7. Sub-fases — ordem de implementação

| Sub-fase | Conteúdo | Estimativa |
|---|---|---|
| 3.10.D | **Este documento** | ✅ done (esta sessão) |
| 3.10.0 | `AddCanonicalChunkedChip` + tests | 2 sessões |
| 3.10.1 | `SubCanonicalChunkedChip` + tests | 2 sessões |
| 3.10.2 | `MulPipelineChip` audit (decisão go/no-go expansão) | 1 sessão (+2-3 se gap real) |
| 3.10.3 | Rebind topo (PowAir → verify_air) + populate_*_to updates | 2 sessões |
| 3.10.4 | STARK plumbing regression + delete trust-shims 5.6.b.1/c.1/d.1 | 2 sessões |
| 3.10.5 | Memory + CLAUDE.md + commit master + push | 1 sessão |

**Total baseline:** 10 sessões. **Worst case (Mul gap real):** 13-15 sessões.

---

## 8. O que está fora do escopo da Etapa 3.10

**Explicitly out of scope:**

- **Mudança de wire format / PV layout**: não. Wire format fica estável.
- **Re-prove de proofs históricos**: não. Proofs antigos continuam válidos no
  verificador (pois verificador só checa PV + proof bytes — não inspeciona trace).
  Apenas proofs NOVOS (post-3.10 deploy do relayer) usam trace expandido.
- **Hard fork da rede**: não. Capability dispatch e PV unchanged.
- **Mudança no Dilithium signature do relayer bundle**: não. Relayer trust path
  separado.
- **MulPipelineChip rewrite** (se audit revelar gap): pode virar Etapa 3.11 separada.
  Decisão tomada na sub-fase 3.10.2 com base em análise concreta.

---

## 9. Riscos e mitigações

| Risco | Impacto | Mitigação |
|---|---|---|
| `MulPipelineChip` audit revela gap maior que esperado | +2-3 sessões | Documentar como 3.11 separada |
| STARK prove time inflate > 3× | UX relayer impactado | Profile + otimizar populate functions |
| Embedders quebram com novos NUM_COLS | Tests vermelhos | Sub-fase 3.10.3 mecânica, padrão estabelecido |
| `assert_chunks_lo_hi_eq` helper introduz bug | Constraint logic incorreta | Sub-fase 3.10.0 entrega helper isolado com unit tests |
| Wire format **acidentalmente** mudar | Hard fork necessário | PV count assertion test em CI; sub-fase 3.10.4 validation gate |

---

## 10. Decisão final

**Recomendação:** implementar Etapa 3.10 conforme spec acima como **post-mainnet
hardening**. Não bloqueia genesis. Pode ser deployado release-by-release pós-mainnet
sem hard fork, conforme threat model evolui.

**Ordem recomendada de execução:**
1. Mainnet launch primeiro (Phase 5 documented as COMPLETE com trust-shim accepted).
2. Operacional steady-state ≥ 3 meses.
3. Iniciar 3.10.0 quando ecossistema relayer estiver maduro o suficiente para
   tolerar prover upgrade.
4. Cada sub-fase commit + push individual; relayer pega na cadência que quiser.

**Quando NÃO fazer 3.10:**
- Se Phase 5 for descontinuada por evolução de mercado / regulação.
- Se análise descobrir threat model dependente de trust-shim aceitável indefinidamente.
- Se redesign chunked introduzir bugs estruturais que justifiquem voltar ao
  esquema atual + outro modelo de mitigação.

---

## 11. Referências

- `oracle/host/src/chips/sha512/word64_add.rs` — exemplo canônico do padrão chunked
  (sub-fase 3.7.0).
- `oracle/host/src/chips/lookup/range_n.rs` — `RangeNChip<N>` primitivo
  (sub-fase 3.0/3.1).
- `oracle/host/src/chips/field25519/{add,sub,reduce,cond_p_sub,add_canonical,
  sub_canonical,add_trunc,sub_trunc}.rs` — chips a substituir.
- `project_phase5_etapa3_7_audit.md` (memória) — predecessor desta análise.
- `project_phase5_lookup_args_design.md` (memória) — explicação histórica de por
  que `p3-uni-stark` 0.5.2 não suporta lookup args (motivou bit decomp em vez de
  permutation table compartilhada).

---

**Fim do documento.**
