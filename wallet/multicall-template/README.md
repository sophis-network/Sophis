# Sophis Multicall — sample sVM contract template

This directory contains a **template** sample sVM contract source for the
Sophis Multicall pattern (J7). It is **not** a workspace member and is
**not built** by `cargo` — it documents the canonical contract shape so
dApp implementers have a reference to start from.

Same template-only convention used by [`wallet/aa-spec/`](../aa-spec/)
for the Account Abstraction spec.

## What is Multicall?

A pattern that bundles N sub-calls into one signed transaction, atomic
by default. Originated as [Multicall.sol] on Ethereum (Maker, MakerDAO,
mds1's Multicall3 are the production references). Sophis J7 ratifies the
equivalent pattern adapted to sVM: same `(target, call_data, value,
allow_failure)` per sub-call, same atomic-by-default semantics, same
per-call result aggregation.

[Multicall.sol]: https://github.com/mds1/multicall

See `docs/J7_MULTICALL_DESIGN.md` for the canonical specification.

## Files

* [`Multicall.template.rs`](./Multicall.template.rs) — sample sVM
  contract source. WASM-compilable when the rest of the SDK glue is
  wired around it (input parsing, sub-call dispatch, output writing).
  Not actually compiled here.

## Deployment story (when concrete dApps need this)

A reference Multicall WASM gets compiled from the template, deployed
once per network, and its `contract_id` is published in the wallet /
SDK so dApps and wallets agree on which contract to call. Single
canonical deployment per network mirrors how Ethereum Multicall.sol
+ Multicall3.sol shipped: one well-known address per chain.

This deployment is NOT shipped by the Sophis core team in J7 v1 —
ecosystem ships when demand surfaces, per founder guidance
(`project_ethereum_lessons.md` item J7).

## Why template-only

Per founder guidance: "Ship como contract no SDK; nativo só se demand
aparecer. Pode ser SDK contract first; promoção a nativo via SIP
futuro." The template freezes the contract shape so future deployers
agree on the wire format; the actual deployment + Rust SDK helper
follow when 2+ dApps need them (D6 of the design doc).
