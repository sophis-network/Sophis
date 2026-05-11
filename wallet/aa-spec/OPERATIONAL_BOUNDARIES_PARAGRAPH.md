# Operational Boundaries — Account Abstraction paragraph

**Status:** Drop-in text. Insert verbatim into the listed destinations **only when** the first AA reference contract is published as code (i.e., when a maintainer opens the SIP and begins the public review process). Inserting earlier is premature; inserting later is a missed signaling opportunity.

**Author:** Marcelo Delgado <sophis-network@proton.me>

**Date:** 2026-05-09

---

## 1. The canonical text (English)

To be inserted into the project's `OPERATIONAL_BOUNDARIES.md` as a new section, AND into the whitepaper §11 ("Operational Boundaries") as a new sub-section:

> ### Account abstraction
>
> Account abstraction (AA) reference contracts and SDK helpers are released as open-source under AGPL-3.0. The Sophis core team does not operate, host, custody, or recover any user account. Specifically:
>
> - **No account factory.** The core team does not deploy or operate a contract that creates accounts on behalf of users. Account contracts are deployed by the operator of each wallet, using either the reference SDK or a third-party tool of their choice.
> - **No guardian curation.** Guardians for any account are chosen exclusively by the account holder. The core team does not maintain, recommend, endorse, or verify any list of guardians, individuals, institutions, or services suitable for that role.
> - **No paymaster operation.** When a third-party paymaster ecosystem develops, the core team will not operate any paymaster instance and will not maintain a list of "preferred" paymasters. Reference contracts for paymaster patterns may be published, but operation is per-deployer responsibility.
> - **No recovery service.** Account recovery occurs through the user's chosen guardians signing rotation messages; the core team is not a party to any recovery flow. Loss of access due to insufficient or compromised guardians is the user's loss.
> - **No identity layer.** Account abstraction in Sophis does not integrate with OAuth, WebAuthn, zkLogin, or any other identity-provider scheme. Authentication is by Dilithium signature only.
>
> The legal posture of this arrangement is identical to the project's posture for the core protocol: reference code is published; operation is performed by third parties under their own responsibility. This is the same posture under which Bitcoin Core has operated for fifteen-plus years and under which the Ethereum ERC-4337 EntryPoint has operated for three-plus years, in both cases without successful prosecution of the reference-code publishers as service providers.

## 2. Texto canônico (Português)

A ser inserido no `OPERATIONAL_BOUNDARIES.md` em português (se houver versão pt-BR do documento) e no whitepaper PT-BR §11:

> ### Abstração de contas
>
> Contratos de referência e helpers de SDK para abstração de contas (AA — Account Abstraction) são publicados como open-source sob AGPL-3.0. A equipe core do Sophis não opera, hospeda, custodia ou recupera qualquer conta de usuário. Especificamente:
>
> - **Sem fábrica de contas.** A equipe core não deploya nem opera contrato que crie contas em nome de usuários. Contratos de conta são deployados pelo operador de cada wallet, usando o SDK de referência ou ferramenta de terceiros à escolha.
> - **Sem curadoria de guardiões.** Os guardiões de qualquer conta são escolhidos exclusivamente pelo titular da conta. A equipe core não mantém, recomenda, endossa ou verifica qualquer lista de guardiões — pessoas, instituições ou serviços — adequados para esse papel.
> - **Sem operação de paymaster.** Quando um ecossistema de paymasters de terceiros se desenvolver, a equipe core não operará qualquer instância de paymaster nem manterá lista de paymasters "preferidos". Contratos de referência para padrões de paymaster podem ser publicados, mas a operação é responsabilidade do deployer.
> - **Sem serviço de recuperação.** Recuperação de contas ocorre via guardiões escolhidos pelo usuário assinando mensagens de rotação; a equipe core não é parte de nenhum fluxo de recuperação. Perda de acesso por guardiões insuficientes ou comprometidos é perda do usuário.
> - **Sem camada de identidade.** Abstração de contas em Sophis não integra com OAuth, WebAuthn, zkLogin ou qualquer outro esquema de provedor de identidade. Autenticação é por assinatura Dilithium apenas.
>
> A postura jurídica desse arranjo é idêntica à postura do projeto para o protocolo core: código de referência é publicado; operação é executada por terceiros sob sua própria responsabilidade. É a mesma postura sob a qual o Bitcoin Core opera há quinze-mais anos e sob a qual o EntryPoint do ERC-4337 do Ethereum opera há três-mais anos, em ambos os casos sem que os publicadores do código de referência tenham sido processados com sucesso como prestadores de serviço.

## 3. Insertion checklist

When the maintainer opens the AA SIP:

- [ ] Read this file end to end
- [ ] Confirm the EN and PT-BR texts are still accurate at insertion time (the legal-posture claims in particular may need updating if relevant precedents change)
- [ ] Open a PR adding the EN section to `OPERATIONAL_BOUNDARIES.md` (root of the repo)
- [ ] Open a PR adding the EN section to `Whitepaper.md` §11 in the founder's local Drive
- [ ] Open a PR adding the PT-BR section to the corresponding pt-BR documents
- [ ] Regenerate the whitepaper PDF after the §11 update is merged
- [ ] Cite this file in the SIP discussion as the canonical source

## 4. Why a separate file

Three reasons:

1. **Travels with operational documentation.** The text belongs in `OPERATIONAL_BOUNDARIES.md` and the whitepaper, not in the AA spec proper. Maintainers who only update operational docs without reading the spec should still find the canonical wording here, in the spec directory, with context.

2. **Frozen language matters.** The exact phrasing — particularly "does not operate, host, custody, or recover" — is chosen to mirror language used by precedents (Bitcoin Core, Monero Project) that have legally weathered prosecution. Maintainers paraphrasing the text risk drifting into language that has not been tested. A canonical file makes it easier to copy verbatim.

3. **Updates are auditable.** Edits to this file can be tracked in git history. If the language is ever revised — for example, after a regulatory development changes what wording is most defensible — the change is visible and discussable, not buried in a whitepaper revision diff.

## 5. What to NOT do with this text

- **Do not soften it.** Drafts that read "the core team generally does not..." or "the core team currently does not..." invite future erosion. The current wording uses unqualified declaratives ("does not"); preserve them.
- **Do not add lists of "approved" exceptions.** "The core team does not operate paymasters except for the official onboarding paymaster" is the failure mode. There are no exceptions.
- **Do not add legal disclaimers as part of the boundary text.** The legal posture is the boundary; disclaimers belong elsewhere if they are needed at all.
- **Do not omit the precedent sentence.** The Bitcoin Core / ERC-4337 precedent reference is load-bearing — it provides external validation for the legal position rather than relying on the project's own assertion. Removing it weakens the paragraph.
- **Do not use "social recovery" anywhere in this text or its translations.** ANTI_PATTERNS.md §2 — guardian-based recovery is the only correct term.

## 6. Post-mainnet evolution

If, after AA reference contracts have been in production for ≥12 months, the operational boundaries change in any way (e.g., a paymaster ecosystem matures and the core team chooses to publish a paymaster reference contract that is widely deployed by third parties), this text should be **revised, not silently extended**. Each addition should:

- Maintain the unqualified "does not operate" phrasing for whatever the team genuinely does not operate
- Explicitly disclaim the new pattern ("Reference paymaster contracts are published; deployment is per-operator")
- Be re-circulated for community review before merging to operational docs

## 7. Last touched

2026-05-09 — initial pre-RFC draft. Insertion deferred until the first AA reference contract is ready for SIP publication.
