# Contributing to Sophis

Thanks for your interest in contributing to Sophis!

We welcome contributions of all sizes and there are many opportunities to contribute at any level — from clarifying documentation and fixing small bugs to implementing full features and reviewing pull requests.

Reach out to `@Node Developers` in Discord in the [#development](https://discord.com/channels/599153230659846165/755890250643144788) channel.

Follow along the R&D Telegram group [@sophisrnd](https://t.me/sophisrnd).

## Quick summary

- Open a GitHub Issue or Pull Request to start any discussion. Use Issues for design or spec discussions and PRs when you have code to share.
- Look for `good first issue` if you're getting started; these are intentionally approachable.
- Write detailed pull requests descriptions: explain what you changed, why, design decisions, and any trade-offs.
- **Anyone** willing to contribute is encouraged to review pull requests and ask questions. Your approval and review counts!

## Reviewing Pull Requests

If you can meaningfully review a pull request, please do so even if you have not contributed code to the repo. This helps in improving the quality of code and gives you a great opportunity to learn more about the codebase through the context of a change.

- Leave review comments, ask clarifying questions, request documentation, point out potential regressions.
- Even if you can't read the code but know how to test it, do that too! Ask for information on how to test the change if it's missing from the PR and run it.
- Use Approve when you believe the change is correct and safe to merge.
- Use Request Changes when you find real issues; explain the issue and prefer actionable guidance.

## How to get started

1. Find an issue (or open one) — good first issues are a great first step.
2. Fork the repo (See [Installation](https://github.com/sophisnet/rusty-sophis?tab=readme-ov-file#installation) guide) and create a feature branch with a short, descriptive name.
3. Implement your change and include tests where appropriate.
4. Make each commit atomic and focused. Update tests or add new ones in the same commit that changes behaviour.
5. Push to your fork and open a Pull Request against the `master` branch (or the branch named in the issue).

## Pull request guidelines

### Before making a Pull Request:
- Run `./check` (or `./check.ps1` on windows) to make sure your code adheres to coding standards
- Run `./test` (or `cargo nextest run --release` on windows) and make sure you all tests still pass

### Please make your PRs easy to review. A helpful PR contains:

- A clear, descriptive title of what the PR does.
- A summary of what changed and the motivation.
- Any relevant background or links to design discussions or Issues.
- A short description of how the change was tested (unit tests, integration tests, manual steps). Reviewers will use this to test your changes.
- Notes about backwards-compatibility, migrations, or behaviour changes.
- If the change is large, consider splitting it into a small series of focused PRs.

### Commit message tips:

- Start with a short subject line (<= 50 chars), leave a blank line, then add details.
- Try to keep your commits atomic as this makes reviewing them in the context of a PR easier, making the PR overall easier to review and eventually merge

## Using Issues and Pull Requests for discussion

- Use a GitHub Issue to propose or discuss ideas before writing code if the change affects APIs, consensus, or requires design feedback.
- You can also contribute by participating in existing discussions.
- When you start implementing, link the Issue in your Pull Request and mention any related discussions.
- If a PR is experimental or a work in progress, create the Pull Request in your fork of the repository first.

## Sophis Improvement Proposals (SIPs)

Non-trivial protocol-level changes go through the **SIP** process,
not a direct PR. A SIP is required for changes affecting consensus
rules, network protocol, the sVM ABI, ZK-Rollup or ZK-Oracle
formats, Data Availability rules, wallet wire formats intended for
ecosystem use, or any change that requires a soft fork or hard
fork.

Bug fixes, refactors, performance work, documentation, tests, and
build / packaging changes do **not** require a SIP — open a regular
PR.

The SIP process and a blank template live in [`SIPS/`](./SIPS/):

- [`SIPS/SIP-0-process.md`](./SIPS/SIP-0-process.md) — full process
- [`SIPS/SIP-template.md`](./SIPS/SIP-template.md) — blank template
- [`SIPS/README.md`](./SIPS/README.md) — index and quick start

When in doubt about whether your change needs a SIP, open a GitHub
Issue first.

## Testing and CI

Add or update tests for behavior changes. Ensure CI passes before requesting a merge. If your change requires a special test or manual validation, describe it in the PR.

## Developer Certificate of Origin (DCO)

All contributions to Sophis must be signed off under the [Developer Certificate of Origin v1.1](https://developercertificate.org/). The DCO is a lightweight contributor agreement that asserts you have the right to submit the work under the project's license (AGPL-3.0, see `LICENSE`). It does **not** transfer copyright; you retain ownership of your contributions.

**To sign off your commits, use `-s` / `--signoff`:**

```bash
git commit -s -m "your commit message"
```

This automatically appends a line of the form:

```
Signed-off-by: Your Name <your.email@example.com>
```

By signing off, you certify that you agree to all four points of the DCO:

> 1. The contribution was created in whole or in part by you and you have the right to submit it under the open source license indicated in the file; or
> 2. The contribution is based upon previous work that, to the best of your knowledge, is covered under an appropriate open source license and you have the right under that license to submit that work with modifications, whether created in whole or in part by you, under the same open source license (unless you are permitted to submit under a different license), as indicated in the file; or
> 3. The contribution was provided directly to you by some other person who certified (1), (2) or (3) and you have not modified it.
> 4. You understand and agree that this project and the contribution are public and that a record of the contribution (including all personal information you submit with it, including your sign-off) is maintained indefinitely and may be redistributed consistent with this project and the open source license(s) involved.

Pull requests that contain commits without a `Signed-off-by` line will be asked to amend the commits before merge. To amend an existing commit on your branch:

```bash
git commit --amend -s --no-edit
git push --force-with-lease
```

To bulk-sign every commit on your feature branch:

```bash
git rebase --signoff main
```

**Why DCO instead of a CLA?** Sophis has no legal entity behind it (see the *Operational Boundaries Statement*). A traditional Contributor License Agreement requires a counterparty to receive the assignment; the DCO is the standard alternative used by the Linux kernel, Git, Docker, and many other projects to obtain the same legal certainty without that overhead.

## Code of conduct

Be respectful and constructive in discussions. We expect contributors to follow common open-source etiquette; if you're unsure about tone, err on the side of politeness.

## Thank You

Thanks for helping make Sophis better. If you have questions, reach out to the channels described at the top of this document

