# SHA-256 anchor — Sophis canonical commitment documents

The four canonical commitment documents

- `MONETARY_POLICY.md`
- `FOUNDER_SELF_RESTRICTION.md`
- `OPERATIONAL_BOUNDARIES.md`
- `HARD_FORK_POLICY.md`

are anchored at the T-72h mainnet announcement per `LAUNCH_CHECKLIST.md`
§1.2 / §5.1. The anchor binds the content of these documents to a
verifiable timestamp prior to the chain itself: any later modification
of any of the four breaks the corresponding hash.

`LAUNCH_CHECKLIST.md` and `SUCCESSION.md` are intentionally **not**
anchored — the checklist is a mutable operational runbook whose content
changes during the T-72h → T+24h window (items get checked off), and
`SUCCESSION.md` is operational with annual updates.

## What the script computes

`scripts/sha256-anchor.{sh,ps1}` compute SHA-256 over the
**LF-normalized git blob content** of each doc at a given ref
(default HEAD), and print one `sha256sum`-format line per doc:

```
<64-hex-hash>  <filename>
```

Internally each line is the equivalent of:

```bash
git show <ref>:<file> | sha256sum
```

The `.ps1` variant streams `git show` stdout directly into a SHA-256
hasher via .NET, avoiding PowerShell's text-encoding pipeline. Both
scripts produce byte-identical output for the same ref.

## Why git blob, not on-disk

The repository uses `text=auto` + `autocrlf=true` (see `.gitattributes`),
so on Windows the working copy has CRLF line endings while the git blob
is LF. Auditors on Linux/macOS hash LF. To match the founder's
published anchor you **must** use `git show <ref>:<file>`. Do **not** use:

- `sha256sum <file>` against a Windows working copy → hashes CRLF bytes
- `Get-FileHash <file>` in PowerShell against on-disk bytes → same
- `Get-Content <file> | sha256sum` → PowerShell encoding tampering

## Verifying a published HASHES_T_72H.txt

```bash
git clone https://github.com/sophis-network/Sophis
cd Sophis
git checkout <ref-from-announcement>   # tag v1.0.0-mainnet, or commit sha
bash scripts/sha256-anchor.sh > /tmp/check.txt
diff HASHES_T_72H.txt /tmp/check.txt
```

Zero diff → the four documents at that ref hash to the values in the
published `HASHES_T_72H.txt`. Any line diff → either the doc was modified
after the anchor was published, or the published file was tampered with.
The truth is whichever value matches the ref the founder named in the
T-72h announcement.

Per-file spot check, if you want to verify a single document by hand:

```bash
git show <ref>:MONETARY_POLICY.md | sha256sum
```

## Running the script

The script is run **once**, at T-72h, against the frozen ref that the
T-72h announcement names. Earlier dry-runs against `HEAD` are fine
(and recommended pre-flight per `LAUNCH_CHECKLIST.md` §1.1), but the
file `HASHES_T_72H.txt` itself is only committed at T-72h.

```bash
# Linux / macOS / WSL / Git Bash
bash scripts/sha256-anchor.sh v1.0.0-mainnet > HASHES_T_72H.txt

# PowerShell 7+ (Windows)
pwsh scripts/sha256-anchor.ps1 v1.0.0-mainnet > HASHES_T_72H.txt
```
