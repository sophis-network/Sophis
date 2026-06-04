#!/usr/bin/env bash
#
# scripts/sha256-anchor.sh - Sophis canonical commitment anchor
#
# Emits the SHA-256 of the LF-normalized git blob content of each of
# the four canonical commitment documents (LAUNCH_CHECKLIST.md
# section 1.2 / 5.1), at the given git ref (default HEAD), one line
# per doc in sha256sum format:
#
#     <64-hex-hash>  <filename>
#
# This file is the founder's pre-mainnet commitment receipt. It must
# be reproducible by any third party with git + sha256sum at the same
# git ref. The repository uses text=auto + autocrlf=true, so on
# Windows the working copy has CRLF line endings while the git blob
# is LF. Auditors on Linux/macOS hash LF. To match the published
# anchor, use `git show <ref>:<file>` - do NOT use sha256sum against a
# Windows working copy.
#
# Usage:
#   bash scripts/sha256-anchor.sh                # against HEAD
#   bash scripts/sha256-anchor.sh v1.0.0-mainnet
#   bash scripts/sha256-anchor.sh <commit-sha>
#
# Re-verify a previously-published HASHES_T_72H.txt at the ref the
# founder named in the announcement:
#
#   bash scripts/sha256-anchor.sh <ref> | diff HASHES_T_72H.txt -
#
# Exits non-zero if any anchor doc is missing at the given ref.

set -euo pipefail

ref="${1:-HEAD}"

docs=(
    "MONETARY_POLICY.md"
    "FOUNDER_SELF_RESTRICTION.md"
    "OPERATIONAL_BOUNDARIES.md"
    "HARD_FORK_POLICY.md"
)

for doc in "${docs[@]}"; do
    if ! git cat-file -e "${ref}:${doc}" 2>/dev/null; then
        echo "error: ${doc} not found at ref ${ref}" >&2
        exit 1
    fi
    hash=$(git show "${ref}:${doc}" | sha256sum | cut -d' ' -f1)
    printf '%s  %s\n' "${hash}" "${doc}"
done
