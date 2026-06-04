# scripts/sha256-anchor.ps1 - Sophis canonical commitment anchor
#
# PowerShell-7 equivalent of scripts/sha256-anchor.sh. Produces
# byte-identical output. See sha256-anchor.sh header for design notes
# (LF blob via `git show`; CRLF gotcha; verification via diff).
#
# Computes SHA-256 directly over the raw byte stream of `git show`
# stdout, bypassing PowerShell's text-encoding pipeline. Do NOT use
# `Get-FileHash` against the working copy on Windows - it hashes the
# CRLF on-disk bytes, which will not match the LF blob hash.
#
# Usage:
#   pwsh scripts/sha256-anchor.ps1
#   pwsh scripts/sha256-anchor.ps1 v1.0.0-mainnet
#   pwsh scripts/sha256-anchor.ps1 <commit-sha>

param(
    [string]$Ref = 'HEAD'
)

$ErrorActionPreference = 'Stop'

# Force LF line endings so output is byte-identical to the POSIX
# variant and to any HASHES_T_72H.txt that was committed via git
# (which normalizes to LF). Without this, Windows emits CRLF and
# auditors running `diff` against the published file would see false
# mismatches even when every hash matches.
[Console]::Out.NewLine = "`n"

$docs = @(
    'MONETARY_POLICY.md',
    'FOUNDER_SELF_RESTRICTION.md',
    'OPERATIONAL_BOUNDARIES.md',
    'HARD_FORK_POLICY.md'
)

foreach ($doc in $docs) {
    # Existence check.
    & git cat-file -e "${Ref}:${doc}" 2>$null
    if ($LASTEXITCODE -ne 0) {
        [Console]::Error.WriteLine("error: ${doc} not found at ref ${Ref}")
        exit 1
    }

    # Stream raw git show stdout into SHA-256, bypassing PS text encoding.
    $psi = [System.Diagnostics.ProcessStartInfo]::new()
    $psi.FileName = 'git'
    $psi.ArgumentList.Add('show')
    $psi.ArgumentList.Add("${Ref}:${doc}")
    $psi.RedirectStandardOutput = $true
    $psi.UseShellExecute = $false
    $psi.CreateNoWindow = $true

    $proc = [System.Diagnostics.Process]::Start($psi)
    $sha256 = [System.Security.Cryptography.SHA256]::Create()
    try {
        $hashBytes = $sha256.ComputeHash($proc.StandardOutput.BaseStream)
    } finally {
        $sha256.Dispose()
    }
    $proc.WaitForExit()
    if ($proc.ExitCode -ne 0) {
        [Console]::Error.WriteLine("error: git show failed for ${doc}")
        exit 1
    }

    $hash = -join ($hashBytes | ForEach-Object { '{0:x2}' -f $_ })
    # Note: avoid `-f $hash, $doc` — comma binds tighter than -f and
    # would drop $doc from the format arguments. String interpolation
    # sidesteps the precedence trap.
    [Console]::Out.WriteLine("$hash  $doc")
}
