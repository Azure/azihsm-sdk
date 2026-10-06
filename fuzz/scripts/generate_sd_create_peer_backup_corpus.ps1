# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

$corpus = Join-Path $PSScriptRoot '..\corpus\fuzz_tbor_sd_create_peer_backup'
New-Item -ItemType Directory -Force -Path $corpus | Out-Null

$scenarioNames = @(
    'valid-self-peer',
    'valid-distinct-keys',
    'repeat',
    'not-finalized',
    'missing-oob',
    'policy-mismatch',
    'cloning-disabled',
    'empty-mfgr-chain',
    'empty-owner-chain',
    'empty-part-owner-chain',
    'wrong-sata-anchor',
    'mismatched-evidence-leaf',
    'invalid-report-signature',
    'invalid-sender-tag',
    'invalid-backup-tag',
    'wrong-kind-backup',
    'zero-report-length',
    'oversized-report-length',
    'report-index-out-of-range',
    'active-cu-session',
    'inactive-co-session'
)

for ($scenario = 0; $scenario -lt $scenarioNames.Count; $scenario++) {
    # FuzzInput's custom Arbitrary implementation consumes:
    # scenario byte, 64 policy-info bytes, 128 report-data bytes,
    # mutation-mask byte, and repeat-count byte.
    $seed = [byte[]]::new(195)
    $seed[0] = [byte]$scenario
    if ($scenario -ge 12 -and $scenario -le 14) {
        $seed[193] = 1
    }
    $path = Join-Path $corpus ($scenarioNames[$scenario])
    [System.IO.File]::WriteAllBytes($path, $seed)
}

# Include no-op tamper variants: these must follow the valid success path.
foreach ($scenario in 12..14) {
    $seed = [byte[]]::new(195)
    $seed[0] = [byte]$scenario
    $path = Join-Path $corpus ("noop-mutation-{0:D2}" -f $scenario)
    [System.IO.File]::WriteAllBytes($path, $seed)
}
