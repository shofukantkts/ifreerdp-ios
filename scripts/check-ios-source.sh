#!/usr/bin/env bash
set -euo pipefail

fail=0

require_pattern() {
    local pattern="$1"
    local file="$2"
    if ! rg -q -- "$pattern" "$file"; then
        printf 'missing required pattern %s in %s\n' "$pattern" "$file" >&2
        fail=1
    fi
}

forbidden_pattern() {
    local pattern="$1"
    if rg -n --glob 'client/iOS/**' -- "$pattern"; then
        printf 'forbidden pattern found: %s\n' "$pattern" >&2
        fail=1
    fi
}

require_pattern 'runs-on: macos-26' .github/workflows/ios.yml
require_pattern 'CertificateTrustStore' client/iOS/FreeRDP/ios_freerdp_ui.m
require_pattern 'IOS_BUNDLE_IDENTIFIER' client/iOS/CMakeLists.txt
require_pattern 'RDP_ENVELOPE_MAGIC' client/iOS/Models/Encryptor.m
require_pattern 'ios_events_read_full' client/iOS/FreeRDP/ios_freerdp_events.m
require_pattern 'requestDesktopResizeToSize' client/iOS/Models/RDPSession.m
forbidden_pattern 'security\.accept_certificates'
forbidden_pattern 'fingerprint\) \? \[NSString stringWithUTF8String:subject\]'

git diff --check
exit "$fail"
