#!/usr/bin/env python3
"""
Patch CompactLog to support X-Skip-Inclusion header on add-pre-chain.

When the header is present, CompactLog signs and returns a valid SCT
but does NOT insert the certificate into the Merkle tree.
This enables the non-inclusion attack scenario.
"""

import sys

FILE = "src/api/handlers.rs"

with open(FILE, "r") as f:
    code = f.read()

# 1. Add HeaderMap to axum imports
old_import = "    http::StatusCode,"
new_import = "    http::{StatusCode, HeaderMap},"
if old_import not in code:
    print(f"ERROR: Could not find import line: {old_import}", file=sys.stderr)
    sys.exit(1)
code = code.replace(old_import, new_import, 1)

# 2. Add headers: HeaderMap parameter to add_pre_chain
old_sig = """pub async fn add_pre_chain(
    State(state): State<Arc<ApiState>>,
    Json(request): Json<AddChainRequest>,"""
new_sig = """pub async fn add_pre_chain(
    State(state): State<Arc<ApiState>>,
    headers: HeaderMap,
    Json(request): Json<AddChainRequest>,"""
if old_sig not in code:
    print(f"ERROR: Could not find add_pre_chain signature", file=sys.stderr)
    sys.exit(1)
code = code.replace(old_sig, new_sig, 1)

# 3. Insert skip_inclusion logic after variable declarations, before add_entry_batched
anchor = "    let issuer_key_hash_for_sct = issuer_key_hash.clone();"
if anchor not in code:
    print(f"ERROR: Could not find anchor line: {anchor}", file=sys.stderr)
    sys.exit(1)

skip_block = """    let issuer_key_hash_for_sct = issuer_key_hash.clone();

    // Skip inclusion: sign SCT but do not add to Merkle tree (non-inclusion attack)
    let skip_inclusion = headers
        .get("x-skip-inclusion")
        .and_then(|v| v.to_str().ok())
        .map(|v| v.eq_ignore_ascii_case("true"))
        .unwrap_or(false);

    if skip_inclusion {
        let sct = sct_builder
            .create_sct_with_timestamp_and_index(
                &tbs_cert_for_sct,
                LogEntryType::PrecertEntry,
                Some(&issuer_key_hash_for_sct),
                timestamp_ms,
                None,
            )
            .expect("Failed to create SCT for skip-inclusion");

        let response = AddChainResponse {
            sct_version: sct.version as u8,
            id: STANDARD.encode(sct.log_id.as_bytes()),
            timestamp: sct.timestamp,
            extensions: STANDARD.encode(&sct.extensions),
            signature: STANDARD.encode(&sct.signature),
        };

        return Ok(Json(response));
    }
"""

code = code.replace(anchor, skip_block, 1)

with open(FILE, "w") as f:
    f.write(code)

print("skip_inclusion patch applied successfully")
