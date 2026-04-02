#!/usr/bin/env python3
"""
Patch CompactLog to remove the LeafIndex extension from MerkleTreeLeaf.

CompactLog embeds a LeafIndex extension (8 bytes) into the MerkleTreeLeaf
extensions field when storing entries. This breaks RFC 6962 compliance
because standard clients compute leaf hashes with empty extensions.

This patch replaces compute_leaf_data_with_index() calls with
compute_leaf_data() so that the MerkleTreeLeaf always has empty
extensions (0x00 0x00), matching the RFC 6962 specification.
"""

import sys

FILE = "src/storage/mod.rs"

with open(FILE, "r") as f:
    code = f.read()

# 1. Patch the production code path: replace compute_leaf_data_with_index
#    with compute_leaf_data (which passes index: None, producing empty extensions)
old_call = """                    let leaf_data_with_index = LogEntry::compute_leaf_data_with_index(
                        &entry.log_entry.certificate,
                        entry.log_entry.entry_type,
                        entry.log_entry.issuer_key_hash.as_deref(),
                        entry.log_entry.timestamp,
                        assigned_index,
                    );"""

new_call = """                    let leaf_data_with_index = LogEntry::compute_leaf_data(
                        &entry.log_entry.certificate,
                        entry.log_entry.entry_type,
                        entry.log_entry.issuer_key_hash.as_deref(),
                        entry.log_entry.timestamp,
                    );"""

if old_call not in code:
    print(f"ERROR: Could not find compute_leaf_data_with_index call in production code path", file=sys.stderr)
    sys.exit(1)
code = code.replace(old_call, new_call, 1)

# 2. Patch the test code path: the find_index_by_hash test also uses
#    compute_leaf_data_with_index to compute the expected leaf hash.
#    It must match the production code, so update it too.
old_test_call = """        let leaf_data_with_index = LogEntry::compute_leaf_data_with_index(
            &log_entry.certificate,
            log_entry.entry_type,
            log_entry.issuer_key_hash.as_deref(),
            log_entry.timestamp,
            index,
        );"""

new_test_call = """        let leaf_data_with_index = LogEntry::compute_leaf_data(
            &log_entry.certificate,
            log_entry.entry_type,
            log_entry.issuer_key_hash.as_deref(),
            log_entry.timestamp,
        );"""

if old_test_call not in code:
    print(f"ERROR: Could not find compute_leaf_data_with_index call in test code path", file=sys.stderr)
    sys.exit(1)
code = code.replace(old_test_call, new_test_call, 1)

with open(FILE, "w") as f:
    f.write(code)

print("remove_leaf_index patch applied successfully")
