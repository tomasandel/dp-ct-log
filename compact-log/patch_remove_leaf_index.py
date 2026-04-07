#!/usr/bin/env python3
"""
Patch CompactLog to remove the LeafIndex extension from MerkleTreeLeaf.

CompactLog embeds a LeafIndex extension (8 bytes) into the MerkleTreeLeaf
extensions field when storing entries. This breaks RFC 6962 compliance
because standard clients compute leaf hashes with empty extensions.

This patch ensures ALL code paths produce MerkleTreeLeaf with empty
extensions (0x00 0x00), matching the RFC 6962 specification:
  1. Storage: tree hash computation (src/storage/mod.rs)
  2. API: get-entries leaf_input serialization (src/types/mod.rs)
  3. Tests: expected leaf hash in tests (src/storage/mod.rs)
"""

import sys

# ---------- Patch 1: src/storage/mod.rs (tree hash + tests) ----------

FILE1 = "src/storage/mod.rs"

with open(FILE1, "r") as f:
    code = f.read()

# 1a. Patch the production code path: replace compute_leaf_data_with_index
#     with compute_leaf_data (which passes index: None, producing empty extensions)
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

# 1b. Patch the test code path
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

with open(FILE1, "w") as f:
    f.write(code)

print(f"Patched {FILE1}")

# ---------- Patch 2: src/types/mod.rs (get-entries serialization) ----------

FILE2 = "src/types/mod.rs"

with open(FILE2, "r") as f:
    code2 = f.read()

# The serialize() method hardcodes Some(self.index), making get-entries
# return leaf_input with the LeafIndex extension even though the tree
# was built without it. Change to None for consistency.
old_serialize = """        let data = Self::serialize_merkle_tree_leaf(
            &self.certificate,
            self.entry_type,
            issuer_key_hash,
            self.timestamp,
            Some(self.index),
        );"""

new_serialize = """        let data = Self::serialize_merkle_tree_leaf(
            &self.certificate,
            self.entry_type,
            issuer_key_hash,
            self.timestamp,
            None,
        );"""

if old_serialize not in code2:
    print(f"ERROR: Could not find serialize_merkle_tree_leaf call in serialize()", file=sys.stderr)
    sys.exit(1)
code2 = code2.replace(old_serialize, new_serialize, 1)

with open(FILE2, "w") as f:
    f.write(code2)

print(f"Patched {FILE2}")
print("remove_leaf_index patch applied successfully")
