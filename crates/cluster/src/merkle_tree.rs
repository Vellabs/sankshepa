//! Merkle Tree for efficient anti-entropy synchronization.
//!
//! This module implements a hash tree that allows nodes to efficiently
//! detect differences in their template/variable state and exchange
//! only the differing portions.

use serde::{Deserialize, Serialize};
use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};

/// A node in the Merkle tree.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct MerkleNode {
    /// Hash of this node's content
    pub hash: u64,
    /// Range of keys covered [start, end)
    pub range_start: u64,
    pub range_end: u64,
    /// Number of items in this subtree
    pub count: usize,
}

/// A Merkle tree for synchronization.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MerkleTree {
    /// Tree depth (determines granularity)
    depth: u32,
    /// Leaf nodes containing actual data hashes
    leaves: Vec<MerkleNode>,
    /// Internal nodes (computed from leaves)
    internal_nodes: Vec<Vec<MerkleNode>>,
    /// Root hash
    root_hash: u64,
}

impl MerkleTree {
    /// Create a new Merkle tree with the given depth.
    /// Depth determines the number of buckets: 2^depth
    pub fn new(depth: u32) -> Self {
        let num_leaves = 1 << depth;
        let bucket_size = u64::MAX / num_leaves as u64;

        let leaves: Vec<MerkleNode> = (0..num_leaves)
            .map(|i| {
                let start = i as u64 * bucket_size;
                let end = if i == num_leaves - 1 {
                    u64::MAX
                } else {
                    (i + 1) as u64 * bucket_size
                };
                MerkleNode {
                    hash: 0,
                    range_start: start,
                    range_end: end,
                    count: 0,
                }
            })
            .collect();

        let mut tree = Self {
            depth,
            leaves,
            internal_nodes: Vec::new(),
            root_hash: 0,
        };
        tree.rebuild_internal();
        tree
    }

    /// Insert a key-value pair into the tree.
    pub fn insert(&mut self, key: &str, value_hash: u64) {
        let key_hash = Self::hash_key(key);
        let bucket = self.find_bucket(key_hash);

        // Combine hashes (XOR for order-independence)
        self.leaves[bucket].hash ^= value_hash;
        self.leaves[bucket].count += 1;

        self.rebuild_internal();
    }

    /// Remove a key from the tree.
    pub fn remove(&mut self, key: &str, value_hash: u64) {
        let key_hash = Self::hash_key(key);
        let bucket = self.find_bucket(key_hash);

        // XOR again to remove
        self.leaves[bucket].hash ^= value_hash;
        if self.leaves[bucket].count > 0 {
            self.leaves[bucket].count -= 1;
        }

        self.rebuild_internal();
    }

    /// Get the root hash.
    pub fn root_hash(&self) -> u64 {
        self.root_hash
    }

    /// Find differences between this tree and another.
    /// Returns ranges that differ.
    pub fn diff(&self, other: &MerkleTree) -> Vec<(u64, u64)> {
        if self.root_hash == other.root_hash {
            return Vec::new();
        }

        let mut diffs = Vec::new();
        self.diff_recursive(&self.leaves, &other.leaves, &mut diffs);
        diffs
    }

    fn diff_recursive(
        &self,
        our_nodes: &[MerkleNode],
        their_nodes: &[MerkleNode],
        diffs: &mut Vec<(u64, u64)>,
    ) {
        for (our, their) in our_nodes.iter().zip(their_nodes.iter()) {
            if our.hash != their.hash {
                diffs.push((our.range_start, our.range_end));
            }
        }
    }

    /// Get a digest for synchronization (compact representation).
    pub fn digest(&self) -> MerkleDigest {
        MerkleDigest {
            root_hash: self.root_hash,
            leaf_hashes: self.leaves.iter().map(|n| n.hash).collect(),
            total_count: self.leaves.iter().map(|n| n.count).sum(),
        }
    }

    /// Find differing buckets given a digest from another node.
    pub fn diff_with_digest(&self, digest: &MerkleDigest) -> Vec<usize> {
        if self.root_hash == digest.root_hash {
            return Vec::new();
        }

        self.leaves
            .iter()
            .enumerate()
            .filter_map(|(i, node)| {
                if i < digest.leaf_hashes.len() && node.hash != digest.leaf_hashes[i] {
                    Some(i)
                } else {
                    None
                }
            })
            .collect()
    }

    /// Get items in a specific bucket range.
    pub fn get_bucket_range(&self, bucket: usize) -> Option<(u64, u64)> {
        self.leaves
            .get(bucket)
            .map(|n| (n.range_start, n.range_end))
    }

    fn find_bucket(&self, key_hash: u64) -> usize {
        let num_leaves = self.leaves.len();
        let bucket_size = u64::MAX / num_leaves as u64;
        (key_hash / bucket_size).min(num_leaves as u64 - 1) as usize
    }

    fn rebuild_internal(&mut self) {
        // Simple implementation: just compute root from leaves
        let mut hasher = DefaultHasher::new();
        for leaf in &self.leaves {
            leaf.hash.hash(&mut hasher);
        }
        self.root_hash = hasher.finish();
    }

    fn hash_key(key: &str) -> u64 {
        let mut hasher = DefaultHasher::new();
        key.hash(&mut hasher);
        hasher.finish()
    }
}

/// Compact digest for network transmission.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MerkleDigest {
    pub root_hash: u64,
    pub leaf_hashes: Vec<u64>,
    pub total_count: usize,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_insert_and_root() {
        let mut tree = MerkleTree::new(4);
        let initial_root = tree.root_hash();

        tree.insert("template1", 12345);
        assert_ne!(tree.root_hash(), initial_root);
    }

    #[test]
    fn test_same_trees() {
        let mut tree1 = MerkleTree::new(4);
        let mut tree2 = MerkleTree::new(4);

        tree1.insert("key1", 100);
        tree2.insert("key1", 100);

        assert_eq!(tree1.root_hash(), tree2.root_hash());
        assert!(tree1.diff(&tree2).is_empty());
    }

    #[test]
    fn test_different_trees() {
        let mut tree1 = MerkleTree::new(4);
        let mut tree2 = MerkleTree::new(4);

        tree1.insert("key1", 100);
        tree2.insert("key2", 200);

        assert_ne!(tree1.root_hash(), tree2.root_hash());
        assert!(!tree1.diff(&tree2).is_empty());
    }

    #[test]
    fn test_order_independence() {
        let mut tree1 = MerkleTree::new(4);
        let mut tree2 = MerkleTree::new(4);

        // Insert in different order
        tree1.insert("key1", 100);
        tree1.insert("key2", 200);

        tree2.insert("key2", 200);
        tree2.insert("key1", 100);

        // Should have the same root if keys fall in different buckets
        // or XOR makes them order-independent in same bucket
        assert_eq!(tree1.root_hash(), tree2.root_hash());
    }
}
