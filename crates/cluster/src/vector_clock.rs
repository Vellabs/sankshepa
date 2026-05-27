//! Vector Clock implementation for causality tracking in AP systems.
//!
//! Vector clocks provide a mechanism to track causal relationships between
//! events in a distributed system, enabling conflict detection and resolution.

use serde::{Deserialize, Serialize};
use std::cmp::Ordering;
use std::collections::HashMap;

/// A vector clock for tracking causality across distributed nodes.
#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq, Eq)]
pub struct VectorClock {
    /// Map from node_id to logical timestamp
    clocks: HashMap<String, u64>,
}

impl VectorClock {
    /// Create a new empty vector clock.
    pub fn new() -> Self {
        Self {
            clocks: HashMap::new(),
        }
    }

    /// Increment the clock for the given node.
    pub fn increment(&mut self, node_id: &str) {
        let counter = self.clocks.entry(node_id.to_string()).or_insert(0);
        *counter += 1;
    }

    /// Get the timestamp for a specific node.
    pub fn get(&self, node_id: &str) -> u64 {
        self.clocks.get(node_id).copied().unwrap_or(0)
    }

    /// Merge another vector clock into this one (take max of each component).
    pub fn merge(&mut self, other: &VectorClock) {
        for (node_id, &timestamp) in &other.clocks {
            let current = self.clocks.entry(node_id.clone()).or_insert(0);
            *current = (*current).max(timestamp);
        }
    }

    /// Check if this clock happened before another (causally precedes).
    pub fn happened_before(&self, other: &VectorClock) -> bool {
        let mut dominated = false;

        // Check all nodes in self
        for (node_id, &self_ts) in &self.clocks {
            let other_ts = other.get(node_id);
            if self_ts > other_ts {
                return false;
            }
            if self_ts < other_ts {
                dominated = true;
            }
        }

        // Check nodes only in other
        for (node_id, &other_ts) in &other.clocks {
            if !self.clocks.contains_key(node_id) && other_ts > 0 {
                dominated = true;
            }
        }

        dominated
    }

    /// Check if two vector clocks are concurrent (neither happened before the other).
    pub fn concurrent_with(&self, other: &VectorClock) -> bool {
        !self.happened_before(other) && !other.happened_before(self) && self != other
    }

    /// Compare two vector clocks for partial ordering.
    pub fn partial_cmp(&self, other: &VectorClock) -> Option<Ordering> {
        if self == other {
            Some(Ordering::Equal)
        } else if self.happened_before(other) {
            Some(Ordering::Less)
        } else if other.happened_before(self) {
            Some(Ordering::Greater)
        } else {
            None // Concurrent
        }
    }

    /// Get all node IDs in this clock.
    pub fn nodes(&self) -> impl Iterator<Item = &String> {
        self.clocks.keys()
    }

    /// Get the sum of all timestamps (for quick comparison).
    pub fn sum(&self) -> u64 {
        self.clocks.values().sum()
    }

    /// Serialize to bytes for network transmission.
    pub fn to_bytes(&self) -> Vec<u8> {
        postcard::to_allocvec(self).unwrap_or_default()
    }

    /// Deserialize from bytes.
    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        postcard::from_bytes(bytes).ok()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_increment() {
        let mut vc = VectorClock::new();
        vc.increment("node1");
        assert_eq!(vc.get("node1"), 1);
        vc.increment("node1");
        assert_eq!(vc.get("node1"), 2);
    }

    #[test]
    fn test_happened_before() {
        let mut vc1 = VectorClock::new();
        let mut vc2 = VectorClock::new();

        vc1.increment("node1");
        vc2.increment("node1");
        vc2.increment("node1");

        assert!(vc1.happened_before(&vc2));
        assert!(!vc2.happened_before(&vc1));
    }

    #[test]
    fn test_concurrent() {
        let mut vc1 = VectorClock::new();
        let mut vc2 = VectorClock::new();

        vc1.increment("node1");
        vc2.increment("node2");

        assert!(vc1.concurrent_with(&vc2));
        assert!(vc2.concurrent_with(&vc1));
    }

    #[test]
    fn test_merge() {
        let mut vc1 = VectorClock::new();
        let mut vc2 = VectorClock::new();

        vc1.increment("node1");
        vc1.increment("node1");
        vc2.increment("node2");

        vc1.merge(&vc2);

        assert_eq!(vc1.get("node1"), 2);
        assert_eq!(vc1.get("node2"), 1);
    }

    #[test]
    fn test_serialization_roundtrip() {
        let mut vc = VectorClock::new();
        vc.increment("node1");
        vc.increment("node1");
        vc.increment("node2");

        let bytes = vc.to_bytes();
        let recovered = VectorClock::from_bytes(&bytes).unwrap();

        assert_eq!(recovered.get("node1"), 2);
        assert_eq!(recovered.get("node2"), 1);
    }

    #[test]
    fn test_from_bytes_invalid_data_returns_none() {
        let result = VectorClock::from_bytes(b"not valid postcard data");
        assert!(result.is_none());
    }

    #[test]
    fn test_sum() {
        let mut vc = VectorClock::new();
        vc.increment("node1");
        vc.increment("node1");
        vc.increment("node2");
        assert_eq!(vc.sum(), 3);
    }

    #[test]
    fn test_partial_cmp_equal() {
        let mut vc1 = VectorClock::new();
        let mut vc2 = VectorClock::new();
        vc1.increment("node1");
        vc2.increment("node1");
        assert_eq!(vc1.partial_cmp(&vc2), Some(std::cmp::Ordering::Equal));
    }

    #[test]
    fn test_partial_cmp_less() {
        let mut vc1 = VectorClock::new();
        let mut vc2 = VectorClock::new();
        vc1.increment("node1");
        vc2.increment("node1");
        vc2.increment("node1");
        assert_eq!(vc1.partial_cmp(&vc2), Some(std::cmp::Ordering::Less));
    }

    #[test]
    fn test_partial_cmp_greater() {
        let mut vc1 = VectorClock::new();
        let mut vc2 = VectorClock::new();
        vc1.increment("node1");
        vc1.increment("node1");
        vc2.increment("node1");
        assert_eq!(vc1.partial_cmp(&vc2), Some(std::cmp::Ordering::Greater));
    }

    #[test]
    fn test_partial_cmp_concurrent_returns_none() {
        let mut vc1 = VectorClock::new();
        let mut vc2 = VectorClock::new();
        vc1.increment("node1");
        vc2.increment("node2");
        assert_eq!(vc1.partial_cmp(&vc2), None);
    }

    #[test]
    fn test_nodes_iterator() {
        let mut vc = VectorClock::new();
        vc.increment("node1");
        vc.increment("node2");
        let nodes: Vec<&String> = vc.nodes().collect();
        assert_eq!(nodes.len(), 2);
    }

    #[test]
    fn test_empty_clock_sum_is_zero() {
        let vc = VectorClock::new();
        assert_eq!(vc.sum(), 0);
    }

    #[test]
    fn test_merge_takes_max() {
        let mut vc1 = VectorClock::new();
        let mut vc2 = VectorClock::new();
        vc1.increment("node1");
        vc1.increment("node1");
        vc1.increment("node1"); // node1 = 3
        vc2.increment("node1"); // node1 = 1
        vc2.increment("node1"); // node1 = 2

        vc2.merge(&vc1);
        // Should keep max = 3
        assert_eq!(vc2.get("node1"), 3);
    }
}
