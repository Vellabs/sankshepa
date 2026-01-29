//! CRDT-based Template Store for eventual consistency.
//!
//! This module implements Conflict-free Replicated Data Types (CRDTs)
//! for managing templates and variables across distributed nodes.
//! CRDTs guarantee eventual consistency without coordination.

use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};

/// A Grow-only Set (G-Set) CRDT for template patterns.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct GSet<T: Clone + Eq + std::hash::Hash> {
    elements: HashSet<T>,
}

impl<T: Clone + Eq + std::hash::Hash> GSet<T> {
    /// Create a new empty G-Set.
    pub fn new() -> Self {
        Self {
            elements: HashSet::new(),
        }
    }

    /// Add an element to the set.
    pub fn add(&mut self, element: T) {
        self.elements.insert(element);
    }

    /// Check if an element exists.
    pub fn contains(&self, element: &T) -> bool {
        self.elements.contains(element)
    }

    /// Merge another G-Set (union).
    pub fn merge(&mut self, other: &GSet<T>) {
        for element in &other.elements {
            self.elements.insert(element.clone());
        }
    }

    /// Get all elements.
    pub fn elements(&self) -> &HashSet<T> {
        &self.elements
    }

    /// Get the number of elements.
    pub fn len(&self) -> usize {
        self.elements.len()
    }

    /// Check if empty.
    pub fn is_empty(&self) -> bool {
        self.elements.is_empty()
    }
}

/// A Last-Writer-Wins Register (LWW-Register) for template metadata.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LWWRegister<T: Clone> {
    value: T,
    timestamp: i64,
    node_id: String,
}

impl<T: Clone> LWWRegister<T> {
    /// Create a new LWW register.
    pub fn new(value: T, node_id: String) -> Self {
        Self {
            value,
            timestamp: chrono::Utc::now().timestamp_millis(),
            node_id,
        }
    }

    /// Update the value.
    pub fn set(&mut self, value: T, node_id: &str) {
        let now = chrono::Utc::now().timestamp_millis();
        if now > self.timestamp || (now == self.timestamp && node_id > self.node_id.as_str()) {
            self.value = value;
            self.timestamp = now;
            self.node_id = node_id.to_string();
        }
    }

    /// Get the current value.
    pub fn get(&self) -> &T {
        &self.value
    }

    /// Merge another register (last writer wins).
    pub fn merge(&mut self, other: &LWWRegister<T>) {
        if other.timestamp > self.timestamp
            || (other.timestamp == self.timestamp && other.node_id > self.node_id)
        {
            self.value = other.value.clone();
            self.timestamp = other.timestamp;
            self.node_id = other.node_id.clone();
        }
    }
}

/// OR-Set (Observed-Remove Set) for templates that can be tombstoned.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ORSet<T: Clone + Eq + std::hash::Hash> {
    /// Map from element to set of (node_id, timestamp) pairs
    elements: HashMap<T, HashSet<(String, i64)>>,
    /// Tombstones: removed (node_id, timestamp) pairs
    tombstones: HashMap<T, HashSet<(String, i64)>>,
}

impl<T: Clone + Eq + std::hash::Hash> Default for ORSet<T> {
    fn default() -> Self {
        Self::new()
    }
}

impl<T: Clone + Eq + std::hash::Hash> ORSet<T> {
    /// Create a new OR-Set.
    pub fn new() -> Self {
        Self {
            elements: HashMap::new(),
            tombstones: HashMap::new(),
        }
    }

    /// Add an element with unique tag.
    pub fn add(&mut self, element: T, node_id: &str) {
        let tag = (node_id.to_string(), chrono::Utc::now().timestamp_millis());
        self.elements.entry(element).or_default().insert(tag);
    }

    /// Remove an element (add all current tags to tombstones).
    pub fn remove(&mut self, element: &T, _node_id: &str) {
        if let Some(tags) = self.elements.get(element) {
            let tombstone_set = self.tombstones.entry(element.clone()).or_default();
            for tag in tags {
                tombstone_set.insert(tag.clone());
            }
        }
    }

    /// Check if element exists (has live tags).
    pub fn contains(&self, element: &T) -> bool {
        if let Some(tags) = self.elements.get(element) {
            let tombstones = self.tombstones.get(element);
            tags.iter()
                .any(|tag| tombstones.is_none() || !tombstones.unwrap().contains(tag))
        } else {
            false
        }
    }

    /// Get all live elements.
    pub fn elements(&self) -> Vec<T> {
        self.elements
            .keys()
            .filter(|e| self.contains(e))
            .cloned()
            .collect()
    }

    /// Merge another OR-Set.
    pub fn merge(&mut self, other: &ORSet<T>) {
        // Merge elements
        for (element, tags) in &other.elements {
            let entry = self.elements.entry(element.clone()).or_default();
            for tag in tags {
                entry.insert(tag.clone());
            }
        }

        // Merge tombstones
        for (element, tags) in &other.tombstones {
            let entry = self.tombstones.entry(element.clone()).or_default();
            for tag in tags {
                entry.insert(tag.clone());
            }
        }
    }
}

/// Template metadata with version tracking.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TemplateEntry {
    pub pattern: String,
    pub template_id: u32,
    pub created_at: i64,
    pub origin_node: String,
    pub usage_count: u64,
}

/// CRDT-based Template Store.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CRDTTemplateStore {
    /// G-Set of template patterns (grow-only, templates never truly deleted)
    templates: GSet<String>,
    /// Map from pattern to metadata (LWW for conflict resolution)
    metadata: HashMap<String, LWWRegister<TemplateEntry>>,
    /// Template ID to pattern mapping
    id_to_pattern: HashMap<u32, String>,
    /// Next template ID (per-node allocation using node_id as prefix)
    next_id: u32,
    /// Node ID
    node_id: String,
    /// Variable history per template (append-only)
    variable_history: HashMap<u32, Vec<VariableRecord>>,
}

/// A record of variables used with a template.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VariableRecord {
    pub timestamp_ms: i64,
    pub variables: Vec<String>,
    pub origin_node: String,
}

impl CRDTTemplateStore {
    /// Create a new CRDT template store.
    pub fn new(node_id: String) -> Self {
        // Use node hash to offset ID space to avoid collisions
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};
        let mut hasher = DefaultHasher::new();
        node_id.hash(&mut hasher);
        let id_offset = (hasher.finish() % 1_000_000) as u32 * 1000;

        Self {
            templates: GSet::new(),
            metadata: HashMap::new(),
            id_to_pattern: HashMap::new(),
            next_id: id_offset,
            node_id,
            variable_history: HashMap::new(),
        }
    }

    /// Add a new template.
    pub fn add_template(&mut self, pattern: String) -> u32 {
        if let Some(entry) = self.metadata.get(&pattern) {
            return entry.get().template_id;
        }

        let template_id = self.next_id;
        self.next_id += 1;

        let entry = TemplateEntry {
            pattern: pattern.clone(),
            template_id,
            created_at: chrono::Utc::now().timestamp_millis(),
            origin_node: self.node_id.clone(),
            usage_count: 0,
        };

        self.templates.add(pattern.clone());
        self.metadata.insert(
            pattern.clone(),
            LWWRegister::new(entry, self.node_id.clone()),
        );
        self.id_to_pattern.insert(template_id, pattern);

        template_id
    }

    /// Import a template from replication (with known ID).
    pub fn import_template(&mut self, pattern: String, template_id: u32, origin_node: &str) {
        if self.templates.contains(&pattern) {
            return;
        }

        let entry = TemplateEntry {
            pattern: pattern.clone(),
            template_id,
            created_at: chrono::Utc::now().timestamp_millis(),
            origin_node: origin_node.to_string(),
            usage_count: 0,
        };

        self.templates.add(pattern.clone());
        self.metadata.insert(
            pattern.clone(),
            LWWRegister::new(entry, origin_node.to_string()),
        );
        self.id_to_pattern.insert(template_id, pattern);

        // Update next_id if needed to avoid collisions
        if template_id >= self.next_id {
            self.next_id = template_id + 1;
        }
    }

    /// Record variable usage.
    pub fn record_variables(&mut self, template_id: u32, variables: Vec<String>) {
        let record = VariableRecord {
            timestamp_ms: chrono::Utc::now().timestamp_millis(),
            variables,
            origin_node: self.node_id.clone(),
        };

        self.variable_history
            .entry(template_id)
            .or_default()
            .push(record);
    }

    /// Get template by pattern.
    pub fn get_template(&self, pattern: &str) -> Option<&TemplateEntry> {
        self.metadata.get(pattern).map(|r| r.get())
    }

    /// Get template by ID.
    pub fn get_template_by_id(&self, id: u32) -> Option<&TemplateEntry> {
        self.id_to_pattern
            .get(&id)
            .and_then(|pattern| self.metadata.get(pattern))
            .map(|r| r.get())
    }

    /// Get all templates.
    pub fn all_templates(&self) -> Vec<&TemplateEntry> {
        self.metadata.values().map(|r| r.get()).collect()
    }

    /// Get variable history for a template.
    pub fn get_variable_history(&self, template_id: u32) -> &[VariableRecord] {
        self.variable_history
            .get(&template_id)
            .map(|v| v.as_slice())
            .unwrap_or(&[])
    }

    /// Merge another CRDT store.
    pub fn merge(&mut self, other: &CRDTTemplateStore) {
        // Merge template sets
        self.templates.merge(&other.templates);

        // Merge metadata (LWW resolution)
        for (pattern, register) in &other.metadata {
            if let Some(our_register) = self.metadata.get_mut(pattern) {
                our_register.merge(register);
            } else {
                self.metadata.insert(pattern.clone(), register.clone());
                let entry = register.get();
                self.id_to_pattern
                    .insert(entry.template_id, pattern.clone());
            }
        }

        // Merge variable history (union)
        for (template_id, records) in &other.variable_history {
            let our_records = self.variable_history.entry(*template_id).or_default();
            for record in records {
                // Simple dedup by timestamp and node
                let exists = our_records.iter().any(|r| {
                    r.timestamp_ms == record.timestamp_ms && r.origin_node == record.origin_node
                });
                if !exists {
                    our_records.push(record.clone());
                }
            }
            // Sort by timestamp
            our_records.sort_by_key(|r| r.timestamp_ms);
        }

        // Update next_id
        for id in other.id_to_pattern.keys() {
            if *id >= self.next_id {
                self.next_id = id + 1;
            }
        }
    }

    /// Get the number of templates.
    pub fn len(&self) -> usize {
        self.templates.len()
    }

    /// Check if empty.
    pub fn is_empty(&self) -> bool {
        self.templates.is_empty()
    }

    /// Get node ID.
    pub fn node_id(&self) -> &str {
        &self.node_id
    }

    /// Export state for replication.
    pub fn export_state(&self) -> CRDTTemplateStore {
        self.clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_gset() {
        let mut set1 = GSet::new();
        let mut set2 = GSet::new();

        set1.add("pattern1".to_string());
        set2.add("pattern2".to_string());

        set1.merge(&set2);

        assert!(set1.contains(&"pattern1".to_string()));
        assert!(set1.contains(&"pattern2".to_string()));
    }

    #[test]
    fn test_lww_register() {
        let mut reg1 = LWWRegister::new("value1".to_string(), "node1".to_string());
        std::thread::sleep(std::time::Duration::from_millis(10));
        let reg2 = LWWRegister::new("value2".to_string(), "node2".to_string());

        reg1.merge(&reg2);
        assert_eq!(reg1.get(), "value2");
    }

    #[test]
    fn test_crdt_store_merge() {
        let mut store1 = CRDTTemplateStore::new("node1".to_string());
        let mut store2 = CRDTTemplateStore::new("node2".to_string());

        store1.add_template("User <*> logged in".to_string());
        store2.add_template("Error: <*>".to_string());

        store1.merge(&store2);

        assert_eq!(store1.len(), 2);
        assert!(store1.get_template("User <*> logged in").is_some());
        assert!(store1.get_template("Error: <*>").is_some());
    }
}
